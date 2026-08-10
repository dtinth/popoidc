// The OAuth 2.1 authorization server that fronts harness identity (ADR-0004).
//
// It grants a freshly generated, previously unowned Shared Secret. Nothing that
// already existed becomes reachable, which is why there is no login screen, no
// consent screen, and no client authentication: there is nothing to protect. The
// one check that does matter — redirect_uri — protects third parties, not us.

import { sha256 } from "@noble/hashes/sha2.js";
import { encodeBase64Url } from "@std/encoding/base64url";
import type { Config } from "./config.ts";
import {
  type ClientMetadata,
  fetchClientMetadata,
  type Fetcher,
  isCimdClientId,
  isRedirectAllowed,
} from "./cimd.ts";
import { seal, unseal } from "./sealedbox.ts";
import { harnessSecret, namespaceFromResource } from "./harness.ts";
import { hmacIdentity } from "./hmacid.ts";
import { mintToken } from "./token.ts";

const enc = new TextEncoder();

/** Domain separation for the authorization code's sealing key. */
const CODE_LABEL = "popoidc/oauth-code/v1";

/** The redirect is immediate and unattended, so the Challenge window fits exactly. */
export const CODE_TTL_SECONDS = 60;

/** 1024 bits. Beyond ~256 buys nothing, but the secret is never typed by a human. */
const SECRET_BYTES = 128;

/** What the authorization code carries, because the Issuer stores nothing. */
interface CodePayload {
  secret: string;
  challenge: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  resource?: string;
  nonce?: string;
  exp: number;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}

function oauthError(
  error: string,
  description: string,
  status = 400,
): Response {
  return json({ error, error_description: description }, status);
}

/** Redirect to the (already validated) client, always naming ourselves per RFC 9207. */
function redirectBack(
  redirectUri: string,
  issuer: string,
  state: string | null,
  params: Record<string, string>,
): Response {
  const target = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) target.searchParams.set(k, v);
  if (state !== null) target.searchParams.set("state", state);
  target.searchParams.set("iss", issuer);
  return new Response(null, {
    status: 302,
    headers: { location: target.toString(), "cache-control": "no-store" },
  });
}

function newSecret(): string {
  return Array.from(
    crypto.getRandomValues(new Uint8Array(SECRET_BYTES)),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
}

/** The S256 transform of a PKCE verifier (RFC 7636). */
export function pkceChallenge(verifier: string): string {
  return encodeBase64Url(sha256(enc.encode(verifier)));
}

/**
 * GET /oauth/authorize — mint a secret, seal it into a code, redirect at once.
 *
 * Errors before the redirect target is validated are returned as JSON: sending
 * them onward would be the open redirect this endpoint exists to avoid. After
 * validation they go back to the client, as OAuth requires.
 */
export async function handleAuthorize(
  cfg: Config,
  url: URL,
  now: () => number,
  fetcher?: Fetcher,
): Promise<Response> {
  if (!cfg.hmacIdentitySecret) {
    return oauthError(
      "temporarily_unavailable",
      "hmac mode is not enabled on this issuer",
      501,
    );
  }
  const q = url.searchParams;
  const clientId = q.get("client_id");
  const redirectUri = q.get("redirect_uri");
  if (!clientId || !redirectUri) {
    return oauthError(
      "invalid_request",
      "client_id and redirect_uri are required",
    );
  }

  let metadata: ClientMetadata | null = null;
  if (isCimdClientId(clientId)) {
    try {
      metadata = await fetchClientMetadata(clientId, fetcher);
    } catch (e) {
      return oauthError("invalid_client", (e as Error).message);
    }
  }
  if (!isRedirectAllowed(redirectUri, metadata)) {
    return oauthError(
      "invalid_request",
      "redirect_uri is not registered for this client",
    );
  }

  const state = q.get("state");
  const back = (error: string, description: string) =>
    redirectBack(redirectUri, cfg.issuer, state, {
      error,
      error_description: description,
    });

  if (q.get("response_type") !== "code") {
    return back("unsupported_response_type", "response_type must be code");
  }
  const challenge = q.get("code_challenge");
  if (!challenge) return back("invalid_request", "code_challenge is required");
  if (q.get("code_challenge_method") !== "S256") {
    return back("invalid_request", "code_challenge_method must be S256");
  }

  const payload: CodePayload = {
    secret: newSecret(),
    challenge,
    clientId,
    redirectUri,
    scope: q.get("scope") ?? "",
    resource: q.get("resource") ?? undefined,
    nonce: q.get("nonce") ?? undefined,
    exp: now() + CODE_TTL_SECONDS,
  };
  return redirectBack(redirectUri, cfg.issuer, state, {
    code: seal(payload, cfg.hmacSecret, CODE_LABEL),
  });
}

/**
 * POST /oauth/token — exchange the code, or refresh.
 *
 * The access token *is* the secret, so refreshing returns it unchanged and nothing
 * expires. Both are deliberate deviations; see ADR-0004.
 */
export async function handleOAuthToken(
  cfg: Config,
  body: URLSearchParams,
  now: () => number,
): Promise<Response> {
  const grantType = body.get("grant_type");

  if (grantType === "refresh_token") {
    const refresh = body.get("refresh_token");
    if (!refresh) {
      return oauthError("invalid_request", "refresh_token is required");
    }
    return json(tokenBody(refresh, null, null));
  }
  if (grantType !== "authorization_code") {
    return oauthError(
      "unsupported_grant_type",
      "grant_type must be authorization_code or refresh_token",
    );
  }

  const code = body.get("code");
  if (!code) return oauthError("invalid_request", "code is required");

  let payload: CodePayload;
  try {
    payload = unseal<CodePayload>(code, cfg.hmacSecret, CODE_LABEL);
  } catch {
    return oauthError("invalid_grant", "the authorization code is invalid");
  }
  if (payload.exp < now()) {
    return oauthError("invalid_grant", "the authorization code has expired");
  }

  const verifier = body.get("code_verifier");
  if (!verifier || pkceChallenge(verifier) !== payload.challenge) {
    return oauthError("invalid_grant", "code_verifier does not match");
  }
  if (body.get("redirect_uri") !== payload.redirectUri) {
    return oauthError("invalid_grant", "redirect_uri does not match");
  }
  if (body.get("client_id") !== payload.clientId) {
    return oauthError("invalid_client", "client_id does not match", 401);
  }

  const scopes = payload.scope.split(/\s+/).filter(Boolean);
  const idToken = scopes.includes("openid")
    ? await mintIdToken(cfg, payload, body.get("resource"), now())
    : null;
  return json(tokenBody(payload.secret, idToken, payload.scope || null));
}

/**
 * The OIDC login assertion. Its `aud` is the client_id, so no relying party will
 * take it — it exists to make the merged metadata document truthful, and for
 * nothing else. Its `sub` uses the namespace the client named in `resource`, so it
 * agrees with what the MCP tools will report.
 */
function mintIdToken(
  cfg: Config,
  payload: CodePayload,
  resource: string | null,
  nowSeconds: number,
): Promise<string> {
  const namespace = namespaceFromResource(resource ?? payload.resource ?? null);
  const { sub, key, keyType } = hmacIdentity(
    harnessSecret(payload.secret, namespace),
    cfg.hmacIdentitySecret!,
  );
  return mintToken({
    issuer: cfg.issuer,
    subject: sub,
    audience: payload.clientId,
    key,
    keyType,
    signingKey: cfg.signingKey,
    nowSeconds,
    claims: payload.nonce ? { nonce: payload.nonce } : undefined,
  });
}

/** No `expires_in`: the access token does not expire, and saying otherwise would be false. */
function tokenBody(
  secret: string,
  idToken: string | null,
  scope: string | null,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    access_token: secret,
    token_type: "Bearer",
    refresh_token: secret,
  };
  if (scope) body.scope = scope;
  if (idToken) body.id_token = idToken;
  return body;
}
