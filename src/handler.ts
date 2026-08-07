import type { Config } from "./config.ts";
import { discoveryDocument, jwksDocument, mintToken } from "./token.ts";
import {
  type Challenge,
  issueChallenge,
  type ProofMethod,
  randomNonce,
  verifyChallenge,
} from "./challenge.ts";
import { parseSshEd25519, sshFingerprint } from "./sshkey.ts";
import { verifySshsig } from "./sshsig.ts";
import { encryptToRecipient } from "./agecrypt.ts";
import { MIN_SECRET_LENGTH, secretFingerprint } from "./hmacid.ts";

export interface HandlerOptions {
  /** Injectable clock (unix seconds) for tests. */
  now?: () => number;
}

/** An error carrying an HTTP status code. */
class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

const enc = new TextEncoder();

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// Challenges and Tokens are single-use and time-bound — no cache (Cloudflare et al.)
// may ever store them, or a stale challenge gets replayed and rejected as expired.
function text(body: string): Response {
  return new Response(body, {
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

/** Max accepted request body. A real /token body is < 1.5 KB; this is generous headroom. */
const MAX_BODY_BYTES = 16 * 1024;

/** Read a request body as text, aborting past `limit` bytes (streamed — Content-Length is not trusted). */
async function readBody(req: Request, limit: number): Promise<string> {
  const reader = req.body?.getReader();
  if (!reader) return "";
  const decoder = new TextDecoder();
  let text = "";
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await reader.cancel();
      throw new HttpError(413, "request body too large");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

/** Classify a supported public key by its string form. */
function keyKind(key: string): "ssh-ed25519" | "age" {
  if (key.startsWith("ssh-ed25519 ")) return "ssh-ed25519";
  if (key.startsWith("age1")) return "age";
  throw new HttpError(400, "unsupported key type");
}

/** The Token subject + key_type for a bound key. */
function identityOf(key: string): { sub: string; keyType: string } {
  if (key.startsWith("age1")) return { sub: key, keyType: "age" };
  return {
    sub: sshFingerprint(parseSshEd25519(key).wire),
    keyType: "ssh-ed25519",
  };
}

/**
 * GET /challenge — issue a challenge bound to {aud, iat, key}.
 * A signing key receives the challenge in the clear (to sign); a decryption key
 * receives it encrypted to the key, so only the holder can recover it.
 */
async function handleChallenge(
  cfg: Config,
  params: URLSearchParams,
  now: () => number,
): Promise<Response> {
  const key = params.get("key");
  const aud = params.get("aud");
  if (!key || !aud) {
    throw new HttpError(400, "key and aud params are required");
  }

  const kind = keyKind(key);
  const requested = params.get("method");
  const method: ProofMethod = kind === "age"
    ? "decrypt"
    : requested === "decrypt"
    ? "decrypt"
    : "sign";

  const challenge: Challenge = {
    v: 1,
    method,
    aud,
    key,
    iat: now(),
    nonce: randomNonce(),
  };
  const token = issueChallenge(challenge, cfg.hmacSecret);

  if (method === "sign") {
    try {
      parseSshEd25519(key);
    } catch {
      throw new HttpError(400, "invalid ssh-ed25519 key");
    }
    return text(token);
  }
  try {
    return text(await encryptToRecipient(key, enc.encode(token)));
  } catch {
    throw new HttpError(400, "invalid recipient key");
  }
}

/** A proven Identity, ready to be minted into a Token. */
interface Grant {
  sub: string;
  keyType: string;
  /** The `key` claim — the raw public key, or the fingerprint when there is no public half. */
  key: string;
  aud: string;
}

/**
 * The Challenge grant: verify a Challenge + its Proof of Possession (Signing or
 * Decryption) and report the Identity it proves.
 */
function grantFromChallenge(
  cfg: Config,
  body: URLSearchParams,
  challengeStr: string,
  nowSeconds: number,
): Grant {
  let challenge: Challenge;
  try {
    challenge = verifyChallenge(challengeStr, cfg.hmacSecret, nowSeconds);
  } catch {
    throw new HttpError(401, "invalid or expired challenge");
  }

  // Signing Proof: the challenge was public, so require a signature over it that
  // matches the bound key. Decryption Proof: recovering the MAC'd challenge (it
  // was returned encrypted to the key) is itself the proof — nothing more needed.
  if (challenge.method === "sign") {
    const signature = body.get("signature");
    if (!signature) throw new HttpError(400, "signature is required");

    const bound = parseSshEd25519(challenge.key);
    let signer;
    try {
      signer = verifySshsig(enc.encode(challengeStr), signature, cfg.namespace);
    } catch {
      throw new HttpError(401, "signature verification failed");
    }
    if (sshFingerprint(signer.publicKeyWire) !== sshFingerprint(bound.wire)) {
      throw new HttpError(401, "signature key does not match the challenge");
    }
  }

  const { sub, keyType } = identityOf(challenge.key);
  return { sub, keyType, key: challenge.key, aud: challenge.aud };
}

/**
 * The HMAC-mode grant (Disclosure Proof): the caller hands over the Shared Secret
 * itself, so there is nothing to challenge — the request body *is* the proof, and
 * a round-trip would add ceremony but no security. The Identity is the peppered
 * HMAC of the secret; the Issuer neither stores the secret nor puts it in the Token.
 */
function grantFromSecret(
  cfg: Config,
  body: URLSearchParams,
  secret: string,
): Grant {
  if (!cfg.hmacIdentitySecret) {
    throw new HttpError(501, "hmac mode is not enabled on this issuer");
  }
  const aud = body.get("aud");
  if (!aud) throw new HttpError(400, "aud is required with secret");
  if (secret.length < MIN_SECRET_LENGTH) {
    throw new HttpError(
      400,
      `secret must be at least ${MIN_SECRET_LENGTH} characters`,
    );
  }

  // No public half exists, so `key` restates the fingerprint rather than leaking
  // the secret it was derived from.
  const sub = secretFingerprint(secret, cfg.hmacIdentitySecret);
  return { sub, keyType: "hmac", key: sub, aud };
}

/** POST /token — take a proof of possession (Challenge-bound or disclosed) and mint a Token. */
async function handleToken(
  cfg: Config,
  req: Request,
  now: () => number,
): Promise<Response> {
  const body = new URLSearchParams(await readBody(req, MAX_BODY_BYTES));
  const challengeStr = body.get("challenge");
  const secret = body.get("secret");
  if (challengeStr && secret) {
    throw new HttpError(400, "send either challenge or secret, not both");
  }

  let grant: Grant;
  if (secret) {
    grant = grantFromSecret(cfg, body, secret);
  } else if (challengeStr) {
    grant = grantFromChallenge(cfg, body, challengeStr, now());
  } else {
    throw new HttpError(400, "challenge or secret is required");
  }

  const jwt = await mintToken({
    issuer: cfg.issuer,
    subject: grant.sub,
    audience: grant.aud,
    key: grant.key,
    keyType: grant.keyType,
    signingKey: cfg.signingKey,
    nowSeconds: now(),
  });
  return text(jwt);
}

/** Build the popoidc HTTP handler over a loaded Config. */
export function createHandler(
  cfg: Config,
  opts: HandlerOptions = {},
): (req: Request) => Promise<Response> {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));

  return async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    try {
      if (req.method === "GET" && url.pathname === "/") {
        return Response.redirect(
          "https://github.com/dtinth/popoidc#readme",
          302,
        );
      }
      if (
        req.method === "GET" &&
        url.pathname === "/.well-known/openid-configuration"
      ) {
        return json(discoveryDocument(cfg.issuer));
      }
      if (req.method === "GET" && url.pathname === "/.well-known/jwks.json") {
        return json(jwksDocument([cfg.signingKey]));
      }
      if (
        url.pathname === "/challenge" &&
        (req.method === "GET" || req.method === "POST")
      ) {
        const params = req.method === "POST"
          ? new URLSearchParams(await readBody(req, MAX_BODY_BYTES))
          : url.searchParams;
        return await handleChallenge(cfg, params, now);
      }
      if (req.method === "POST" && url.pathname === "/token") {
        return await handleToken(cfg, req, now);
      }
      return json({ error: "not_found" }, 404);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      return json({ error: "internal_error" }, 500);
    }
  };
}
