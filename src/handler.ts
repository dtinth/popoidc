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

function text(body: string): Response {
  return new Response(body, {
    headers: { "content-type": "text/plain; charset=utf-8" },
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
  url: URL,
  now: () => number,
): Promise<Response> {
  const key = url.searchParams.get("key");
  const aud = url.searchParams.get("aud");
  if (!key || !aud) {
    throw new HttpError(400, "key and aud query params are required");
  }

  const kind = keyKind(key);
  const requested = url.searchParams.get("method");
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

/** POST /token — verify a challenge + its Proof of Possession, then mint a Token. */
async function handleToken(
  cfg: Config,
  req: Request,
  now: () => number,
): Promise<Response> {
  const body = new URLSearchParams(await readBody(req, MAX_BODY_BYTES));
  const challengeStr = body.get("challenge");
  if (!challengeStr) throw new HttpError(400, "challenge is required");

  let challenge: Challenge;
  try {
    challenge = verifyChallenge(challengeStr, cfg.hmacSecret, now());
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
  const jwt = await mintToken({
    issuer: cfg.issuer,
    subject: sub,
    audience: challenge.aud,
    key: challenge.key,
    keyType,
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
      if (req.method === "GET" && url.pathname === "/challenge") {
        return await handleChallenge(cfg, url, now);
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
