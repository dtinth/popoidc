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

/** Classify a supported public key by its string form. */
function keyKind(key: string): "ssh-ed25519" | "age" {
  if (key.startsWith("ssh-ed25519 ")) return "ssh-ed25519";
  if (key.startsWith("age1")) return "age";
  throw new HttpError(400, "unsupported key type");
}

/** GET /challenge — issue a challenge bound to {aud, iat, key}. */
function handleChallenge(cfg: Config, url: URL, now: () => number): Response {
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

  if (method === "sign") {
    return text(issueChallenge(challenge, cfg.hmacSecret));
  }
  throw new HttpError(400, "decrypt method not yet supported");
}

/** POST /token — verify a challenge + its Proof of Possession, then mint a Token. */
async function handleToken(
  cfg: Config,
  req: Request,
  now: () => number,
): Promise<Response> {
  const body = new URLSearchParams(await req.text());
  const challengeStr = body.get("challenge");
  if (!challengeStr) throw new HttpError(400, "challenge is required");

  let challenge: Challenge;
  try {
    challenge = verifyChallenge(challengeStr, cfg.hmacSecret, now());
  } catch {
    throw new HttpError(401, "invalid or expired challenge");
  }

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

    const jwt = await mintToken({
      issuer: cfg.issuer,
      subject: sshFingerprint(bound.wire),
      audience: challenge.aud,
      key: challenge.key,
      keyType: "ssh-ed25519",
      signingKey: cfg.signingKey,
      nowSeconds: now(),
    });
    return text(jwt);
  }
  throw new HttpError(400, "decrypt method not yet supported");
}

/** Build the sshid HTTP handler over a loaded Config. */
export function createHandler(
  cfg: Config,
  opts: HandlerOptions = {},
): (req: Request) => Promise<Response> {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));

  return async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    try {
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
        return handleChallenge(cfg, url, now);
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
