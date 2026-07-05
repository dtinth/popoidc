import { importJWK, type JWK } from "jose";
import type { SigningKey } from "./token.ts";

/** Runtime configuration, loaded once at startup. */
export interface Config {
  /** Public HTTPS issuer URL; equals the `iss` claim (no trailing slash). */
  issuer: string;
  /** SSHSIG namespace bound into Signing Proofs. */
  namespace: string;
  /** Secret keying the challenge HMAC. */
  hmacSecret: Uint8Array;
  /** The RSA key Tokens are signed with. */
  signingKey: SigningKey;
}

/** Minimal view of an environment source, for testability. */
export interface EnvSource {
  get(key: string): string | undefined;
}

function required(env: EnvSource, key: string): string {
  const v = env.get(key);
  if (!v) throw new Error(`missing required env var ${key}`);
  return v;
}

/**
 * Load configuration from the environment:
 *   SSHID_ISSUER      public issuer URL
 *   SSHID_SIGNING_JWK RSA private JWK (JSON) with a `kid`
 *   SSHID_HMAC_SECRET challenge HMAC secret
 *   SSHID_NAMESPACE   optional SSHSIG namespace (default "sshid")
 */
export async function loadConfig(env: EnvSource = Deno.env): Promise<Config> {
  const issuer = required(env, "SSHID_ISSUER").replace(/\/+$/, "");
  const hmacSecret = new TextEncoder().encode(
    required(env, "SSHID_HMAC_SECRET"),
  );
  const namespace = env.get("SSHID_NAMESPACE") ?? "sshid";

  let jwk: JWK & { kid?: string };
  try {
    jwk = JSON.parse(required(env, "SSHID_SIGNING_JWK"));
  } catch {
    throw new Error("SSHID_SIGNING_JWK is not valid JSON");
  }
  if (jwk.kty !== "RSA" || !jwk.kid || !jwk.d) {
    throw new Error("SSHID_SIGNING_JWK must be an RSA private JWK with a kid");
  }

  const privateKey = await importJWK(jwk, "RS256") as CryptoKey;
  const publicJwk: JWK = {
    kty: "RSA",
    n: jwk.n,
    e: jwk.e,
    kid: jwk.kid,
    alg: "RS256",
    use: "sig",
  };

  return {
    issuer,
    namespace,
    hmacSecret,
    signingKey: { kid: jwk.kid, privateKey, publicJwk },
  };
}
