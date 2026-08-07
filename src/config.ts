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
  /**
   * Pepper deriving HMAC-mode Secret Fingerprints. Optional: leaving it unset
   * disables HMAC mode entirely. Kept apart from `hmacSecret` because that one is
   * rotatable at will (it only invalidates in-flight challenges) whereas this one
   * *names* every Shared Secret Identity — changing it renames all of them.
   */
  hmacIdentitySecret?: Uint8Array;
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
 *   POPOIDC_ISSUER               public issuer URL
 *   POPOIDC_SIGNING_JWK          RSA private JWK (JSON) with a `kid`
 *   POPOIDC_HMAC_SECRET          challenge HMAC secret
 *   POPOIDC_HMAC_IDENTITY_SECRET optional identity pepper; enables HMAC mode
 *   POPOIDC_NAMESPACE            optional SSHSIG namespace (default "popoidc")
 */
export async function loadConfig(env: EnvSource = Deno.env): Promise<Config> {
  const issuer = required(env, "POPOIDC_ISSUER").replace(/\/+$/, "");
  const hmacSecret = new TextEncoder().encode(
    required(env, "POPOIDC_HMAC_SECRET"),
  );
  const identitySecret = env.get("POPOIDC_HMAC_IDENTITY_SECRET");
  const namespace = env.get("POPOIDC_NAMESPACE") ?? "popoidc";

  let jwk: JWK & { kid?: string };
  try {
    jwk = JSON.parse(required(env, "POPOIDC_SIGNING_JWK"));
  } catch {
    throw new Error("POPOIDC_SIGNING_JWK is not valid JSON");
  }
  if (jwk.kty !== "RSA" || !jwk.kid || !jwk.d) {
    throw new Error(
      "POPOIDC_SIGNING_JWK must be an RSA private JWK with a kid",
    );
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
    hmacIdentitySecret: identitySecret
      ? new TextEncoder().encode(identitySecret)
      : undefined,
    signingKey: { kid: jwk.kid, privateKey, publicJwk },
  };
}
