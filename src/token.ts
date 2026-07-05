import { type JWK, SignJWT } from "jose";
import { encodeBase64Url } from "@std/encoding/base64url";

/** An RSA key the Issuer signs Tokens with; its public half is published in the JWKS. */
export interface SigningKey {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
}

/** Token lifetime (ADR-0001): 15 minutes. */
export const TOKEN_TTL_SECONDS = 15 * 60;

export interface MintParams {
  issuer: string;
  subject: string;
  audience: string;
  /** Raw public key string, surfaced as the `key` claim. */
  key: string;
  /** e.g. "ssh-ed25519" or "age", surfaced as `key_type`. */
  keyType: string;
  signingKey: SigningKey;
  nowSeconds: number;
  ttlSeconds?: number;
}

/** Mint the RS256 ID Token asserting possession of a key. */
export function mintToken(p: MintParams): Promise<string> {
  const ttl = p.ttlSeconds ?? TOKEN_TTL_SECONDS;
  return new SignJWT({ key: p.key, key_type: p.keyType })
    .setProtectedHeader({ alg: "RS256", kid: p.signingKey.kid, typ: "JWT" })
    .setIssuer(p.issuer)
    .setSubject(p.subject)
    .setAudience(p.audience)
    .setIssuedAt(p.nowSeconds)
    .setNotBefore(p.nowSeconds)
    .setExpirationTime(p.nowSeconds + ttl)
    .setJti(encodeBase64Url(crypto.getRandomValues(new Uint8Array(16))))
    .sign(p.signingKey.privateKey);
}

/** The OIDC discovery document. */
export function discoveryDocument(issuer: string): Record<string, unknown> {
  return {
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    id_token_signing_alg_values_supported: ["RS256"],
    subject_types_supported: ["public"],
    response_types_supported: ["id_token"],
    scopes_supported: ["openid"],
    claims_supported: [
      "iss",
      "sub",
      "aud",
      "iat",
      "nbf",
      "exp",
      "jti",
      "key",
      "key_type",
    ],
  };
}

/** The JWKS document — public halves only, one entry per (rotating) signing key. */
export function jwksDocument(keys: SigningKey[]): { keys: JWK[] } {
  return { keys: keys.map((k) => k.publicJwk) };
}
