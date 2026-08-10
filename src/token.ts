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
  /** Extra claims merged into the payload — the OIDC `nonce`, in practice. */
  claims?: Record<string, unknown>;
}

/** Mint the RS256 ID Token asserting possession of a key. */
export function mintToken(p: MintParams): Promise<string> {
  const ttl = p.ttlSeconds ?? TOKEN_TTL_SECONDS;
  return new SignJWT({ key: p.key, key_type: p.keyType, ...p.claims })
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

/**
 * The metadata document, describing two roles at one issuer: the Token issuer that
 * relying parties verify against, and the OAuth authorization server that MCP
 * connectors authorize with (ADR-0004). Served at both the OIDC and the OAuth
 * well-known paths, so a client finds it whichever it tries first.
 */
export function discoveryDocument(issuer: string): Record<string, unknown> {
  return {
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    id_token_signing_alg_values_supported: ["RS256"],
    subject_types_supported: ["public"],
    // "code", not "id_token": the OAuth flow issues an authorization code. An
    // id_token comes back from the token endpoint, and only for the openid scope.
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    // MCP clients MUST refuse an authorization server that does not advertise PKCE.
    code_challenge_methods_supported: ["S256"],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
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

/**
 * OAuth 2.0 Protected Resource Metadata (RFC 9728) for one MCP endpoint. `resource`
 * must equal the canonical URI the client dialled, so this is built per path rather
 * than served as one constant — `/mcp` and `/mcp/ns1` are different resources.
 */
export function protectedResourceMetadata(
  issuer: string,
  resourcePath: string,
): Record<string, unknown> {
  return {
    resource: `${issuer}${resourcePath}`,
    authorization_servers: [issuer],
    scopes_supported: ["openid"],
    bearer_methods_supported: ["header"],
  };
}

/** The JWKS document — public halves only, one entry per (rotating) signing key. */
export function jwksDocument(keys: SigningKey[]): { keys: JWK[] } {
  return { keys: keys.map((k) => k.publicJwk) };
}
