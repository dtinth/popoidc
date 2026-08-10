import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { encodeBase64 } from "@std/encoding/base64";

const enc = new TextEncoder();

/**
 * Domain separation for the identity subkey. The pepper is only ever used through
 * this derived subkey, so a Secret Fingerprint can never collide with — or be
 * confused for — another HMAC the Issuer computes.
 */
const IDENTITY_LABEL = "popoidc/hmac-identity/v1";

/**
 * Shortest accepted Shared Secret. The pepper makes a fingerprint useless for
 * _offline_ guessing, but anyone may ask the Issuer to mint a Token for a
 * _guessed_ secret — so a short secret is online-brute-forceable. Generate one
 * with `openssl rand -base64 24`.
 */
export const MIN_SECRET_LENGTH = 16;

/**
 * The Secret Fingerprint naming a Shared Secret Identity: `HMAC-SHA256:` +
 * unpadded base64 of HMAC-SHA256(subkey(pepper), secret) — same shape as the
 * OpenSSH `SHA256:…` fingerprint, so trust policies read the same either way.
 *
 * Deterministic (a secret always names the same Identity) and peppered (the
 * fingerprint discloses nothing about the secret, and the same secret names
 * different Identities on different Issuers).
 */
export function secretFingerprint(secret: string, pepper: Uint8Array): string {
  const subkey = hmac(sha256, pepper, enc.encode(IDENTITY_LABEL));
  return "HMAC-SHA256:" +
    encodeBase64(hmac(sha256, subkey, enc.encode(secret))).replace(/=+$/, "");
}

/**
 * The Token claims naming a Shared Secret Identity. A Shared Secret has no public
 * half, so `key` restates the fingerprint rather than disclosing the secret.
 * Shared by the HMAC-mode grant and the MCP harness tools, so the rule lives once.
 */
export function hmacIdentity(
  secret: string,
  pepper: Uint8Array,
): { sub: string; keyType: string; key: string } {
  const sub = secretFingerprint(secret, pepper);
  return { sub, keyType: "hmac", key: sub };
}
