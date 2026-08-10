import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { decodeBase64Url, encodeBase64Url } from "@std/encoding/base64url";

const enc = new TextEncoder();
const dec = new TextDecoder();

/** ChaCha20-Poly1305 nonce length. */
const NONCE_BYTES = 12;

/**
 * Derive the sealing key from a server secret. The label separates this key from
 * every other use of the same secret — the challenge MAC above all — so one
 * server secret can safely key several unrelated things.
 */
function sealingKey(secret: Uint8Array, label: string): Uint8Array {
  return hmac(sha256, secret, enc.encode(label));
}

/**
 * Seal a JSON value into an opaque, tamper-evident base64url string. Used for the
 * OAuth authorization code, which must carry its own state because the Issuer
 * stores none — and must be encrypted, not merely MAC'd, because it carries a secret.
 */
export function seal(
  value: unknown,
  secret: Uint8Array,
  label: string,
): string {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const body = chacha20poly1305(sealingKey(secret, label), nonce)
    .encrypt(enc.encode(JSON.stringify(value)));
  const out = new Uint8Array(NONCE_BYTES + body.length);
  out.set(nonce);
  out.set(body, NONCE_BYTES);
  return encodeBase64Url(out);
}

/**
 * Reverse `seal`. Throws when the input is malformed, was tampered with, or was
 * sealed under a different label or secret.
 */
export function unseal<T>(
  sealed: string,
  secret: Uint8Array,
  label: string,
): T {
  let raw: Uint8Array;
  try {
    raw = decodeBase64Url(sealed);
  } catch {
    throw new Error("malformed sealed value");
  }
  if (raw.length <= NONCE_BYTES) throw new Error("truncated sealed value");
  const plain = chacha20poly1305(
    sealingKey(secret, label),
    raw.subarray(0, NONCE_BYTES),
  ).decrypt(raw.subarray(NONCE_BYTES));
  return JSON.parse(dec.decode(plain)) as T;
}
