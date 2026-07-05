import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { decodeBase64Url, encodeBase64Url } from "@std/encoding/base64url";

const enc = new TextEncoder();
const dec = new TextDecoder();

/** The proof method a challenge asks for. */
export type ProofMethod = "sign" | "decrypt";

/**
 * The self-describing, server-issued challenge. Serialized as `b64url(json).b64url(hmac)`
 * so it is stateless: the Issuer re-verifies its own HMAC on redemption.
 */
export interface Challenge {
  v: 1;
  method: ProofMethod;
  /** Requested audience, bound into the challenge (and later the Token). */
  aud: string;
  /** The public key string this challenge is bound to (ssh-ed25519 line or age1…). */
  key: string;
  /** Issued-at, unix seconds. */
  iat: number;
  /** Random, for uniqueness. */
  nonce: string;
}

/** Default freshness window (seconds) — also the signature/secret replay window. */
export const MAX_AGE_SECONDS = 60;

function mac(payload: string, secret: Uint8Array): Uint8Array {
  return hmac(sha256, secret, enc.encode(payload));
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Issue a challenge token, MAC'd with the server secret. */
export function issueChallenge(
  challenge: Challenge,
  secret: Uint8Array,
): string {
  const payload = encodeBase64Url(enc.encode(JSON.stringify(challenge)));
  return `${payload}.${encodeBase64Url(mac(payload, secret))}`;
}

/**
 * Verify a challenge token's MAC and freshness, returning the decoded challenge.
 * Throws on a bad MAC, malformed token, or an `iat` outside ±`maxAgeSeconds` of `nowSeconds`.
 */
export function verifyChallenge(
  token: string,
  secret: Uint8Array,
  nowSeconds: number,
  maxAgeSeconds: number = MAX_AGE_SECONDS,
): Challenge {
  const dot = token.indexOf(".");
  if (dot < 1 || dot === token.length - 1) {
    throw new Error("malformed challenge");
  }
  const payload = token.slice(0, dot);

  let provided: Uint8Array;
  try {
    provided = decodeBase64Url(token.slice(dot + 1));
  } catch {
    throw new Error("malformed challenge MAC");
  }
  if (!timingSafeEqual(provided, mac(payload, secret))) {
    throw new Error("bad challenge MAC");
  }

  const challenge = JSON.parse(
    dec.decode(decodeBase64Url(payload)),
  ) as Challenge;
  if (typeof challenge.iat !== "number") throw new Error("bad challenge iat");
  if (challenge.iat > nowSeconds + maxAgeSeconds) {
    throw new Error("challenge from the future");
  }
  if (challenge.iat < nowSeconds - maxAgeSeconds) {
    throw new Error("challenge expired");
  }
  return challenge;
}

/** A random nonce for a fresh challenge. */
export function randomNonce(): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)));
}
