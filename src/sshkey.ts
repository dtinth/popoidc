import { decodeBase64, encodeBase64 } from "@std/encoding/base64";
import { sha256 } from "@noble/hashes/sha2.js";

/** A parsed `ssh-ed25519` public key. */
export interface SshEd25519Key {
  /** Full public-key wire blob: string "ssh-ed25519" + string(32-byte pubkey). */
  wire: Uint8Array;
  /** Raw 32-byte Ed25519 public key. */
  ed25519: Uint8Array;
  /** Free-text comment (may be empty). */
  comment: string;
}

/** Read a length-prefixed SSH wire string, returning its bytes and the next offset. */
function readString(buf: Uint8Array, offset: number): [Uint8Array, number] {
  if (offset + 4 > buf.length) throw new Error("ssh wire: truncated length");
  const len = new DataView(buf.buffer, buf.byteOffset + offset, 4).getUint32(0);
  const start = offset + 4;
  const end = start + len;
  if (end > buf.length) throw new Error("ssh wire: truncated string");
  return [buf.subarray(start, end), end];
}

/** Parse an `ssh-ed25519 AAAA... [comment]` public key line. Throws on anything else. */
export function parseSshEd25519(line: string): SshEd25519Key {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 2) throw new Error("invalid ssh public key line");
  const [type, b64, ...rest] = parts;
  if (type !== "ssh-ed25519") throw new Error(`unsupported key type: ${type}`);

  let wire: Uint8Array;
  try {
    wire = decodeBase64(b64);
  } catch {
    throw new Error("invalid base64 in ssh public key");
  }

  const [algo, afterAlgo] = readString(wire, 0);
  if (new TextDecoder().decode(algo) !== "ssh-ed25519") {
    throw new Error("wire key type mismatch");
  }
  const [pub, end] = readString(wire, afterAlgo);
  if (pub.length !== 32) throw new Error("ed25519 public key must be 32 bytes");
  if (end !== wire.length) throw new Error("trailing bytes in ssh public key");

  return { wire, ed25519: pub, comment: rest.join(" ") };
}

/** The OpenSSH SHA256 fingerprint: `SHA256:` + unpadded base64 of SHA-256(wire). */
export function sshFingerprint(wire: Uint8Array): string {
  return "SHA256:" + encodeBase64(sha256(wire)).replace(/=+$/, "");
}
