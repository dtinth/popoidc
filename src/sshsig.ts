import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { decodeBase64 } from "@std/encoding/base64";
import { concat, Reader, writeString } from "./sshwire.ts";

// SSHSIG format: see OpenSSH PROTOCOL.sshsig.
const MAGIC = new TextEncoder().encode("SSHSIG");
const enc = new TextEncoder();
const dec = new TextDecoder();

export interface SshsigResult {
  /** The signer's public-key wire blob (string "ssh-ed25519" + string pubkey). */
  publicKeyWire: Uint8Array;
}

/** Strip the `-----BEGIN/END SSH SIGNATURE-----` armor and base64-decode the body. */
function dearmor(armored: string): Uint8Array {
  const m = armored.match(
    /-----BEGIN SSH SIGNATURE-----([\s\S]*?)-----END SSH SIGNATURE-----/,
  );
  if (!m) throw new Error("not an SSH signature");
  return decodeBase64(m[1].replace(/\s+/g, ""));
}

function hashMessage(algorithm: string, message: Uint8Array): Uint8Array {
  if (algorithm === "sha512") return sha512(message);
  if (algorithm === "sha256") return sha256(message);
  throw new Error(`unsupported SSHSIG hash algorithm: ${algorithm}`);
}

/**
 * Verify an armored SSHSIG over `message` under `expectedNamespace`.
 * Returns the signer's public key on success; throws on any failure.
 * Only `ssh-ed25519` keys are supported.
 */
export function verifySshsig(
  message: Uint8Array,
  armored: string,
  expectedNamespace: string,
): SshsigResult {
  const r = new Reader(dearmor(armored));

  const magic = r.readBytes(6);
  if (!MAGIC.every((b, i) => b === magic[i])) {
    throw new Error("bad SSHSIG magic");
  }
  const version = r.readUint32();
  if (version !== 1) throw new Error(`unsupported SSHSIG version ${version}`);

  const publicKeyWire = r.readString();
  const namespace = dec.decode(r.readString());
  if (namespace !== expectedNamespace) {
    throw new Error(`namespace mismatch: ${namespace} != ${expectedNamespace}`);
  }
  r.readString(); // reserved
  const hashAlgorithm = dec.decode(r.readString());
  const signatureBlob = r.readString();

  // Public key: string "ssh-ed25519" + string(32-byte key).
  const pk = new Reader(publicKeyWire);
  if (dec.decode(pk.readString()) !== "ssh-ed25519") {
    throw new Error("unsupported SSHSIG key type");
  }
  const publicKey = pk.readString();
  if (publicKey.length !== 32) throw new Error("bad ed25519 public key length");

  // Signature: string "ssh-ed25519" + string(64-byte signature).
  const sig = new Reader(signatureBlob);
  if (dec.decode(sig.readString()) !== "ssh-ed25519") {
    throw new Error("unsupported SSHSIG signature type");
  }
  const rawSignature = sig.readString();
  if (rawSignature.length !== 64) {
    throw new Error("bad ed25519 signature length");
  }

  // The signed blob is MAGIC || namespace || reserved || hash_alg || H(message).
  const signed = concat(
    MAGIC,
    writeString(enc.encode(namespace)),
    writeString(new Uint8Array(0)),
    writeString(enc.encode(hashAlgorithm)),
    writeString(hashMessage(hashAlgorithm, message)),
  );

  if (!ed25519.verify(rawSignature, signed, publicKey)) {
    throw new Error("SSHSIG signature verification failed");
  }
  return { publicKeyWire };
}
