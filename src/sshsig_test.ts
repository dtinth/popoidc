import { assertEquals, assertThrows } from "@std/assert";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { encodeBase64 } from "@std/encoding/base64";
import { verifySshsig } from "./sshsig.ts";
import { parseSshEd25519, sshFingerprint } from "./sshkey.ts";
import { concat, writeString } from "./sshwire.ts";
import { genEd25519, sshSign, withTempDir } from "./testutil.ts";

const enc = new TextEncoder();
const MAGIC = enc.encode("SSHSIG");

function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

/** Build an armored SSHSIG blob — valid by default, with overridable fields for negative tests. */
function buildSshsig(opts: {
  message?: Uint8Array;
  namespace?: string;
  hashAlg?: string;
  magic?: Uint8Array;
  version?: number;
  pkAlgo?: string;
  pubkeyLen?: number;
  sigAlgo?: string;
  sigLen?: number;
  corruptSig?: boolean;
} = {}): string {
  const sk = ed25519.utils.randomSecretKey();
  const pub = ed25519.getPublicKey(sk);
  const message = opts.message ?? enc.encode("m");
  const ns = opts.namespace ?? "popoidc";
  const hashAlg = opts.hashAlg ?? "sha512";
  const h = hashAlg === "sha256"
    ? sha256(message)
    : hashAlg === "sha512"
    ? sha512(message)
    : new Uint8Array(0);
  const signed = concat(
    MAGIC,
    writeString(enc.encode(ns)),
    writeString(new Uint8Array(0)),
    writeString(enc.encode(hashAlg)),
    writeString(h),
  );
  const rawSig = opts.corruptSig
    ? ed25519.sign(enc.encode("other"), sk)
    : ed25519.sign(signed, sk);
  const pkField = concat(
    writeString(enc.encode(opts.pkAlgo ?? "ssh-ed25519")),
    writeString(
      opts.pubkeyLen !== undefined ? new Uint8Array(opts.pubkeyLen) : pub,
    ),
  );
  const sigField = concat(
    writeString(enc.encode(opts.sigAlgo ?? "ssh-ed25519")),
    writeString(
      opts.sigLen !== undefined ? new Uint8Array(opts.sigLen) : rawSig,
    ),
  );
  const blob = concat(
    opts.magic ?? MAGIC,
    u32(opts.version ?? 1),
    writeString(pkField),
    writeString(enc.encode(ns)),
    writeString(new Uint8Array(0)),
    writeString(enc.encode(hashAlg)),
    writeString(sigField),
  );
  return `-----BEGIN SSH SIGNATURE-----\n${
    encodeBase64(blob)
  }\n-----END SSH SIGNATURE-----\n`;
}

Deno.test("verifySshsig accepts a genuine signature and returns the signer key", async () => {
  await withTempDir(async (dir) => {
    const pubLine = await genEd25519(dir);
    const message = enc.encode(
      "popoidc challenge: aud=octo-sts.dev iat=1751731200",
    );
    const armored = await sshSign(dir, "id", "popoidc", message);

    const { publicKeyWire } = verifySshsig(message, armored, "popoidc");

    assertEquals(
      sshFingerprint(publicKeyWire),
      sshFingerprint(parseSshEd25519(pubLine).wire),
    );
  });
});

Deno.test("verifySshsig rejects a signature made under a different namespace", async () => {
  await withTempDir(async (dir) => {
    await genEd25519(dir);
    const message = enc.encode("payload");
    const armored = await sshSign(dir, "id", "not-popoidc", message);
    assertThrows(() => verifySshsig(message, armored, "popoidc"));
  });
});

Deno.test("verifySshsig rejects a tampered message", async () => {
  await withTempDir(async (dir) => {
    await genEd25519(dir);
    const armored = await sshSign(dir, "id", "popoidc", enc.encode("original"));
    assertThrows(() =>
      verifySshsig(enc.encode("tampered"), armored, "popoidc")
    );
  });
});

Deno.test("verifySshsig accepts a valid sha256 signature", () => {
  const message = enc.encode("hello sha256");
  const { publicKeyWire } = verifySshsig(
    message,
    buildSshsig({ message, hashAlg: "sha256" }),
    "popoidc",
  );
  assertEquals(publicKeyWire.length > 0, true);
});

Deno.test("verifySshsig rejects non-armored input", () => {
  assertThrows(() =>
    verifySshsig(enc.encode("m"), "not a signature", "popoidc")
  );
});

Deno.test("verifySshsig rejects bad magic", () => {
  assertThrows(() =>
    verifySshsig(
      enc.encode("m"),
      buildSshsig({ magic: enc.encode("BADSIG") }),
      "popoidc",
    )
  );
});

Deno.test("verifySshsig rejects an unsupported version", () => {
  assertThrows(() =>
    verifySshsig(enc.encode("m"), buildSshsig({ version: 2 }), "popoidc")
  );
});

Deno.test("verifySshsig rejects an unsupported key type", () => {
  assertThrows(() =>
    verifySshsig(enc.encode("m"), buildSshsig({ pkAlgo: "ssh-rsa" }), "popoidc")
  );
});

Deno.test("verifySshsig rejects a bad public key length", () => {
  assertThrows(() =>
    verifySshsig(enc.encode("m"), buildSshsig({ pubkeyLen: 8 }), "popoidc")
  );
});

Deno.test("verifySshsig rejects an unsupported signature type", () => {
  assertThrows(() =>
    verifySshsig(
      enc.encode("m"),
      buildSshsig({ sigAlgo: "ssh-rsa" }),
      "popoidc",
    )
  );
});

Deno.test("verifySshsig rejects a bad signature length", () => {
  assertThrows(() =>
    verifySshsig(enc.encode("m"), buildSshsig({ sigLen: 8 }), "popoidc")
  );
});

Deno.test("verifySshsig rejects an unsupported hash algorithm", () => {
  assertThrows(() =>
    verifySshsig(enc.encode("m"), buildSshsig({ hashAlg: "md5" }), "popoidc")
  );
});

Deno.test("verifySshsig rejects a signature that does not verify", () => {
  assertThrows(() =>
    verifySshsig(enc.encode("m"), buildSshsig({ corruptSig: true }), "popoidc")
  );
});
