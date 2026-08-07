import { assert, assertEquals, assertNotEquals } from "@std/assert";
import { secretFingerprint } from "./hmacid.ts";

const enc = new TextEncoder();
const pepper = enc.encode("server-pepper");

Deno.test("secretFingerprint has the SHA256-fingerprint shape (unpadded base64)", () => {
  const fp = secretFingerprint("a-shared-secret", pepper);
  assert(fp.startsWith("HMAC-SHA256:"), fp);
  const b64 = fp.slice("HMAC-SHA256:".length);
  assertEquals(b64.length, 43); // 32 bytes, base64, padding stripped
  assert(!b64.includes("="), "padding must be stripped");
});

Deno.test("secretFingerprint is deterministic for the same secret and pepper", () => {
  assertEquals(
    secretFingerprint("a-shared-secret", pepper),
    secretFingerprint("a-shared-secret", pepper),
  );
});

Deno.test("secretFingerprint separates different secrets", () => {
  assertNotEquals(
    secretFingerprint("a-shared-secret", pepper),
    secretFingerprint("another-shared-secret", pepper),
  );
});

Deno.test("secretFingerprint separates Issuers: the same secret differs per pepper", () => {
  assertNotEquals(
    secretFingerprint("a-shared-secret", pepper),
    secretFingerprint("a-shared-secret", enc.encode("other-pepper")),
  );
});
