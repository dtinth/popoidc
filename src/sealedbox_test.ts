import { assertEquals, assertThrows } from "@std/assert";
import { seal, unseal } from "./sealedbox.ts";

const enc = new TextEncoder();
const secret = enc.encode("server-secret");
const LABEL = "popoidc/test/v1";

Deno.test("seal round-trips a value through unseal", () => {
  const value = { secret: "s3cret", exp: 1_700_000_060 };
  assertEquals(unseal(seal(value, secret, LABEL), secret, LABEL), value);
});

Deno.test("seal produces a different string every time (random nonce)", () => {
  const a = seal({ v: 1 }, secret, LABEL);
  const b = seal({ v: 1 }, secret, LABEL);
  assertEquals(a === b, false);
});

Deno.test("unseal rejects a value sealed under a different label", () => {
  const sealed = seal({ v: 1 }, secret, LABEL);
  assertThrows(() => unseal(sealed, secret, "popoidc/other/v1"));
});

Deno.test("unseal rejects a value sealed under a different secret", () => {
  const sealed = seal({ v: 1 }, secret, LABEL);
  assertThrows(() => unseal(sealed, enc.encode("other-secret"), LABEL));
});

Deno.test("unseal rejects a tampered body", () => {
  const sealed = seal({ v: 1 }, secret, LABEL);
  const flipped = sealed.slice(0, -2) +
    (sealed.at(-2) === "A" ? "B" : "A") + sealed.at(-1);
  assertThrows(() => unseal(flipped, secret, LABEL));
});

Deno.test("unseal rejects a malformed or truncated value", () => {
  assertThrows(() => unseal("!!!not base64!!!", secret, LABEL));
  assertThrows(() => unseal("AAAA", secret, LABEL));
});
