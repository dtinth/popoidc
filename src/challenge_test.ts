import { assertEquals, assertThrows } from "@std/assert";
import { encodeBase64Url } from "@std/encoding/base64url";
import {
  type Challenge,
  issueChallenge,
  verifyChallenge,
} from "./challenge.ts";

const secret = new TextEncoder().encode("test-hmac-secret");
const base: Challenge = {
  v: 1,
  method: "sign",
  aud: "octo-sts.dev",
  key: "ssh-ed25519 AAAAC3Nz",
  iat: 1_000_000,
  nonce: "kZ3Qm9",
};

Deno.test("an issued challenge verifies and round-trips its fields", () => {
  const token = issueChallenge(base, secret);
  assertEquals(verifyChallenge(token, secret, base.iat), base);
});

Deno.test("verifyChallenge rejects a tampered payload", () => {
  const [p, m] = issueChallenge(base, secret).split(".");
  const tampered = p.slice(0, -1) + (p.endsWith("A") ? "B" : "A") + "." + m;
  assertThrows(() => verifyChallenge(tampered, secret, base.iat));
});

Deno.test("verifyChallenge rejects a wrong secret", () => {
  const token = issueChallenge(base, secret);
  assertThrows(() =>
    verifyChallenge(token, new TextEncoder().encode("other"), base.iat)
  );
});

Deno.test("verifyChallenge rejects an expired challenge", () => {
  const token = issueChallenge(base, secret);
  assertThrows(() => verifyChallenge(token, secret, base.iat + 61));
});

Deno.test("verifyChallenge rejects a challenge from the future", () => {
  const token = issueChallenge(base, secret);
  assertThrows(() => verifyChallenge(token, secret, base.iat - 61));
});

Deno.test("verifyChallenge accepts within the freshness window", () => {
  const token = issueChallenge(base, secret);
  verifyChallenge(token, secret, base.iat + 59); // must not throw
});

Deno.test("verifyChallenge rejects a token with no dot", () => {
  assertThrows(() => verifyChallenge("nodothere", secret, base.iat));
});

Deno.test("verifyChallenge rejects a token with an empty MAC", () => {
  assertThrows(() => verifyChallenge("payload.", secret, base.iat));
});

Deno.test("verifyChallenge rejects a non-base64url MAC", () => {
  const [payload] = issueChallenge(base, secret).split(".");
  assertThrows(() => verifyChallenge(`${payload}.!!!`, secret, base.iat));
});

Deno.test("verifyChallenge rejects a MAC of the wrong length", () => {
  const [payload] = issueChallenge(base, secret).split(".");
  const shortMac = encodeBase64Url(new Uint8Array(8));
  assertThrows(() =>
    verifyChallenge(`${payload}.${shortMac}`, secret, base.iat)
  );
});

Deno.test("verifyChallenge rejects a challenge with a non-numeric iat", () => {
  const token = issueChallenge({ ...base, iat: NaN }, secret);
  assertThrows(() => verifyChallenge(token, secret, base.iat));
});
