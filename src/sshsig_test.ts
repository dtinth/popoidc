import { assertEquals, assertThrows } from "@std/assert";
import { verifySshsig } from "./sshsig.ts";
import { parseSshEd25519, sshFingerprint } from "./sshkey.ts";
import { genEd25519, sshSign, withTempDir } from "./testutil.ts";

const enc = new TextEncoder();

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
