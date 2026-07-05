import { assertEquals, assertThrows } from "@std/assert";
import { verifySshsig } from "./sshsig.ts";
import { parseSshEd25519, sshFingerprint } from "./sshkey.ts";
import { genEd25519, sshSign, withTempDir } from "./testutil.ts";

const enc = new TextEncoder();

Deno.test("verifySshsig accepts a genuine signature and returns the signer key", async () => {
  await withTempDir(async (dir) => {
    const pubLine = await genEd25519(dir);
    const message = enc.encode(
      "sshid challenge: aud=octo-sts.dev iat=1751731200",
    );
    const armored = await sshSign(dir, "id", "sshid", message);

    const { publicKeyWire } = verifySshsig(message, armored, "sshid");

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
    const armored = await sshSign(dir, "id", "not-sshid", message);
    assertThrows(() => verifySshsig(message, armored, "sshid"));
  });
});

Deno.test("verifySshsig rejects a tampered message", async () => {
  await withTempDir(async (dir) => {
    await genEd25519(dir);
    const armored = await sshSign(dir, "id", "sshid", enc.encode("original"));
    assertThrows(() => verifySshsig(enc.encode("tampered"), armored, "sshid"));
  });
});
