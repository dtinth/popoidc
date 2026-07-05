import { assertEquals } from "@std/assert";
import { encryptToRecipient } from "./agecrypt.ts";
import {
  ageDecrypt,
  genAgeIdentity,
  genEd25519,
  withTempDir,
} from "./testutil.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();

// ADR-0002 gate: encrypt in TS, decrypt with the real `age` binary. Must round-trip.

Deno.test("encryptToRecipient round-trips through age (native age1 X25519)", async () => {
  await withTempDir(async (dir) => {
    const { identityFile, recipient } = await genAgeIdentity(dir);
    const secret = "the-challenge-secret-42";
    const armored = await encryptToRecipient(recipient, enc.encode(secret));
    assertEquals(dec.decode(await ageDecrypt(identityFile, armored)), secret);
  });
});

Deno.test("encryptToRecipient round-trips through age (reimplemented ssh-ed25519 stanza)", async () => {
  await withTempDir(async (dir) => {
    const pubLine = await genEd25519(dir, "id");
    const secret = "ssh-decryption-proof-secret";
    const armored = await encryptToRecipient(pubLine, enc.encode(secret));
    // The ssh *private* key doubles as an age identity.
    assertEquals(dec.decode(await ageDecrypt(`${dir}/id`, armored)), secret);
  });
});
