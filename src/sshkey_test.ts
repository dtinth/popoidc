import { assertEquals, assertThrows } from "@std/assert";
import { parseSshEd25519, sshFingerprint } from "./sshkey.ts";

async function sshKeygen(args: string[], cwd: string): Promise<string> {
  const { code, stdout, stderr } = await new Deno.Command("ssh-keygen", {
    args,
    cwd,
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (code !== 0) {
    throw new Error("ssh-keygen failed: " + new TextDecoder().decode(stderr));
  }
  return new TextDecoder().decode(stdout);
}

Deno.test("sshFingerprint matches `ssh-keygen -lf` for a generated ed25519 key", async () => {
  const dir = await Deno.makeTempDir();
  try {
    await sshKeygen([
      "-t",
      "ed25519",
      "-N",
      "",
      "-C",
      "alice@example",
      "-f",
      "id",
    ], dir);
    const pubLine = (await Deno.readTextFile(`${dir}/id.pub`)).trim();
    // `ssh-keygen -lf` prints e.g. "256 SHA256:xxxx alice@example (ED25519)"
    const expected = (await sshKeygen(["-lf", "id.pub"], dir)).split(/\s+/)[1];

    const key = parseSshEd25519(pubLine);
    assertEquals(key.comment, "alice@example");
    assertEquals(key.ed25519.length, 32);
    assertEquals(sshFingerprint(key.wire), expected);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("parseSshEd25519 rejects a non-ed25519 key type", () => {
  assertThrows(() => parseSshEd25519("ssh-rsa AAAAB3NzaC1yc2E comment"));
});

Deno.test("parseSshEd25519 rejects malformed input", () => {
  assertThrows(() => parseSshEd25519("not-a-key"));
});
