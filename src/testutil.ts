// Shared test helpers that drive the real `ssh-keygen` and `age` binaries, so
// tests verify against ground-truth implementations rather than our own code.

import { exportJWK, generateKeyPair } from "jose";
import type { SigningKey } from "./token.ts";
import type { Config } from "./config.ts";

/** A ready-to-use Config for handler tests. */
export async function testConfig(
  overrides: Partial<Config> = {},
): Promise<Config> {
  return {
    issuer: "https://popoidc.test",
    namespace: "popoidc",
    hmacSecret: new TextEncoder().encode("test-hmac-secret"),
    signingKey: await testSigningKey(),
    ...overrides,
  };
}

/** An ephemeral RS256 signing key for tests. */
export async function testSigningKey(kid = "test-key-1"): Promise<SigningKey> {
  const { publicKey, privateKey } = await generateKeyPair("RS256", {
    extractable: true,
  });
  const publicJwk = {
    ...(await exportJWK(publicKey)),
    kid,
    alg: "RS256",
    use: "sig",
  };
  return { kid, privateKey, publicJwk };
}

async function run(
  bin: string,
  args: string[],
  opts: { cwd?: string; stdin?: Uint8Array } = {},
): Promise<Uint8Array> {
  const cmd = new Deno.Command(bin, {
    args,
    cwd: opts.cwd,
    stdin: opts.stdin ? "piped" : "null",
    stdout: "piped",
    stderr: "piped",
  });
  const child = cmd.spawn();
  if (opts.stdin) {
    const w = child.stdin.getWriter();
    await w.write(opts.stdin);
    await w.close();
  }
  const { code, stdout, stderr } = await child.output();
  if (code !== 0) {
    throw new Error(
      `${bin} ${args.join(" ")} failed: ${new TextDecoder().decode(stderr)}`,
    );
  }
  return stdout;
}

export function sshKeygen(args: string[], cwd: string): Promise<Uint8Array> {
  return run("ssh-keygen", args, { cwd });
}

/** Generate a native age identity; return the identity file path and its `age1…` recipient. */
export async function genAgeIdentity(
  dir: string,
  name = "agekey.txt",
): Promise<{ identityFile: string; recipient: string }> {
  await run("age-keygen", ["-o", name], { cwd: dir });
  const recipient = new TextDecoder().decode(
    await run("age-keygen", ["-y", name], { cwd: dir }),
  )
    .trim();
  return { identityFile: `${dir}/${name}`, recipient };
}

/** Decrypt an armored age file with the real `age` binary using `identityFile`. */
export function ageDecrypt(
  identityFile: string,
  armored: string,
): Promise<Uint8Array> {
  return run("age", ["-d", "-i", identityFile], {
    stdin: new TextEncoder().encode(armored),
  });
}

/** Generate an ed25519 keypair `<name>`/`<name>.pub` in `dir`; return the public line. */
export async function genEd25519(
  dir: string,
  name = "id",
  comment = "test@popoidc",
): Promise<string> {
  await sshKeygen(["-t", "ed25519", "-N", "", "-C", comment, "-f", name], dir);
  return (await Deno.readTextFile(`${dir}/${name}.pub`)).trim();
}

/** Sign `message` with SSHSIG under `namespace` using private key `name`; return armored sig. */
export async function sshSign(
  dir: string,
  name: string,
  namespace: string,
  message: Uint8Array,
): Promise<string> {
  await Deno.writeFile(`${dir}/msg`, message);
  await sshKeygen(["-Y", "sign", "-n", namespace, "-f", name, "msg"], dir);
  return await Deno.readTextFile(`${dir}/msg.sig`);
}

/** Run a body with a fresh temp dir that is always cleaned up. */
export async function withTempDir(
  fn: (dir: string) => Promise<void>,
): Promise<void> {
  const dir = await Deno.makeTempDir();
  try {
    await fn(dir);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}
