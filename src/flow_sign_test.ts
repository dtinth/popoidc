import { assertEquals } from "@std/assert";
import { createLocalJWKSet, jwtVerify } from "jose";
import { createHandler } from "./handler.ts";
import { jwksDocument } from "./token.ts";
import { parseSshEd25519, sshFingerprint } from "./sshkey.ts";
import { genEd25519, sshSign, testConfig, withTempDir } from "./testutil.ts";

const enc = new TextEncoder();

function challengeUrl(key: string, aud: string): string {
  return `https://sshid.test/challenge?key=${encodeURIComponent(key)}&aud=${
    encodeURIComponent(aud)
  }`;
}

function postToken(fields: Record<string, string>): Request {
  return new Request("https://sshid.test/token", {
    method: "POST",
    body: new URLSearchParams(fields),
  });
}

Deno.test("signing flow: challenge → ssh-keygen sign → Token", async () => {
  await withTempDir(async (dir) => {
    const cfg = await testConfig();
    const now = 1_700_000_000;
    const handler = createHandler(cfg, { now: () => now });
    const pubLine = await genEd25519(dir);

    const challenge =
      await (await handler(new Request(challengeUrl(pubLine, "octo-sts.dev"))))
        .text();
    const signature = await sshSign(
      dir,
      "id",
      cfg.namespace,
      enc.encode(challenge),
    );

    const res = await handler(postToken({ challenge, signature }));
    assertEquals(res.status, 200);
    const jwt = (await res.text()).trim();

    const jwks = createLocalJWKSet(jwksDocument([cfg.signingKey]));
    const { payload } = await jwtVerify(jwt, jwks, {
      issuer: cfg.issuer,
      audience: "octo-sts.dev",
      currentDate: new Date((now + 1) * 1000),
    });
    assertEquals(payload.sub, sshFingerprint(parseSshEd25519(pubLine).wire));
    assertEquals(payload.key_type, "ssh-ed25519");
    assertEquals(payload.key, pubLine);
  });
});

Deno.test("token endpoint rejects a signature from a different key", async () => {
  await withTempDir(async (dir) => {
    const cfg = await testConfig();
    const handler = createHandler(cfg, { now: () => 1_700_000_000 });
    const pubLine = await genEd25519(dir, "id");
    await genEd25519(dir, "other");

    const challenge =
      await (await handler(new Request(challengeUrl(pubLine, "octo-sts.dev"))))
        .text();
    const signature = await sshSign(
      dir,
      "other",
      cfg.namespace,
      enc.encode(challenge),
    );

    const res = await handler(postToken({ challenge, signature }));
    assertEquals(res.status, 401);
  });
});

Deno.test("token endpoint rejects a challenge that is past the freshness window", async () => {
  await withTempDir(async (dir) => {
    const cfg = await testConfig();
    let clock = 1_700_000_000;
    const handler = createHandler(cfg, { now: () => clock });
    const pubLine = await genEd25519(dir);

    const challenge =
      await (await handler(new Request(challengeUrl(pubLine, "octo-sts.dev"))))
        .text();
    const signature = await sshSign(
      dir,
      "id",
      cfg.namespace,
      enc.encode(challenge),
    );

    clock += 120; // beyond the ±60s window
    const res = await handler(postToken({ challenge, signature }));
    assertEquals(res.status, 401);
  });
});
