import { assertEquals } from "@std/assert";
import { createLocalJWKSet, jwtVerify } from "jose";
import { createHandler } from "./handler.ts";
import { jwksDocument } from "./token.ts";
import { parseSshEd25519, sshFingerprint } from "./sshkey.ts";
import {
  ageDecrypt,
  genAgeIdentity,
  genEd25519,
  testConfig,
  withTempDir,
} from "./testutil.ts";

const dec = new TextDecoder();

function challengeUrl(key: string, aud: string, method?: string): string {
  const u = new URL("https://sshid.test/challenge");
  u.searchParams.set("key", key);
  u.searchParams.set("aud", aud);
  if (method) u.searchParams.set("method", method);
  return u.toString();
}

function postToken(challenge: string): Request {
  return new Request("https://sshid.test/token", {
    method: "POST",
    body: new URLSearchParams({ challenge }),
  });
}

Deno.test("decryption flow (native age1): challenge → age -d → Token", async () => {
  await withTempDir(async (dir) => {
    const cfg = await testConfig();
    const now = 1_700_000_000;
    const handler = createHandler(cfg, { now: () => now });
    const { identityFile, recipient } = await genAgeIdentity(dir);

    const armored = await (await handler(
      new Request(challengeUrl(recipient, "octo-sts.dev")),
    )).text();
    const token = dec.decode(await ageDecrypt(identityFile, armored));

    const res = await handler(postToken(token));
    assertEquals(res.status, 200);
    const jwt = (await res.text()).trim();

    const jwks = createLocalJWKSet(jwksDocument([cfg.signingKey]));
    const { payload } = await jwtVerify(jwt, jwks, {
      issuer: cfg.issuer,
      audience: "octo-sts.dev",
      currentDate: new Date((now + 1) * 1000),
    });
    assertEquals(payload.sub, recipient);
    assertEquals(payload.key_type, "age");
  });
});

Deno.test("decryption flow (ssh-ed25519): challenge → age -d → Token", async () => {
  await withTempDir(async (dir) => {
    const cfg = await testConfig();
    const now = 1_700_000_000;
    const handler = createHandler(cfg, { now: () => now });
    const pubLine = await genEd25519(dir, "id");

    const armored = await (await handler(
      new Request(challengeUrl(pubLine, "octo-sts.dev", "decrypt")),
    )).text();
    const token = dec.decode(await ageDecrypt(`${dir}/id`, armored));

    const res = await handler(postToken(token));
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
  });
});
