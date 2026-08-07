import { assertEquals, assertNotEquals } from "@std/assert";
import { createLocalJWKSet, jwtVerify } from "jose";
import { createHandler } from "./handler.ts";
import { jwksDocument } from "./token.ts";
import { secretFingerprint } from "./hmacid.ts";
import { testConfig } from "./testutil.ts";

const NOW = 1_700_000_000;
const SECRET = "9ZqFq0k7pR2sT4vW6xY8zA==";

function postToken(fields: Record<string, string>): Request {
  return new Request("https://popoidc.test/token", {
    method: "POST",
    body: new URLSearchParams(fields),
  });
}

/** Mint via HMAC mode and return the raw JWT (asserting a 200 first). */
async function mint(
  handler: (req: Request) => Promise<Response>,
  fields: Record<string, string>,
): Promise<string> {
  const res = await handler(postToken(fields));
  assertEquals(res.status, 200);
  return (await res.text()).trim();
}

Deno.test("hmac flow: secret → Token, in one request", async () => {
  const cfg = await testConfig();
  const handler = createHandler(cfg, { now: () => NOW });

  const jwt = await mint(handler, { secret: SECRET, aud: "octo-sts.dev" });

  const jwks = createLocalJWKSet(jwksDocument([cfg.signingKey]));
  const { payload } = await jwtVerify(jwt, jwks, {
    issuer: cfg.issuer,
    audience: "octo-sts.dev",
    currentDate: new Date((NOW + 1) * 1000),
  });
  assertEquals(payload.sub, secretFingerprint(SECRET, cfg.hmacIdentitySecret!));
  assertEquals(payload.key_type, "hmac");
  // No public half to publish — `key` restates the fingerprint, never the secret.
  assertEquals(payload.key, payload.sub);
});

Deno.test("hmac flow: the same secret always names the same Identity", async () => {
  const handler = createHandler(await testConfig(), { now: () => NOW });
  const claims = async (secret: string) =>
    JSON.parse(
      atob(
        (await mint(handler, { secret, aud: "octo-sts.dev" })).split(".")[1],
      ),
    ).sub;

  assertEquals(await claims(SECRET), await claims(SECRET));
  assertNotEquals(await claims(SECRET), await claims(SECRET + "x"));
});

Deno.test("hmac mode is off unless an identity pepper is configured", async () => {
  const cfg = await testConfig({ hmacIdentitySecret: undefined });
  const res = await createHandler(cfg, { now: () => NOW })(
    postToken({ secret: SECRET, aud: "octo-sts.dev" }),
  );
  assertEquals(res.status, 501);
});

Deno.test("/token (hmac) requires aud", async () => {
  const res = await createHandler(await testConfig(), { now: () => NOW })(
    postToken({ secret: SECRET }),
  );
  assertEquals(res.status, 400);
});

Deno.test("/token (hmac) rejects a guessably short secret", async () => {
  const res = await createHandler(await testConfig(), { now: () => NOW })(
    postToken({ secret: "hunter2", aud: "octo-sts.dev" }),
  );
  assertEquals(res.status, 400);
});

Deno.test("/token rejects a request carrying both a challenge and a secret", async () => {
  const res = await createHandler(await testConfig(), { now: () => NOW })(
    postToken({ challenge: "x.y", secret: SECRET, aud: "octo-sts.dev" }),
  );
  assertEquals(res.status, 400);
});
