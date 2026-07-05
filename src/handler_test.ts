import { assert, assertEquals } from "@std/assert";
import { createHandler } from "./handler.ts";
import { testConfig } from "./testutil.ts";

Deno.test("GET /.well-known/openid-configuration returns the discovery document", async () => {
  const handler = createHandler(await testConfig());
  const res = await handler(
    new Request("https://sshid.test/.well-known/openid-configuration"),
  );
  assertEquals(res.status, 200);
  const doc = await res.json();
  assertEquals(doc.issuer, "https://sshid.test");
  assertEquals(doc.jwks_uri, "https://sshid.test/.well-known/jwks.json");
  assertEquals(doc.id_token_signing_alg_values_supported, ["RS256"]);
});

Deno.test("GET /.well-known/jwks.json returns the public JWKS", async () => {
  const cfg = await testConfig();
  const res = await createHandler(cfg)(
    new Request("https://sshid.test/.well-known/jwks.json"),
  );
  assertEquals(res.status, 200);
  const doc = await res.json();
  assertEquals(doc.keys[0].kid, cfg.signingKey.kid);
  assert(
    doc.keys[0].d === undefined,
    "JWKS must not leak private key material",
  );
});

Deno.test("an unknown route returns 404", async () => {
  const res = await createHandler(await testConfig())(
    new Request("https://sshid.test/nope"),
  );
  assertEquals(res.status, 404);
});
