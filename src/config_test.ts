import { assert, assertEquals, assertRejects } from "@std/assert";
import { exportJWK, generateKeyPair } from "jose";
import { loadConfig } from "./config.ts";

function fakeEnv(vars: Record<string, string>) {
  return { get: (k: string) => vars[k] };
}

async function privateJwkJson(kid = "k1"): Promise<string> {
  const { privateKey } = await generateKeyPair("RS256", { extractable: true });
  return JSON.stringify({ ...(await exportJWK(privateKey)), kid });
}

Deno.test("loadConfig builds a Config from env and derives a public-only JWK", async () => {
  const env = fakeEnv({
    POPOIDC_ISSUER: "https://popoidc.example/",
    POPOIDC_SIGNING_JWK: await privateJwkJson("k1"),
    POPOIDC_HMAC_SECRET: "supersecret",
  });

  const cfg = await loadConfig(env);

  assertEquals(cfg.issuer, "https://popoidc.example"); // trailing slash trimmed
  assertEquals(cfg.namespace, "popoidc");
  assertEquals(cfg.signingKey.kid, "k1");
  assertEquals(cfg.signingKey.publicJwk.alg, "RS256");
  assert(
    cfg.signingKey.publicJwk.d === undefined,
    "must not expose private key",
  );
});

Deno.test("loadConfig requires POPOIDC_ISSUER", async () => {
  await assertRejects(() =>
    loadConfig(fakeEnv({ POPOIDC_SIGNING_JWK: "{}", POPOIDC_HMAC_SECRET: "x" }))
  );
});

Deno.test("loadConfig rejects a JWK that is not an RSA private key with a kid", async () => {
  await assertRejects(() =>
    loadConfig(fakeEnv({
      POPOIDC_ISSUER: "https://x",
      POPOIDC_SIGNING_JWK: JSON.stringify({ kty: "oct", k: "aaaa" }),
      POPOIDC_HMAC_SECRET: "x",
    }))
  );
});

Deno.test("loadConfig rejects a signing JWK that is not valid JSON", async () => {
  await assertRejects(() =>
    loadConfig(fakeEnv({
      POPOIDC_ISSUER: "https://x",
      POPOIDC_SIGNING_JWK: "not json {",
      POPOIDC_HMAC_SECRET: "x",
    }))
  );
});
