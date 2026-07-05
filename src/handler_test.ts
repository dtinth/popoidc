import { assert, assertEquals } from "@std/assert";
import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeBase64 } from "@std/encoding/base64";
import { createHandler } from "./handler.ts";
import { issueChallenge } from "./challenge.ts";
import { concat, writeString } from "./sshwire.ts";
import { testConfig } from "./testutil.ts";

const NOW = 1_700_000_000;

/** A syntactically valid ssh-ed25519 public key line (no private key needed). */
function sshPubLine(): string {
  const pub = ed25519.getPublicKey(ed25519.utils.randomSecretKey());
  const wire = concat(
    writeString(new TextEncoder().encode("ssh-ed25519")),
    writeString(pub),
  );
  return "ssh-ed25519 " + encodeBase64(wire);
}

function postToken(fields: Record<string, string>): Request {
  return new Request("https://popoidc.test/token", {
    method: "POST",
    body: new URLSearchParams(fields),
  });
}

Deno.test("GET /.well-known/openid-configuration returns the discovery document", async () => {
  const handler = createHandler(await testConfig());
  const res = await handler(
    new Request("https://popoidc.test/.well-known/openid-configuration"),
  );
  assertEquals(res.status, 200);
  const doc = await res.json();
  assertEquals(doc.issuer, "https://popoidc.test");
  assertEquals(doc.jwks_uri, "https://popoidc.test/.well-known/jwks.json");
  assertEquals(doc.id_token_signing_alg_values_supported, ["RS256"]);
});

Deno.test("GET /.well-known/jwks.json returns the public JWKS", async () => {
  const cfg = await testConfig();
  const res = await createHandler(cfg)(
    new Request("https://popoidc.test/.well-known/jwks.json"),
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
    new Request("https://popoidc.test/nope"),
  );
  assertEquals(res.status, 404);
});

Deno.test("GET / redirects to the GitHub readme", async () => {
  const res = await createHandler(await testConfig())(
    new Request("https://popoidc.test/"),
  );
  assertEquals(res.status, 302);
  assertEquals(
    res.headers.get("location"),
    "https://github.com/dtinth/popoidc#readme",
  );
});

Deno.test("/challenge requires key and aud", async () => {
  const res = await createHandler(await testConfig())(
    new Request("https://popoidc.test/challenge?aud=octo-sts.dev"),
  );
  assertEquals(res.status, 400);
});

Deno.test("/challenge rejects an unsupported key type", async () => {
  const res = await createHandler(await testConfig())(
    new Request("https://popoidc.test/challenge?key=whatever&aud=x"),
  );
  assertEquals(res.status, 400);
});

Deno.test("/challenge rejects an invalid ssh-ed25519 key", async () => {
  const url = "https://popoidc.test/challenge?key=" +
    encodeURIComponent("ssh-ed25519 !!!bad") + "&aud=x";
  const res = await createHandler(await testConfig())(new Request(url));
  assertEquals(res.status, 400);
});

Deno.test("/challenge rejects an invalid age recipient", async () => {
  const res = await createHandler(await testConfig())(
    new Request(
      "https://popoidc.test/challenge?key=age1notarealrecipient&aud=x&method=decrypt",
    ),
  );
  assertEquals(res.status, 400);
});

Deno.test("/token requires a challenge", async () => {
  const res = await createHandler(await testConfig())(postToken({}));
  assertEquals(res.status, 400);
});

Deno.test("/token (sign) requires a signature", async () => {
  const cfg = await testConfig();
  const challenge = issueChallenge(
    { v: 1, method: "sign", aud: "x", key: sshPubLine(), iat: NOW, nonce: "n" },
    cfg.hmacSecret,
  );
  const res = await createHandler(cfg, { now: () => NOW })(
    postToken({ challenge }),
  );
  assertEquals(res.status, 400);
});

Deno.test("/token (sign) rejects an unverifiable signature", async () => {
  const cfg = await testConfig();
  const challenge = issueChallenge(
    { v: 1, method: "sign", aud: "x", key: sshPubLine(), iat: NOW, nonce: "n" },
    cfg.hmacSecret,
  );
  const res = await createHandler(cfg, { now: () => NOW })(
    postToken({ challenge, signature: "garbage" }),
  );
  assertEquals(res.status, 401);
});

Deno.test("/token returns 500 when signing fails unexpectedly", async () => {
  const cfg = await testConfig();
  const broken = {
    ...cfg,
    signingKey: { ...cfg.signingKey, privateKey: {} as unknown as CryptoKey },
  };
  const challenge = issueChallenge(
    { v: 1, method: "decrypt", aud: "x", key: "age1qqq", iat: NOW, nonce: "n" },
    cfg.hmacSecret,
  );
  const res = await createHandler(broken, { now: () => NOW })(
    postToken({ challenge }),
  );
  assertEquals(res.status, 500);
});
