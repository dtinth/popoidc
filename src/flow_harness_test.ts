import { assert, assertEquals } from "@std/assert";
import { createLocalJWKSet, jwtVerify } from "jose";
import { createHandler } from "./handler.ts";
import { pkceChallenge } from "./oauth.ts";
import { testConfig } from "./testutil.ts";

const NOW = 1_700_000_000;
const CLIENT_ID = "https://claude.example/oauth/client.json";
const REDIRECT = "https://claude.example/callback";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

const fetcher = () =>
  Promise.resolve(
    new Response(JSON.stringify({
      client_id: CLIENT_ID,
      client_name: "Claude",
      redirect_uris: [REDIRECT],
    })),
  );

Deno.test("harness flow: authorize → token → tools/call → a verifiable Token", async () => {
  const cfg = await testConfig();
  const handler = createHandler(cfg, { now: () => NOW, fetcher });
  const resource = `${cfg.issuer}/mcp/devbox`;

  // 1. The connector authorizes. No screen: one redirect, carrying the code.
  const authorize = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    code_challenge: pkceChallenge(VERIFIER),
    code_challenge_method: "S256",
    scope: "openid",
    state: "xyz",
    resource,
  });
  const redirected = await handler(
    new Request(`https://popoidc.test/oauth/authorize?${authorize}`),
  );
  assertEquals(redirected.status, 302);
  const callback = new URL(redirected.headers.get("location")!);
  assertEquals(callback.searchParams.get("state"), "xyz");
  const code = callback.searchParams.get("code")!;

  // 2. The platform redeems it. The access token is the secret itself.
  const tokenRes = await handler(
    new Request("https://popoidc.test/oauth/token", {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        client_id: CLIENT_ID,
        code_verifier: VERIFIER,
        resource,
      }),
    }),
  );
  assertEquals(tokenRes.status, 200);
  const { access_token: accessToken, id_token: idToken } = await tokenRes
    .json();

  const rpc = (method: string, params?: Record<string, unknown>) =>
    handler(
      new Request(`https://popoidc.test/mcp/devbox`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${accessToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      }),
    );

  // 3. The agent asks who it is, then mints a Token for a relying party.
  const identity = JSON.parse(
    (await (await rpc("tools/call", { name: "get_harness_identity" })).json())
      .result.content[0].text,
  );
  assertEquals(identity.iss, cfg.issuer);
  assertEquals(identity.namespace, "devbox");

  const minted = await (await rpc("tools/call", {
    name: "create_harness_id_token",
    arguments: { aud: "octo-sts.dev" },
  })).json();
  const jwt = minted.result.content[0].text;

  // 4. A relying party verifies it with nothing but the published JWKS.
  const jwks = createLocalJWKSet(
    await (await handler(
      new Request("https://popoidc.test/.well-known/jwks.json"),
    )).json(),
  );
  const { payload } = await jwtVerify(jwt, jwks, {
    issuer: cfg.issuer,
    audience: "octo-sts.dev",
    currentDate: new Date((NOW + 1) * 1000),
  });
  assertEquals(payload.sub, identity.sub);
  assertEquals(payload.key_type, "hmac");

  // The id_token names the same identity, but only the client may consume it.
  const { payload: login } = await jwtVerify(idToken, jwks, {
    issuer: cfg.issuer,
    audience: CLIENT_ID,
    currentDate: new Date((NOW + 1) * 1000),
  });
  assertEquals(login.sub, identity.sub);
});

Deno.test("reconnecting produces a different identity", async () => {
  const cfg = await testConfig();
  const handler = createHandler(cfg, { now: () => NOW, fetcher });

  const connect = async () => {
    const authorize = new URLSearchParams({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT,
      code_challenge: pkceChallenge(VERIFIER),
      code_challenge_method: "S256",
    });
    const redirected = await handler(
      new Request(`https://popoidc.test/oauth/authorize?${authorize}`),
    );
    const code = new URL(redirected.headers.get("location")!).searchParams
      .get("code")!;
    const res = await handler(
      new Request("https://popoidc.test/oauth/token", {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT,
          client_id: CLIENT_ID,
          code_verifier: VERIFIER,
        }),
      }),
    );
    return (await res.json()).access_token;
  };

  const first = await connect();
  const second = await connect();
  assert(first !== second, "each authorization mints a new secret");
});

Deno.test("the metadata document is served at both well-known paths", async () => {
  const handler = createHandler(await testConfig(), { now: () => NOW });
  const oidc = await (await handler(
    new Request("https://popoidc.test/.well-known/openid-configuration"),
  )).json();
  const oauth = await (await handler(
    new Request("https://popoidc.test/.well-known/oauth-authorization-server"),
  )).json();

  assertEquals(oidc, oauth);
  // MCP clients MUST refuse an authorization server that does not advertise PKCE.
  assertEquals(oidc.code_challenge_methods_supported, ["S256"]);
  assertEquals(oidc.response_types_supported, ["code"]);
  assertEquals(oidc.client_id_metadata_document_supported, true);
  assertEquals(oidc.authorization_response_iss_parameter_supported, true);
  assertEquals(
    oidc.authorization_endpoint,
    "https://popoidc.test/oauth/authorize",
  );
  assertEquals(oidc.token_endpoint, "https://popoidc.test/oauth/token");
});

Deno.test("protected resource metadata names each endpoint exactly", async () => {
  const cfg = await testConfig();
  const handler = createHandler(cfg, { now: () => NOW });
  const prm = async (path: string) =>
    await (await handler(
      new Request(
        `https://popoidc.test/.well-known/oauth-protected-resource${path}`,
      ),
    )).json();

  assertEquals((await prm("/mcp")).resource, `${cfg.issuer}/mcp`);
  assertEquals((await prm("/mcp/ns1")).resource, `${cfg.issuer}/mcp/ns1`);
  assertEquals((await prm("/mcp")).authorization_servers, [cfg.issuer]);

  const missing = await handler(
    new Request(
      "https://popoidc.test/.well-known/oauth-protected-resource/elsewhere",
    ),
  );
  assertEquals(missing.status, 404);
});
