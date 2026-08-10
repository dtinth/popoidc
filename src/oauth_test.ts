import { assert, assertEquals } from "@std/assert";
import { decodeJwt } from "jose";
import { handleAuthorize, handleOAuthToken, pkceChallenge } from "./oauth.ts";
import { harnessSecret } from "./harness.ts";
import { secretFingerprint } from "./hmacid.ts";
import { testConfig } from "./testutil.ts";

const NOW = 1_700_000_000;
const CLIENT_ID = "https://app.example.com/oauth/client.json";
const REDIRECT = "https://app.example.com/callback";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/** Serves a Client ID Metadata Document naming REDIRECT. */
const fetcher = () =>
  Promise.resolve(
    new Response(JSON.stringify({
      client_id: CLIENT_ID,
      client_name: "Example",
      redirect_uris: [REDIRECT],
    })),
  );

function authorizeUrl(overrides: Record<string, string> = {}): URL {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    code_challenge: pkceChallenge(VERIFIER),
    code_challenge_method: "S256",
    state: "st4te",
    ...overrides,
  });
  return new URL(`https://popoidc.test/oauth/authorize?${params}`);
}

/** Run the authorize step and return the issued code. */
async function getCode(
  cfg: Awaited<ReturnType<typeof testConfig>>,
  overrides: Record<string, string> = {},
): Promise<string> {
  const res = await handleAuthorize(
    cfg,
    authorizeUrl(overrides),
    () => NOW,
    fetcher,
  );
  assertEquals(res.status, 302);
  const location = new URL(res.headers.get("location")!);
  const code = location.searchParams.get("code");
  assert(code, `expected a code, got ${location.search}`);
  return code;
}

function tokenBody(fields: Record<string, string>): URLSearchParams {
  return new URLSearchParams({
    grant_type: "authorization_code",
    redirect_uri: REDIRECT,
    client_id: CLIENT_ID,
    code_verifier: VERIFIER,
    ...fields,
  });
}

Deno.test("pkceChallenge matches the RFC 7636 test vector", () => {
  assertEquals(
    pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  );
});

Deno.test("authorize redirects at once with a code, the state, and iss", async () => {
  const cfg = await testConfig();
  const res = await handleAuthorize(cfg, authorizeUrl(), () => NOW, fetcher);
  assertEquals(res.status, 302);
  assertEquals(res.headers.get("cache-control"), "no-store");
  const location = new URL(res.headers.get("location")!);
  assertEquals(location.origin + location.pathname, REDIRECT);
  assert(location.searchParams.get("code"));
  assertEquals(location.searchParams.get("state"), "st4te");
  assertEquals(location.searchParams.get("iss"), cfg.issuer); // RFC 9207
});

Deno.test("authorize is disabled when hmac mode is off", async () => {
  const cfg = await testConfig({ hmacIdentitySecret: undefined });
  const res = await handleAuthorize(cfg, authorizeUrl(), () => NOW, fetcher);
  assertEquals(res.status, 501);
});

Deno.test("authorize requires client_id and redirect_uri", async () => {
  const cfg = await testConfig();
  const url = new URL(
    "https://popoidc.test/oauth/authorize?response_type=code",
  );
  assertEquals(
    (await handleAuthorize(cfg, url, () => NOW, fetcher)).status,
    400,
  );
});

Deno.test("authorize refuses a redirect_uri the client did not register", async () => {
  const cfg = await testConfig();
  const res = await handleAuthorize(
    cfg,
    authorizeUrl({ redirect_uri: "https://evil.example/callback" }),
    () => NOW,
    fetcher,
  );
  assertEquals(res.status, 400); // never redirected — that is the whole point
  assertEquals((await res.json()).error, "invalid_request");
});

Deno.test("authorize refuses an unfetchable client document", async () => {
  const cfg = await testConfig();
  const res = await handleAuthorize(
    cfg,
    authorizeUrl(),
    () => NOW,
    () => Promise.resolve(new Response("nope", { status: 404 })),
  );
  assertEquals(res.status, 400);
  assertEquals((await res.json()).error, "invalid_client");
});

Deno.test("authorize sends protocol errors back to the validated client", async () => {
  const cfg = await testConfig();
  for (
    const [overrides, expected] of [
      [{ response_type: "token" }, "unsupported_response_type"],
      [{ code_challenge: "" }, "invalid_request"],
      [{ code_challenge_method: "plain" }, "invalid_request"],
    ] as const
  ) {
    const res = await handleAuthorize(
      cfg,
      authorizeUrl(overrides),
      () => NOW,
      fetcher,
    );
    assertEquals(res.status, 302);
    const location = new URL(res.headers.get("location")!);
    assertEquals(location.searchParams.get("error"), expected);
    assertEquals(location.searchParams.get("state"), "st4te");
    assertEquals(location.searchParams.get("iss"), cfg.issuer);
  }
});

Deno.test("token exchanges a code for the secret as access and refresh token", async () => {
  const cfg = await testConfig();
  const code = await getCode(cfg);
  const res = await handleOAuthToken(cfg, tokenBody({ code }), () => NOW);
  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.token_type, "Bearer");
  assertEquals(body.access_token, body.refresh_token);
  assertEquals(body.access_token.length, 256); // 1024 bits, hex
  assertEquals(body.id_token, undefined); // no openid scope was requested
  assertEquals(body.expires_in, undefined); // it does not expire
});

Deno.test("token rejects a bad verifier, redirect_uri, client_id, or code", async () => {
  const cfg = await testConfig();
  const code = await getCode(cfg);
  const cases: [Record<string, string>, number, string][] = [
    [{ code, code_verifier: "wrong" }, 400, "invalid_grant"],
    [
      { code, redirect_uri: "https://elsewhere.example/cb" },
      400,
      "invalid_grant",
    ],
    [
      { code, client_id: "https://other.example/c.json" },
      401,
      "invalid_client",
    ],
    [{ code: "not-a-code" }, 400, "invalid_grant"],
  ];
  for (const [fields, status, error] of cases) {
    const res = await handleOAuthToken(cfg, tokenBody(fields), () => NOW);
    assertEquals(res.status, status);
    assertEquals((await res.json()).error, error);
  }
});

Deno.test("token rejects an expired code", async () => {
  const cfg = await testConfig();
  const code = await getCode(cfg);
  const res = await handleOAuthToken(cfg, tokenBody({ code }), () => NOW + 120);
  assertEquals(res.status, 400);
  assertEquals((await res.json()).error, "invalid_grant");
});

Deno.test("token rejects a missing code or an unknown grant type", async () => {
  const cfg = await testConfig();
  assertEquals(
    (await handleOAuthToken(cfg, tokenBody({}), () => NOW)).status,
    400,
  );
  const res = await handleOAuthToken(
    cfg,
    new URLSearchParams({ grant_type: "password" }),
    () => NOW,
  );
  assertEquals((await res.json()).error, "unsupported_grant_type");
});

Deno.test("refresh returns the same secret, unchanged", async () => {
  const cfg = await testConfig();
  const res = await handleOAuthToken(
    cfg,
    new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: "s3cr3t",
    }),
    () => NOW,
  );
  const body = await res.json();
  assertEquals(body.access_token, "s3cr3t");
  assertEquals(body.refresh_token, "s3cr3t");
});

Deno.test("refresh requires a refresh_token", async () => {
  const cfg = await testConfig();
  const res = await handleOAuthToken(
    cfg,
    new URLSearchParams({ grant_type: "refresh_token" }),
    () => NOW,
  );
  assertEquals(res.status, 400);
});

Deno.test("the openid scope yields an id_token named by the resource namespace", async () => {
  const cfg = await testConfig();
  const code = await getCode(cfg, {
    scope: "openid",
    nonce: "n-0S6_WzA2Mj",
    resource: "https://popoidc.test/mcp/ns1",
  });
  const res = await handleOAuthToken(
    cfg,
    tokenBody({ code, resource: "https://popoidc.test/mcp/ns1" }),
    () => NOW,
  );
  const body = await res.json();
  assertEquals(body.scope, "openid");

  const claims = decodeJwt(body.id_token);
  assertEquals(claims.iss, cfg.issuer);
  assertEquals(claims.aud, CLIENT_ID); // a login assertion, not a workload token
  assertEquals(claims.nonce, "n-0S6_WzA2Mj");
  assertEquals(
    claims.sub,
    secretFingerprint(
      harnessSecret(body.access_token, "ns1"),
      cfg.hmacIdentitySecret!,
    ),
  );
});

Deno.test("without a resource the id_token names the bare namespace", async () => {
  const cfg = await testConfig();
  const code = await getCode(cfg, { scope: "openid" });
  const res = await handleOAuthToken(cfg, tokenBody({ code }), () => NOW);
  const body = await res.json();
  assertEquals(
    decodeJwt(body.id_token).sub,
    secretFingerprint(
      harnessSecret(body.access_token, null),
      cfg.hmacIdentitySecret!,
    ),
  );
});

Deno.test("a non-CIMD client_id may only use loopback redirects", async () => {
  const cfg = await testConfig();
  const ok = await handleAuthorize(
    cfg,
    authorizeUrl({
      client_id: "local-client",
      redirect_uri: "http://127.0.0.1:3000/callback",
    }),
    () => NOW,
    fetcher,
  );
  assertEquals(ok.status, 302);

  const denied = await handleAuthorize(
    cfg,
    authorizeUrl({
      client_id: "local-client",
      redirect_uri: "https://app.example.com/callback",
    }),
    () => NOW,
    fetcher,
  );
  assertEquals(denied.status, 400);
});
