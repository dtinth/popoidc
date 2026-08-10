import { assert, assertEquals } from "@std/assert";
import { createHandler } from "./handler.ts";
import { MCP_PROTOCOL_VERSION } from "./mcp.ts";
import { harnessSecret } from "./harness.ts";
import { secretFingerprint } from "./hmacid.ts";
import { testConfig } from "./testutil.ts";

const NOW = 1_700_000_000;
const TOKEN = "an-access-token-that-is-really-a-shared-secret";

function rpc(
  method: string,
  params?: Record<string, unknown>,
  opts: { path?: string; token?: string | null; id?: unknown } = {},
): Request {
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  const token = opts.token === undefined ? TOKEN : opts.token;
  if (token) headers.authorization = `Bearer ${token}`;
  const body: Record<string, unknown> = { jsonrpc: "2.0", method };
  if (params) body.params = params;
  if (!("id" in opts)) body.id = 1;
  else if (opts.id !== undefined) body.id = opts.id;
  return new Request(`https://popoidc.test${opts.path ?? "/mcp"}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

async function call(
  req: Request,
  cfg?: Awaited<ReturnType<typeof testConfig>>,
): Promise<Response> {
  return await createHandler(cfg ?? await testConfig(), { now: () => NOW })(
    req,
  );
}

/** The text of the single content block a tool result carries. */
async function toolText(res: Response): Promise<string> {
  const body = await res.json();
  assertEquals(body.result.isError, false);
  return body.result.content[0].text;
}

Deno.test("/mcp answers 401 and points at its own resource metadata", async () => {
  const res = await call(rpc("tools/list", undefined, { token: null }));
  assertEquals(res.status, 401);
  assertEquals(
    res.headers.get("www-authenticate"),
    'Bearer resource_metadata="https://popoidc.test/.well-known/oauth-protected-resource/mcp", scope="openid"',
  );
});

Deno.test("a namespaced endpoint points at its own metadata document", async () => {
  const res = await call(
    rpc("tools/list", undefined, { path: "/mcp/ns1", token: null }),
  );
  assertEquals(res.status, 401);
  assert(
    res.headers.get("www-authenticate")!.includes(
      "/.well-known/oauth-protected-resource/mcp/ns1",
    ),
  );
});

Deno.test("initialize works before a token exists", async () => {
  const res = await call(rpc("initialize", {}, { token: null }));
  assertEquals(res.status, 200);
  const { result } = await res.json();
  assertEquals(result.protocolVersion, MCP_PROTOCOL_VERSION);
  assertEquals(result.capabilities.tools, {});
  assertEquals(result.serverInfo.name, "popoidc");
});

Deno.test("tools/list offers exactly the two harness tools", async () => {
  const { result } = await (await call(rpc("tools/list"))).json();
  assertEquals(result.tools.map((t: { name: string }) => t.name), [
    "get_harness_identity",
    "create_harness_id_token",
  ]);
  assertEquals(result.tools[1].inputSchema.required, ["aud"]);
});

Deno.test("get_harness_identity reports the sub a trust policy must name", async () => {
  const cfg = await testConfig();
  const res = await call(
    rpc("tools/call", { name: "get_harness_identity", arguments: {} }, {
      path: "/mcp/ns1",
    }),
    cfg,
  );
  assertEquals(
    JSON.parse(await toolText(res)),
    {
      sub: secretFingerprint(
        harnessSecret(TOKEN, "ns1"),
        cfg.hmacIdentitySecret!,
      ),
      iss: cfg.issuer,
      namespace: "ns1",
    },
  );
});

Deno.test("the same token names different identities per namespace", async () => {
  const cfg = await testConfig();
  const subOf = async (path: string) =>
    JSON.parse(
      await toolText(
        await call(
          rpc("tools/call", { name: "get_harness_identity" }, { path }),
          cfg,
        ),
      ),
    ).sub;

  const bare = await subOf("/mcp");
  const ns1 = await subOf("/mcp/ns1");
  const ns2 = await subOf("/mcp/ns2");
  assertEquals(new Set([bare, ns1, ns2]).size, 3);
});

Deno.test("create_harness_id_token requires an aud", async () => {
  const res = await call(
    rpc("tools/call", { name: "create_harness_id_token", arguments: {} }),
  );
  const { result } = await res.json();
  assertEquals(result.isError, true);
  assert(result.content[0].text.includes("aud is required"));
});

Deno.test("a malformed Authorization header is treated as no token at all", async () => {
  const res = await call(
    new Request("https://popoidc.test/mcp", {
      method: "POST",
      headers: { authorization: "Basic dXNlcjpwYXNz" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }),
  );
  assertEquals(res.status, 401);
});

Deno.test("an unknown tool and an unknown method are JSON-RPC errors", async () => {
  const unknownTool = await (await call(
    rpc("tools/call", { name: "nope" }),
  )).json();
  assertEquals(unknownTool.error.code, -32602);

  const noParams = await (await call(rpc("tools/call"))).json();
  assertEquals(noParams.error.code, -32602);

  const unknownMethod = await (await call(rpc("resources/list"))).json();
  assertEquals(unknownMethod.error.code, -32601);
});

Deno.test("a notification gets 202 and no body", async () => {
  const res = await call(
    rpc("notifications/initialized", {}, { id: undefined }),
  );
  assertEquals(res.status, 202);
  assertEquals(await res.text(), "");
});

Deno.test("ping answers empty", async () => {
  const { result } = await (await call(rpc("ping"))).json();
  assertEquals(result, {});
});

Deno.test("malformed JSON-RPC input is reported as such", async () => {
  const bad = await createHandler(await testConfig(), { now: () => NOW })(
    new Request("https://popoidc.test/mcp", {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}` },
      body: "{not json",
    }),
  );
  assertEquals((await bad.json()).error.code, -32700);

  const batched = await createHandler(await testConfig(), { now: () => NOW })(
    new Request("https://popoidc.test/mcp", {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}` },
      body: "[]",
    }),
  );
  assertEquals((await batched.json()).error.code, -32600);

  for (const body of ["5", "null"]) {
    const scalar = await createHandler(await testConfig(), { now: () => NOW })(
      new Request("https://popoidc.test/mcp", {
        method: "POST",
        headers: { authorization: `Bearer ${TOKEN}` },
        body,
      }),
    );
    assertEquals((await scalar.json()).error.code, -32600);
  }
});

Deno.test("/mcp accepts POST only, and rejects a malformed namespace", async () => {
  const get = await call(
    new Request("https://popoidc.test/mcp", { method: "GET" }),
  );
  assertEquals(get.status, 405);

  const bad = await call(rpc("tools/list", undefined, { path: "/mcp/NOPE" }));
  assertEquals(bad.status, 404);
});

Deno.test("/mcp is disabled when hmac mode is off", async () => {
  const res = await call(
    rpc("tools/list"),
    await testConfig({ hmacIdentitySecret: undefined }),
  );
  assertEquals(res.status, 501);
});
