import { assert, assertEquals, assertNotEquals } from "@std/assert";
import {
  harnessSecret,
  mcpPath,
  namespaceFromResource,
  parseMcpPath,
} from "./harness.ts";

Deno.test("parseMcpPath accepts the bare endpoint and a valid namespace", () => {
  assertEquals(parseMcpPath("/mcp"), { namespace: null });
  assertEquals(parseMcpPath("/mcp/ns1"), { namespace: "ns1" });
  assertEquals(parseMcpPath("/mcp/a-b_c"), { namespace: "a-b_c" });
});

Deno.test("parseMcpPath rejects a malformed namespace without normalizing", () => {
  assertEquals(parseMcpPath("/mcp/"), undefined); // empty segment
  assertEquals(parseMcpPath("/mcp/NS1"), undefined); // no case folding
  assertEquals(parseMcpPath("/mcp/a/b"), undefined); // one segment only
  assertEquals(parseMcpPath("/mcp/oops!"), undefined);
  assertEquals(parseMcpPath("/mcp/" + "a".repeat(65)), undefined);
  assertEquals(parseMcpPath("/token"), undefined);
});

Deno.test("namespaceFromResource reads the namespace an MCP client asked for", () => {
  assertEquals(
    namespaceFromResource("https://popoidc.test/mcp/ns1"),
    "ns1",
  );
  assertEquals(namespaceFromResource("https://popoidc.test/mcp"), null);
  assertEquals(namespaceFromResource("https://popoidc.test/mcp/"), null);
});

Deno.test("namespaceFromResource falls back to the bare namespace", () => {
  assertEquals(namespaceFromResource(null), null);
  assertEquals(namespaceFromResource("not a url"), null);
  assertEquals(namespaceFromResource("https://popoidc.test/elsewhere"), null);
  assertEquals(namespaceFromResource("https://popoidc.test/"), null);
});

Deno.test("mcpPath is the inverse of parseMcpPath", () => {
  for (const namespace of [null, "ns1"]) {
    assertEquals(parseMcpPath(mcpPath(namespace)), { namespace });
  }
});

Deno.test("harnessSecret is deterministic and long enough for HMAC mode", () => {
  const a = harnessSecret("token", "ns1");
  assertEquals(a, harnessSecret("token", "ns1"));
  assert(a.length >= 16, "must satisfy MIN_SECRET_LENGTH");
});

Deno.test("harnessSecret separates namespaces, tokens, and the bare endpoint", () => {
  assertNotEquals(harnessSecret("token", "ns1"), harnessSecret("token", "ns2"));
  assertNotEquals(harnessSecret("token", "ns1"), harnessSecret("other", "ns1"));
  assertNotEquals(harnessSecret("token", null), harnessSecret("token", "bare"));
});
