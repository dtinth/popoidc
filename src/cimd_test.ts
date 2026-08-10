import { assert, assertEquals, assertRejects } from "@std/assert";
import {
  type ClientMetadata,
  fetchClientMetadata,
  isCimdClientId,
  isRedirectAllowed,
} from "./cimd.ts";

const CLIENT_ID = "https://app.example.com/oauth/client.json";

function jsonFetcher(body: unknown, init: ResponseInit = {}) {
  return () =>
    Promise.resolve(
      new Response(
        typeof body === "string" ? body : JSON.stringify(body),
        init,
      ),
    );
}

function validDoc(overrides: Partial<ClientMetadata> = {}) {
  return {
    client_id: CLIENT_ID,
    client_name: "Example Client",
    redirect_uris: ["https://app.example.com/callback"],
    ...overrides,
  };
}

Deno.test("isCimdClientId requires https, a path, and no fragment", () => {
  assert(isCimdClientId(CLIENT_ID));
  assert(!isCimdClientId("http://app.example.com/client.json"));
  assert(!isCimdClientId("https://app.example.com"));
  assert(!isCimdClientId("https://app.example.com/c.json#frag"));
  assert(!isCimdClientId("not-a-url"));
});

Deno.test("fetchClientMetadata returns a valid document", async () => {
  const doc = await fetchClientMetadata(CLIENT_ID, jsonFetcher(validDoc()));
  assertEquals(doc.redirect_uris, ["https://app.example.com/callback"]);
});

Deno.test("fetchClientMetadata refuses a non-CIMD client_id", async () => {
  await assertRejects(() =>
    fetchClientMetadata("public-client", jsonFetcher(validDoc()))
  );
});

Deno.test("fetchClientMetadata refuses SSRF targets by host", async () => {
  for (
    const host of [
      "localhost",
      "127.0.0.1",
      "10.0.0.5",
      "172.16.0.1",
      "192.168.1.1",
      "169.254.169.254",
      "metadata.internal",
      "[::1]",
      "[fe80::1]",
      "[fd00::1]",
    ]
  ) {
    await assertRejects(
      () => fetchClientMetadata(`https://${host}/c.json`, jsonFetcher({})),
      Error,
      "not reachable",
    );
  }
});

Deno.test("fetchClientMetadata allows a public address literal", async () => {
  const clientId = "https://93.184.216.34/c.json";
  const doc = await fetchClientMetadata(
    clientId,
    jsonFetcher({ ...validDoc(), client_id: clientId }),
  );
  assertEquals(doc.client_id, clientId);
});

Deno.test("fetchClientMetadata rejects a non-200 response", async () => {
  await assertRejects(() =>
    fetchClientMetadata(CLIENT_ID, jsonFetcher(validDoc(), { status: 404 }))
  );
});

Deno.test("fetchClientMetadata rejects an oversized document", async () => {
  await assertRejects(
    () =>
      fetchClientMetadata(
        CLIENT_ID,
        jsonFetcher(validDoc(), {
          headers: { "content-length": String(1024 * 1024) },
        }),
      ),
    Error,
    "too large",
  );
  await assertRejects(
    () => fetchClientMetadata(CLIENT_ID, jsonFetcher("x".repeat(70_000))),
    Error,
    "too large",
  );
});

Deno.test("fetchClientMetadata rejects malformed or mismatched documents", async () => {
  await assertRejects(() =>
    fetchClientMetadata(CLIENT_ID, jsonFetcher("{not json"))
  );
  await assertRejects(
    () =>
      fetchClientMetadata(
        CLIENT_ID,
        jsonFetcher(
          validDoc({ client_id: "https://elsewhere.example/c.json" }),
        ),
      ),
    Error,
    "does not match",
  );
  await assertRejects(
    () =>
      fetchClientMetadata(
        CLIENT_ID,
        jsonFetcher(validDoc({ redirect_uris: [] })),
      ),
    Error,
    "redirect_uris",
  );
  await assertRejects(
    () =>
      fetchClientMetadata(
        CLIENT_ID,
        jsonFetcher({ client_id: CLIENT_ID, redirect_uris: [42] }),
      ),
    Error,
    "redirect_uris",
  );
});

Deno.test("isRedirectAllowed matches the document's list exactly", () => {
  const doc = validDoc();
  assert(isRedirectAllowed("https://app.example.com/callback", doc));
  assert(!isRedirectAllowed("https://app.example.com/callback2", doc));
  assert(!isRedirectAllowed("https://evil.example/callback", doc));
});

Deno.test("isRedirectAllowed permits only loopback without a document", () => {
  assert(isRedirectAllowed("http://localhost:3000/callback", null));
  assert(isRedirectAllowed("http://127.0.0.1:3000/callback", null));
  assert(!isRedirectAllowed("https://evil.example/callback", null));
  assert(!isRedirectAllowed("not-a-url", null));
});
