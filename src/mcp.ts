// The MCP server exposing harness identity (ADR-0004).
//
// The access token arriving in the Authorization header IS an HMAC-mode Shared
// Secret. The platform holds it and attaches it; the model never reads it. These
// tools mix the namespace into it and redeem it through the ordinary grant.

import type { Config } from "./config.ts";
import { harnessSecret, mcpPath, type Namespace } from "./harness.ts";
import { hmacIdentity } from "./hmacid.ts";
import { mintToken } from "./token.ts";

/** The MCP revision this server speaks. */
export const MCP_PROTOCOL_VERSION = "2026-07-28";

const TOOLS = [
  {
    name: "get_harness_identity",
    title: "Get harness identity",
    description:
      "Report this harness's identity at the popoidc issuer: the `sub` that a " +
      "relying party's trust policy must name, the issuer, and the namespace. " +
      "The identity changes whenever the connector is authorized again.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "create_harness_id_token",
    title: "Create harness ID token",
    description:
      "Mint a short-lived RS256 ID Token that proves this harness's identity to " +
      "one relying party. The token lives 15 minutes.",
    inputSchema: {
      type: "object",
      properties: {
        aud: {
          type: "string",
          description:
            "The relying party the token is for, e.g. `octo-sts.dev`. Required: " +
            "a token minted for the wrong audience is worse than an error.",
        },
      },
      required: ["aud"],
      additionalProperties: false,
    },
  },
];

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

type RpcId = string | number | null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}

function rpcResult(id: RpcId, result: unknown): Response {
  return json({ jsonrpc: "2.0", id, result });
}

function rpcError(id: RpcId, code: number, message: string): Response {
  return json({ jsonrpc: "2.0", id, error: { code, message } });
}

/** A tool result: MCP carries these as content blocks, not as JSON-RPC errors. */
function toolText(text: string, isError = false) {
  return { content: [{ type: "text", text }], isError };
}

/**
 * The 401 that starts the OAuth flow. `resource_metadata` points at this exact
 * namespace's document, so the `resource` the client then sends names the right one.
 */
export function unauthorized(cfg: Config, namespace: Namespace): Response {
  const metadata = `${cfg.issuer}/.well-known/oauth-protected-resource${
    mcpPath(namespace)
  }`;
  return new Response(
    JSON.stringify({ error: "invalid_token" }),
    {
      status: 401,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
        "www-authenticate":
          `Bearer resource_metadata="${metadata}", scope="openid"`,
      },
    },
  );
}

function bearerToken(authorization: string | null): string | null {
  if (!authorization) return null;
  const match = /^Bearer\s+(\S+)$/i.exec(authorization.trim());
  return match ? match[1] : null;
}

/** POST /mcp[/namespace] — one JSON-RPC message per request; this server is stateless. */
export async function handleMcp(
  cfg: Config,
  bodyText: string,
  authorization: string | null,
  namespace: Namespace,
  now: () => number,
): Promise<Response> {
  if (!cfg.hmacIdentitySecret) {
    return json({ error: "hmac mode is not enabled on this issuer" }, 501);
  }

  let message: JsonRpcRequest;
  try {
    message = JSON.parse(bodyText);
  } catch {
    return rpcError(null, -32700, "parse error");
  }
  if (Array.isArray(message) || typeof message !== "object" || !message) {
    return rpcError(null, -32600, "invalid request");
  }

  const id = message.id ?? null;
  const isNotification = message.id === undefined;

  // `initialize` must work before a token exists, so a client can discover the
  // server. Everything that touches an identity needs the bearer token.
  const token = bearerToken(authorization);
  if (!token && message.method !== "initialize") {
    return unauthorized(cfg, namespace);
  }

  switch (message.method) {
    case "initialize":
      return rpcResult(id, {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: "popoidc", title: "popoidc harness identity" },
      });

    case "ping":
      return rpcResult(id, {});

    case "tools/list":
      return rpcResult(id, { tools: TOOLS });

    case "tools/call":
      return await callTool(
        cfg,
        message.params ?? {},
        token!,
        namespace,
        id,
        now,
      );

    default:
      if (isNotification) return new Response(null, { status: 202 });
      return rpcError(id, -32601, `method not found: ${message.method}`);
  }
}

async function callTool(
  cfg: Config,
  params: Record<string, unknown>,
  token: string,
  namespace: Namespace,
  id: RpcId,
  now: () => number,
): Promise<Response> {
  const name = params.name;
  const args = (params.arguments ?? {}) as Record<string, unknown>;
  const secret = harnessSecret(token, namespace);
  const identity = hmacIdentity(secret, cfg.hmacIdentitySecret!);

  if (name === "get_harness_identity") {
    return rpcResult(
      id,
      toolText(
        JSON.stringify({
          sub: identity.sub,
          iss: cfg.issuer,
          namespace,
        }),
      ),
    );
  }

  if (name === "create_harness_id_token") {
    const aud = args.aud;
    if (typeof aud !== "string" || aud === "") {
      return rpcResult(
        id,
        toolText("aud is required and must be a string", true),
      );
    }
    const jwt = await mintToken({
      issuer: cfg.issuer,
      subject: identity.sub,
      audience: aud,
      key: identity.key,
      keyType: identity.keyType,
      signingKey: cfg.signingKey,
      nowSeconds: now(),
    });
    return rpcResult(id, toolText(jwt));
  }

  return rpcError(id, -32602, `unknown tool: ${String(name)}`);
}
