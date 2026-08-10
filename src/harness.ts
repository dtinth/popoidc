import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { encodeBase64Url } from "@std/encoding/base64url";

const enc = new TextEncoder();

/** One namespace path segment, or `null` for the bare `/mcp` endpoint. */
export type Namespace = string | null;

/** Namespaces are compared exactly — no case folding, no normalization. */
const NAMESPACE_PATTERN = /^[a-z0-9_-]{1,64}$/;

/**
 * Match `/mcp` or `/mcp/<namespace>`. Returns `undefined` for anything else,
 * including a malformed namespace, so the caller falls through to its 404.
 */
export function parseMcpPath(
  pathname: string,
): { namespace: Namespace } | undefined {
  if (pathname === "/mcp") return { namespace: null };
  if (!pathname.startsWith("/mcp/")) return undefined;
  const ns = pathname.slice("/mcp/".length);
  if (!NAMESPACE_PATTERN.test(ns)) return undefined;
  return { namespace: ns };
}

/** The endpoint path a namespace lives at — the inverse of `parseMcpPath`. */
export function mcpPath(namespace: Namespace): string {
  return namespace === null ? "/mcp" : `/mcp/${namespace}`;
}

/**
 * The namespace an MCP client named in its RFC 8707 `resource` parameter. Used by
 * the OAuth token endpoint, which is shared across namespaces and would otherwise
 * have no idea which one this connector will talk to. Falls back to the bare
 * namespace when the parameter is missing or is not an MCP endpoint.
 */
export function namespaceFromResource(resource: string | null): Namespace {
  if (!resource) return null;
  let pathname: string;
  try {
    pathname = new URL(resource).pathname;
  } catch {
    return null;
  }
  return parseMcpPath(pathname.replace(/\/+$/, "") || "/")?.namespace ?? null;
}

/**
 * Derive the Shared Secret that an access token names inside a namespace.
 *
 * This is what keeps the MCP layer a thin wrapper: the namespace is mixed in
 * *here*, and the result is then redeemed through the ordinary HMAC-mode grant,
 * so the Secret Fingerprint derivation itself never learns that namespaces exist.
 *
 * `bare` and `ns:<name>` cannot collide, because a namespace can contain no colon.
 */
export function harnessSecret(
  accessToken: string,
  namespace: Namespace,
): string {
  const scope = namespace === null ? "bare" : `ns:${namespace}`;
  return encodeBase64Url(
    hmac(
      sha256,
      enc.encode(accessToken),
      enc.encode(`popoidc/mcp-ns/v1\n${scope}`),
    ),
  );
}
