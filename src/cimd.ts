// OAuth Client ID Metadata Documents (MCP 2026-07-28): the client_id is an HTTPS
// URL serving its own registration. It replaces Dynamic Client Registration and
// suits a stateless Issuer — there is nothing to store, only a URL to resolve.

/** The parts of a Client ID Metadata Document that popoidc uses. */
export interface ClientMetadata {
  client_id: string;
  client_name?: string;
  redirect_uris: string[];
}

/** Injectable so tests never touch the network. */
export type Fetcher = (url: string, init: RequestInit) => Promise<Response>;

const MAX_DOCUMENT_BYTES = 64 * 1024;
const FETCH_TIMEOUT_MS = 5000;

/**
 * Hostnames a metadata fetch must never reach. This blocks the obvious SSRF
 * targets — loopback, link-local and the private ranges — by literal inspection.
 * A hostname that *resolves* to one of these still gets through: closing that
 * needs resolution before connection, and DNS rebinding defeats it anyway. The
 * residual risk is accepted (see docs/harness-identity.md).
 */
function isBlockedHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h.endsWith(".internal") || h.endsWith(".local")) return true;
  if (h === "::1" || h === "::" || h.startsWith("fc") || h.startsWith("fd")) {
    return true;
  }
  if (h.startsWith("fe80:")) return true;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!v4) return false;
  const [a, b] = [Number(v4[1]), Number(v4[2])];
  if (a === 127 || a === 0 || a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

/** Is this `client_id` a Client ID Metadata Document URL? HTTPS, a path, no fragment. */
export function isCimdClientId(clientId: string): boolean {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return false;
  }
  return url.protocol === "https:" && url.pathname.length > 1 &&
    url.hash === "";
}

/**
 * Fetch and validate the document at a URL-shaped `client_id`. Throws on anything
 * that is not a well-formed document whose own `client_id` equals the URL exactly.
 */
export async function fetchClientMetadata(
  clientId: string,
  fetcher: Fetcher = fetch,
): Promise<ClientMetadata> {
  if (!isCimdClientId(clientId)) throw new Error("client_id is not a CIMD URL");
  if (isBlockedHost(new URL(clientId).hostname)) {
    throw new Error("client_id host is not reachable");
  }

  // No redirects: a redirect is how an allowed host hands the fetch to a blocked one.
  const res = await fetcher(clientId, {
    redirect: "error",
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`client metadata fetch failed: ${res.status}`);
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > MAX_DOCUMENT_BYTES) {
    throw new Error("client metadata document too large");
  }
  const body = await res.text();
  if (body.length > MAX_DOCUMENT_BYTES) {
    throw new Error("client metadata document too large");
  }

  let doc: ClientMetadata;
  try {
    doc = JSON.parse(body);
  } catch {
    throw new Error("client metadata is not valid JSON");
  }
  if (doc?.client_id !== clientId) {
    throw new Error("client metadata client_id does not match its URL");
  }
  if (
    !Array.isArray(doc.redirect_uris) || doc.redirect_uris.length === 0 ||
    !doc.redirect_uris.every((u) => typeof u === "string")
  ) {
    throw new Error("client metadata has no usable redirect_uris");
  }
  return doc;
}

/** Loopback redirect targets, the only ones allowed without a metadata document. */
function isLoopbackRedirect(redirectUri: string): boolean {
  let url: URL;
  try {
    url = new URL(redirectUri);
  } catch {
    return false;
  }
  return (url.protocol === "http:" || url.protocol === "https:") &&
    (url.hostname === "localhost" || url.hostname === "127.0.0.1" ||
      url.hostname === "[::1]");
}

/**
 * Decide whether popoidc may redirect a browser to `redirectUri`.
 *
 * The identities here are unowned, so a stolen code costs their holder nothing.
 * This check exists for everyone else: an unvalidated redirect would make popoidc
 * an open redirector on a trusted domain, which is a tool for attacking third
 * parties.
 */
export function isRedirectAllowed(
  redirectUri: string,
  metadata: ClientMetadata | null,
): boolean {
  if (metadata) return metadata.redirect_uris.includes(redirectUri);
  return isLoopbackRedirect(redirectUri);
}
