import type { Config } from "./config.ts";
import { discoveryDocument, jwksDocument } from "./token.ts";

export interface HandlerOptions {
  /** Injectable clock (unix seconds) for tests. */
  now?: () => number;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** Build the sshid HTTP handler over a loaded Config. */
export function createHandler(
  cfg: Config,
  _opts: HandlerOptions = {},
): (req: Request) => Promise<Response> {
  return (req: Request): Promise<Response> => {
    const url = new URL(req.url);

    if (
      req.method === "GET" &&
      url.pathname === "/.well-known/openid-configuration"
    ) {
      return Promise.resolve(json(discoveryDocument(cfg.issuer)));
    }
    if (req.method === "GET" && url.pathname === "/.well-known/jwks.json") {
      return Promise.resolve(json(jwksDocument([cfg.signingKey])));
    }
    return Promise.resolve(json({ error: "not_found" }, 404));
  };
}
