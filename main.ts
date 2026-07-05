import { loadConfig } from "./src/config.ts";
import { createHandler } from "./src/handler.ts";

if (import.meta.main) {
  const cfg = await loadConfig();
  const port = Number(Deno.env.get("PORT") ?? "8000");
  Deno.serve({ port, hostname: "0.0.0.0" }, createHandler(cfg));
}
