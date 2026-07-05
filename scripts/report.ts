// Assemble the GitHub Pages report from CI outputs.
// Run after `deno test … | tee site/tests.txt` and `deno coverage … --html`.

const log = await Deno.readTextFile("site/tests.txt").catch(() =>
  "(no test log)"
);
const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const page = (title: string, body: string) =>
  `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
  body { font: 15px/1.6 system-ui, sans-serif; max-width: 62rem; margin: 2rem auto; padding: 0 1rem; }
  a { color: #2563eb; }
  pre { background: #0b1021; color: #e5e7eb; padding: 1rem; border-radius: 8px; overflow: auto; }
  h1 { margin-bottom: .25rem; }
</style></head><body>${body}</body></html>`;

await Deno.writeTextFile(
  "site/tests.html",
  page(
    "popoidc — test report",
    `<h1>popoidc — test report</h1>
<p><a href="./">← report home</a></p>
<pre>${esc(log)}</pre>`,
  ),
);

await Deno.writeTextFile(
  "site/index.html",
  page(
    "popoidc — CI report",
    `<h1>popoidc — CI report</h1>
<p>Proof-of-possession OIDC issuer. Reports from the latest <code>main</code> build.</p>
<ul>
  <li><a href="./coverage/">Coverage report</a></li>
  <li><a href="./tests.html">Test report</a></li>
</ul>
<p><a href="https://github.com/dtinth/popoidc">Source on GitHub</a></p>`,
  ),
);

console.log("built site/index.html and site/tests.html");
