# Harness identity: MCP connector OAuth as a credential channel

A coding agent has no way to prove what it is. GitHub Actions hands every job an
OIDC ID Token; a Claude harness gets nothing equivalent, because the platform
has no workload identity federation. The obvious fallback — a long-lived secret
in the environment — is the thing worth avoiding: anything in the environment is
reachable by the model, by every tool it runs, and by every log it writes.

But the platform does have one credential channel from which the model is
structurally excluded. An MCP connector authorizes over OAuth; the platform
stores the resulting access token and attaches it to each MCP request itself.
The token never enters the context window and never lands in the environment.

## Decision

popoidc grows an OAuth authorization server and an MCP server, and uses the
connector token store as the vault for an HMAC-mode Shared Secret (ADR-0003).

1. `GET /oauth/authorize` generates a fresh 1024-bit secret, seals it into the
   authorization code, and redirects immediately — no login screen, no consent
   screen.
2. `POST /oauth/token` returns that secret as **both** the access token and the
   refresh token. Refresh returns it unchanged.
3. `POST /mcp/<namespace>` exposes two tools. `get_harness_identity` reports the
   `sub`, `iss` and namespace; `create_harness_id_token` mints a Token for a
   requested `aud`. Both derive a per-namespace secret from the access token and
   redeem it through the existing HMAC-mode grant.

The identity is **ephemeral and unowned**: reconnecting produces a new one. It
belongs to the **harness**, not to an agent session — every agent on that
connector shares it.

## Why these choices

- **No screen, and no account.** Authorization grants a freshly generated,
  previously unowned identity. It gives access to nothing that already existed.
  That single property collapses the OAuth attack surface: CSRF, code
  interception, mix-up and confused-deputy all degrade to "the attacker obtains
  their own new identity", which they could get by visiting `/oauth/authorize`
  themselves. It is also why accepting any `client_id` is safe here and would
  not be in a normal authorization server.
- **The access token is the raw secret.** Nothing is bound to it — no audience,
  no expiry — because any change to the string changes the identity it names.
  Constraints and identity are welded together by construction. Unwelding them
  (a sealed wrapper carrying an audience allowlist and an expiry) was considered
  and rejected as maintenance the use case does not yet justify.
- **The namespace lives in the URL path, never in a tool argument.** A connector
  URL is fixed by a human; a tool argument is chosen by the model. Namespaces
  are not a privilege boundary — anyone holding the token can reach any of them
  — so a model-chosen namespace would let a prompt-injected agent select which
  identity to act as.
- **The `sub` stays opaque.** The namespace is mixed into the secret _before_
  the existing grant is called, so the Secret Fingerprint derivation never
  learns that namespaces exist, and the MCP layer stays a thin wrapper over
  token machinery that already shipped. A labelled `sub` (`AGENT:ns1:…`) would
  read better in a trust policy; it was rejected as surface the wrapper does not
  need.
- **CIMD for redirect validation.** With no registration there are no
  pre-registered redirect URIs, and an unvalidated `redirect_uri` would make
  popoidc an open redirector — damage borne by third parties, whom the "nothing
  to steal" argument does not protect. Client ID Metadata Documents (MCP
  2026-07-28) supply the registered values statelessly: fetch the `client_id`
  URL, read its `redirect_uris`. No per-client configuration, and the public
  instance stays public.
- **One issuer.** The OAuth authorization server role and the token issuer role
  share `POPOIDC_ISSUER` and one merged metadata document. A separate issuer for
  the OAuth role was considered; it would have reached into `config.ts` and the
  minting path for no benefit the merged document does not already give.

## Consequences

- **A commit per reconnection.** A trust policy naming a harness identity must
  be updated whenever the connector re-authorizes. Accepted: for GitHub this is
  one API call, and `get_harness_identity` exists so the agent can report its
  own `sub`.
- **Prompt injection can mint.** The model cannot read the secret, but it can
  call the mint tool and exfiltrate the result. What the connector channel buys
  is narrower than it first appears: no durable credential in context,
  environment or logs — a leaked transcript holds at most a 15-minute Token —
  and disconnect revokes everything. It is not "the model cannot act as this
  identity".
- **Deliberate deviations from OAuth 2.1 / MCP 2026-07-28.** Access tokens do
  not expire (**SHOULD** issue short-lived). Refresh tokens do not rotate
  (**MUST** for public clients). Authorization codes are not single-use, since
  statelessness forbids it — replay yields the same secret, so there is nothing
  to gain. The MCP server cannot validate that a presented access token was
  issued for it, because a raw secret carries no audience; it is accepted only
  at this server, so the property holds in fact if not in form.
- **Every harness owns two identities.** The access token is itself a valid
  HMAC-mode secret, so its holder can call `POST /token` directly and obtain the
  un-namespaced fingerprint as well. Different values, different policies, no
  overlap — but it should be known rather than discovered.
- **The `id_token` is narrower than hoped.** It is returned only for the
  `openid` scope, and its `aud` is the `client_id`, so no relying party will
  accept it. It was expected to double as a way for the platform to display the
  identity; testing showed Claude does not surface it. It stays because it is
  what makes the merged metadata document honest, and for nothing else.
