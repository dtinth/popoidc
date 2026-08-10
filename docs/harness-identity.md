# Harness identity over MCP

How a coding agent gets a popoidc Identity without ever holding a secret in its
environment. The decision and its reasoning live in
[ADR-0004](./adr/0004-harness-identity-over-mcp.md); this document is the
protocol reference.

## Shape

The Claude platform stores an MCP connector's OAuth access token and attaches it
to every MCP request itself. The token never reaches the context window and
never reaches the environment. popoidc uses that store as a vault: the access
token **is** an HMAC-mode Shared Secret (ADR-0003), and the tools redeem it for
Tokens.

```
browser ──► GET  /oauth/authorize   generate secret, seal into code, redirect
platform ─► POST /oauth/token       code → access_token (= the secret)
agent ────► POST /mcp/<ns>          tools/call → a 15-minute RS256 Token
```

Authorization mints a **new, unowned** identity every time. Reconnecting changes
it. The identity belongs to the harness, not to an agent session: every agent on
that connector shares one `sub`.

## Endpoints

| Method | Path                                               | Purpose                                      |
| ------ | -------------------------------------------------- | -------------------------------------------- |
| GET    | `/oauth/authorize`                                 | Mint a secret, seal it into a code, redirect |
| POST   | `/oauth/token`                                     | `authorization_code` and `refresh_token`     |
| POST   | `/mcp`, `/mcp/<namespace>`                         | MCP JSON-RPC; `401` when unauthenticated     |
| GET    | `/.well-known/oauth-protected-resource/mcp[/<ns>]` | Protected Resource Metadata (RFC 9728)       |
| GET    | `/.well-known/oauth-authorization-server`          | The merged metadata document                 |
| GET    | `/.well-known/openid-configuration`                | The same document, at the OIDC path          |

The issuer never changes. `POPOIDC_ISSUER` names the token issuer _and_ the
authorization server, and one document describes both roles. Three identifiers
are involved and they are independent:

| Name      | Value                             | Where it appears                             |
| --------- | --------------------------------- | -------------------------------------------- |
| Issuer    | `https://popoidc.example`         | `iss`; `issuer`; PRM `authorization_servers` |
| Resource  | `https://popoidc.example/mcp/ns1` | RFC 8707 `resource`; PRM `resource`          |
| Namespace | `ns1`                             | the URL path; mixed into the secret          |

## Namespaces

A namespace is a path segment matching `[a-z0-9_-]{1,64}`, compared exactly — no
case folding, no normalization. Bare `/mcp` is a distinct namespace from every
named one, not the empty string.

Its purpose is rotation without re-authorization: change the configured
connector URL and the `sub` changes at once. It is **not** a privilege boundary
— anyone holding the access token can reach every namespace — which is why it
lives in the URL, where a human sets it, and never in a tool argument, where the
model would.

The MCP layer derives the per-namespace secret before calling the existing
grant, so the Secret Fingerprint derivation never learns that namespaces exist:

```
harness_secret = base64url(HMAC-SHA256(key = access_token,
                                       msg = "popoidc/mcp-ns/v1\n" + namespace))
```

That value is sent to `POST /token` as `secret`, exactly as any other HMAC-mode
caller would. The resulting `sub` is an ordinary opaque `HMAC-SHA256:…`
fingerprint.

## Authorization code

popoidc stores nothing, so the code carries the state. It is a ChaCha20-Poly1305
sealed box, base64url encoded, holding:

- the generated secret
- the PKCE `code_challenge`
- the `nonce`, when the authorize request supplied one
- the `client_id` and the `redirect_uri`
- an expiry, 60 seconds out — the same window as `MAX_AGE_SECONDS`

The sealing key is a domain-separated subkey of `POPOIDC_HMAC_SECRET`, so HMAC
mode needs no new configuration. Rotating that secret invalidates only codes in
flight, matching the challenge MAC's rotation semantics.
`POPOIDC_HMAC_IDENTITY_SECRET` is never used here — it names identities and must
never change.

`code_verifier` is verified against the sealed challenge (`S256` only). Codes
are **not** single-use; statelessness forbids it. Redeeming one twice returns
the same secret, hence the same identity, so nothing is gained by replay.

## Client registration

Only Client ID Metadata Documents. The `client_id` is an HTTPS URL with a path;
popoidc fetches it, requires `client_id` in the document to equal the URL, and
requires the presented `redirect_uri` to appear in its `redirect_uris`.

This exists to stop popoidc becoming an open redirector. The identities have
nothing to steal, but an unvalidated redirect on a trusted domain is a tool for
attacking other people. Fetches refuse redirects, time out, cap the response
size, and reject hostnames that are literally loopback, link-local or
private-range. A hostname that merely _resolves_ to one still gets through:
closing that needs resolution before connection, and DNS rebinding defeats it
anyway. The residual risk is accepted.

When `client_id` is not an HTTPS URL, only `localhost` and `127.0.0.1` redirect
URIs are permitted.

## The id_token

Returned from `/oauth/token` only when the request `scope` contains `openid`.
Its `aud` is the `client_id` — it is a login assertion to the client, not a
workload token, and no relying party will accept it. `sub` uses the namespace
parsed from the RFC 8707 `resource` parameter, so it names the identity the
tools will actually return; without `resource` it falls back to the
un-namespaced one. Any `nonce` from the authorize request is copied in.

It exists to make the merged metadata document truthful. Nothing else consumes
it.

## Tools

### `get_harness_identity`

No arguments. Returns JSON:

```json
{ "sub": "HMAC-SHA256:…", "iss": "https://popoidc.example", "namespace": "ns1" }
```

Call it after each reconnection to learn the `sub` a trust policy must name.

### `create_harness_id_token`

| Argument | Type   | Required | Meaning                            |
| -------- | ------ | -------- | ---------------------------------- |
| `aud`    | string | yes      | the Relying Party the Token is for |

Returns the JWT as text. There is no default `aud`: a wrong audience is worse
than an error. Tokens live 15 minutes; a long task calls the tool again.

## What this does and does not protect

It **does** keep any durable credential out of the context window, the
environment and the logs. A leaked transcript holds at most a 15-minute Token.
Disconnecting the connector revokes everything at once.

It **does not** stop a prompt-injected agent from calling
`create_harness_id_token` and exfiltrating the result. The model cannot read the
secret, but it can use it for as long as the session lasts.

## Deliberate deviations

- Access tokens never expire (OAuth 2.1: **SHOULD** be short-lived).
- Refresh tokens do not rotate (**MUST** for public clients).
- Authorization codes are not single-use.
- The MCP server cannot check that a presented access token was issued for it —
  a raw secret carries no audience. It is accepted nowhere else, so the property
  holds in fact.
