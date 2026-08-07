# popoidc

[![CI](https://github.com/dtinth/popoidc/actions/workflows/ci.yml/badge.svg)](https://github.com/dtinth/popoidc/actions/workflows/ci.yml)
[![Coverage & test report](https://img.shields.io/badge/report-gh--pages-2563eb)](https://dtinth.github.io/popoidc/)

A public, self-hosted **OIDC-compatible token issuer** that mints short-lived
JWTs asserting _only_ that the bearer controls a given key or secret — "GitHub
Actions OIDC, but the auth factor is a key you already own."

Prove possession of an `ssh-ed25519` key (by signing), a native `age`/X25519 key
(by decrypting), or a plain shared secret (by disclosing it — "HMAC mode"), and
receive an RS256 ID Token whose `sub` is that identity's fingerprint. Relying
parties verify it via standard OIDC discovery + JWKS and decide for themselves
whether that fingerprint is authorized — popoidc never asserts a human identity.

The design and the decisions behind it live in [CONTEXT.md](./CONTEXT.md) and
[docs/adr/](./docs/adr/).

## Public instance

A public instance runs at **<https://popoidc.spacet.me>**. Anyone may use it —
but it is provided as-is, with **no SLA and no uptime guarantee**. Set
`ISS=https://popoidc.spacet.me` in the examples below to try it, or self-host
your own (see [Deploy](#deploy)).

## Endpoints

| Method   | Path                                                         | Purpose                                          |
| -------- | ------------------------------------------------------------ | ------------------------------------------------ |
| GET      | `/`                                                          | Redirects to this README                         |
| GET      | `/.well-known/openid-configuration`                          | OIDC discovery (RS256)                           |
| GET      | `/.well-known/jwks.json`                                     | Public signing keys                              |
| GET/POST | `/challenge` — `key`, `aud`, optional `method=sign\|decrypt` | Issue a challenge                                |
| POST     | `/token`                                                     | Redeem a challenge + Proof of Possession → Token |
| POST     | `/token` — `secret`, `aud`                                   | HMAC mode: disclose a shared secret → Token      |

`/challenge` takes its params from the query string (`GET`) or a form-encoded
body (`POST` — keeps the key out of the URL / access logs).

`method` defaults to `sign` for SSH keys (works with `ssh-agent` and hardware
keys) and is forced to `decrypt` for age keys. SSH keys may also use `decrypt`
(on-disk keys only).

## Get a token (shell)

### Signing Proof (SSH key — works with agent/FIDO/on-disk)

```bash
ISS=https://popoidc.example
KEY="$(cat ~/.ssh/id_ed25519.pub)"
C=$(curl -sG "$ISS/challenge" --data-urlencode "key=$KEY" --data-urlencode "aud=octo-sts.dev")
SIG=$(printf %s "$C" | ssh-keygen -Y sign -n popoidc -f ~/.ssh/id_ed25519 2>/dev/null)
TOKEN=$(curl -s "$ISS/token" --data-urlencode "challenge=$C" --data-urlencode "signature=$SIG")
echo "$TOKEN"
```

### Decryption Proof (uniform — SSH _or_ age key, on-disk)

```bash
ISS=https://popoidc.example
KEY="$(cat ~/.ssh/id_ed25519.pub)"   # or an age1… recipient
TOKEN=$(curl -sG "$ISS/challenge" --data-urlencode "key=$KEY" --data-urlencode "aud=octo-sts.dev" --data-urlencode "method=decrypt" \
  | age -d -i ~/.ssh/id_ed25519 \
  | curl -s "$ISS/token" --data-urlencode "challenge@-")
echo "$TOKEN"
```

### Disclosure Proof (HMAC mode — a shared secret, no key at all)

Requires the Issuer to have `POPOIDC_HMAC_IDENTITY_SECRET` set (see
[Configuration](#configuration)); otherwise `/token` answers `501`.

```bash
ISS=https://popoidc.example
SECRET="$(cat ~/.config/popoidc/secret)"    # generate: openssl rand -base64 24
TOKEN=$(curl -s "$ISS/token" --data-urlencode "secret=$SECRET" --data-urlencode "aud=octo-sts.dev")
echo "$TOKEN"
```

One request, no challenge round-trip: the secret _is_ the proof, so binding it
to a server-issued challenge would add ceremony but no security. The `sub` is
`HMAC-SHA256:<base64>` — HMAC-SHA256 of your secret under a server-side pepper —
so it is stable for a given secret, reveals nothing about it, and differs across
Issuers. Decode the returned Token to read the `sub` you need for a trust
policy.

Secrets must be at least 16 characters. The pepper stops _offline_ guessing, but
anyone may ask the Issuer to mint a Token for a _guessed_ secret, so use a
random one (`openssl rand -base64 24`) — never a password you use elsewhere.

**The trade-off:** unlike the other two modes, the secret leaves the client and
is seen by the Issuer. That is a real cost, and it buys the simplest possible
client — no key, no signing, no `age`, one `curl`. It does not widen the trust
model much: a relying party already trusts the Issuer to mint identities, and
the Issuer already holds the signing key, so it could always impersonate you to
that relying party. What it _does_ add is that a compromised Issuer learns the
secret itself — which is why the secret must be dedicated to popoidc and used
nowhere else.

## Using it with octo-sts

Point a trust policy (`.github/chainguard/<name>.sts.yaml` in the target
repo/org) at your issuer and the devbox key's fingerprint:

```yaml
issuer: https://popoidc.example
subject: SHA256:Ln0abc… # from `ssh-keygen -lf ~/.ssh/id_ed25519.pub`
permissions:
  contents: read
```

The token's `aud` must be `octo-sts.dev` (as in the examples above).

## Configuration

All configuration is via environment variables (see
[.env.example](./.env.example)):

- `POPOIDC_ISSUER` — public HTTPS issuer URL (equals `iss`).
- `POPOIDC_SIGNING_JWK` — RSA private JWK with a `kid` (`deno task keygen`).
- `POPOIDC_HMAC_SECRET` — secret for the challenge HMAC. Rotate freely; it only
  invalidates challenges in flight.
- `POPOIDC_HMAC_IDENTITY_SECRET` — optional pepper for HMAC-mode fingerprints.
  Unset (the default) disables HMAC mode. **Do not rotate it**: it _names_ every
  shared-secret identity, so changing it renames all of them at once and breaks
  every trust policy pointing at one. Kept separate from `POPOIDC_HMAC_SECRET`
  for exactly that reason.
- `POPOIDC_NAMESPACE` — optional SSHSIG namespace (default `popoidc`).
- `PORT` — optional (default `8000`).

popoidc is **stateless**: no database. The signing key and HMAC secret live in
env.

## Deploy

Build the container and let Dokploy/Traefik terminate TLS and route your domain
to port `8000`:

```bash
docker build -t popoidc .
docker run -p 8000:8000 --env-file .env popoidc
```

## Development

Test-first, with a pre-commit hook that auto-formats and blocks on any
`deno fmt`/`lint`/`check`/`test` failure (so every commit is green).

```bash
deno task test     # run the suite
deno task check    # fmt + lint + type-check + test (same gates as the hook)
deno task dev      # run locally with --watch
```

**Test dependency:** the SSHSIG and age crypto are validated against the real
`ssh-keygen` and `age` binaries, so both must be on `PATH` to run the tests
(`age` is _not_ needed at runtime).
