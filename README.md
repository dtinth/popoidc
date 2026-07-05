# popoidc

[![CI](https://github.com/dtinth/popoidc/actions/workflows/ci.yml/badge.svg)](https://github.com/dtinth/popoidc/actions/workflows/ci.yml)
[![Coverage & test report](https://img.shields.io/badge/report-gh--pages-2563eb)](https://dtinth.github.io/popoidc/)

A public, self-hosted **OIDC-compatible token issuer** that mints short-lived
JWTs asserting _only_ that the bearer controls a given public key — "GitHub
Actions OIDC, but the auth factor is a key you already own."

Prove possession of an `ssh-ed25519` key (by signing) or a native `age`/X25519
key (by decrypting), and receive an RS256 ID Token whose `sub` is the key's
fingerprint. Relying parties verify it via standard OIDC discovery + JWKS and
decide for themselves whether that key is authorized — popoidc never asserts a
human identity.

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
- `POPOIDC_HMAC_SECRET` — secret for the challenge HMAC.
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
