# SSH/age proof-of-possession as a custom OIDC grant

We want a public Issuer that turns _control of an existing key_ (an
`ssh-ed25519` key or a native `age`/X25519 recipient) into a short-lived,
standards-verifiable OIDC Token — "GitHub Actions OIDC, but the auth factor is a
key you already own." The first Relying Party is octo-sts (devbox → scoped
GitHub token).

## Decision

The Issuer is a **standards-compliant OIDC verifier** — real
`/.well-known/openid-configuration` + JWKS, tokens signed **RS256** — so any
OIDC-aware Relying Party can consume Tokens with no special code. But **token
acquisition is a custom grant**, not OIDC authorization-code (there is no
browser; keys live in CLIs):

1. `GET /challenge?key=…&aud=…&method=sign|decrypt` returns a **mandatory,
   server-issued, stateless Challenge**: an HMAC (keyed by a server secret,
   never stored) binding `{aud, iat, public key}`.
2. The holder returns a **Proof of Possession** over that Challenge — **Signing
   Proof** (SSHSIG, namespace `popoidc`) or **Decryption Proof** (decrypt a
   secret the Challenge encrypted to the recipient).
3. `POST /token` re-verifies the HMAC + the proof + `iat` freshness (±60 s) and
   mints a 15-minute RS256 JWT whose `sub` is the key fingerprint.

The Token asserts **key possession only** — never a human identity. All
authorization ("may this fingerprint do anything?") belongs to the Relying Party
(for octo-sts, its Trust Policy).

## Why these choices

- **Mandatory server-issued Challenge.** Decryption Proof (required for
  encrypt-only age keys) is _impossible_ in a client-only request — the verifier
  must create the ciphertext from a secret the client doesn't know. Making the
  Challenge mandatory also moves `aud`/freshness binding server-side, uniformly
  across both proof methods.
- **Stateless (HMAC, not storage).** Keeps the Issuer a no-database container
  app. Accepted consequence: a ~60 s replay window (the freshness bound); strict
  single-use can be layered on later with KV if a Relying Party ever demands it.
- **RS256.** GitHub Actions OIDC — the model we emulate — signs RS256 for
  maximal public-RP compatibility (verified: coreos/go-oidc defaults to RS256
  unless the discovery doc advertises other algs). EdDSA was tidier and
  verified-compatible with octo-sts, but RS256 keeps "public / any RP" actually
  true.

## Consequences

- SSH keys prove by signing (universal: agent/FIDO/on-disk) **or** decryption
  (on-disk only — `ssh-agent` and hardware keys cannot decrypt). age keys prove
  by decryption only.
- The Issuer must encrypt to `ssh-ed25519` recipients, which typage can't do —
  so age's `ssh-ed25519` stanza is reimplemented in TS (novel crypto; guarded by
  a real-`age` interop test).
- Not standard OIDC login: no browser, consent, or PKCE. Relying Parties adopt
  the Issuer purely via OIDC discovery of its JWKS.
