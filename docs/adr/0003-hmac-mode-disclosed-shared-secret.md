# HMAC mode: accept a disclosed shared secret as a third proof

ADR-0001 gives the Issuer two ways to prove an Identity, both keyed: Signing
Proof and Decryption Proof. Both demand real key material on the client — an
`ssh-ed25519` key plus SSHSIG, or an on-disk key plus the `age` binary. That is
more than some callers have (a CI job, a script, a container with no keyring),
and every one of them still needs the same thing: a stable `sub` a Relying Party
can name in a trust policy.

## Decision

Add **HMAC mode**: `POST /token` with `secret` + `aud` mints a Token whose `sub`
is `HMAC-SHA256:<base64>` — HMAC-SHA256 of the disclosed secret under a
server-side **Identity Pepper**, via a domain-separated subkey. The caller
invents the secret; the Issuer stores nothing.

- **No Challenge round-trip.** A Challenge exists to bind audience and freshness
  to a proof the client computes _without_ revealing the secret. Here the secret
  itself is the proof, so a challenge would add a request and buy nothing. The
  audience is passed directly instead.
- **Off by default, enabled by `POPOIDC_HMAC_IDENTITY_SECRET`.** Absent that env
  var, `/token` answers `501` — an operator who wants key-only proofs gets them
  by doing nothing.
- **A separate secret from `POPOIDC_HMAC_SECRET`.** The challenge MAC secret is
  rotatable at will (it only invalidates challenges in flight). The pepper
  _names_ every Shared Secret Identity, so rotating it renames all of them and
  breaks every trust policy at once. Conflating the two would turn a harmless
  rotation into a silent outage.
- **Minimum 16 characters.** The pepper defeats offline guessing, but anyone may
  ask the Issuer to mint a Token for a _guessed_ secret; a length floor rules
  out the trivially online-brute-forceable.
- **The secret never appears in the Token.** `key_type` is `hmac` and the `key`
  claim restates the fingerprint, since there is no public half to publish.

## Why this is acceptable (the trade-off)

The secret leaves the client and is seen by the Issuer — squarely against the
instinct behind ADR-0001, where the private key never moves. We accept it
because the Relying Party's trust model already assumes an honest Issuer: it
holds the RS256 signing key and can mint a Token for _any_ `sub` whenever it
likes. A caller who trusts the Issuer to assert their identity is already
trusting it more than this mode asks. What the mode genuinely adds is that a
compromised Issuer learns the secret itself — harmless if the secret is
dedicated to popoidc, which is why the docs push `openssl rand -base64 24` and
warn against reuse.

Consequence: HMAC mode is strictly weaker than the keyed modes and is offered as
a convenience, not a replacement. Keyed Identities remain the default, and both
`/challenge` paths are untouched.
