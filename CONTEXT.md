# sshid

A public OIDC-compatible token issuer. Anyone who can prove possession of a
supported private key can obtain a signed Token asserting control of the
corresponding public key. It asserts key possession only — never a human
identity.

## Language

**Issuer**: This service. Issues Challenges, mints signed Tokens, and publishes
the keys to verify them. _Avoid_: OP, IdP, auth server (all correct in
spec-speak, but we say Issuer).

**Identity**: A public key held by a requester, of a supported type. Named by
its **Key Fingerprint**. Types: an SSH key (ed25519) proven by **Signing
Proof**; an age/X25519 recipient proven by **Decryption Proof**. _Avoid_:
account, user, principal, "SSH Identity" (too narrow now).

**Key Fingerprint**: The stable, per-type identifier that becomes the Token's
`sub`. SSH keys → the OpenSSH `SHA256:<base64>` fingerprint (`ssh-keygen -lf`).
age recipients → the `age1…` recipient string. Chosen for trust-policy
ergonomics. _Avoid_: key id, thumbprint, did.

**Challenge**: A server-issued, stateless (HMAC-authenticated, never stored)
token that binds the requested **Audience**, a freshness timestamp, and the
target public key. The uniform carrier of audience/freshness binding across all
key types. Redeemed at the token endpoint by returning a **Proof of Possession**
over it. _Avoid_: nonce (it contains one, but is more), session.

**Proof of Possession**: The response only the private key can produce for a
given **Challenge**. Two methods: **Signing Proof** (sign the Challenge —
signing-capable keys, via SSHSIG with namespace `sshid`) and **Decryption
Proof** (decrypt a secret the Challenge encrypted to the public key —
encryption-only keys like age). Required because public keys are public; without
it a Token is worthless. _Avoid_: authentication, login.

An SSH key may prove by **either** method (client picks via `?method=`):

- **Signing Proof** — universal: works for keys in `ssh-agent`, FIDO/hardware
  (`sk-`), and on disk. The default and only method for agent/hardware keys.
- **Decryption Proof** — on-disk keys only, because `ssh-agent` and hardware
  keys cannot decrypt and `age` reads the private key file directly. Gives the
  uniform `curl challenge | age -d | curl token` flow.

Because Decryption Proof is offered for SSH keys, the Issuer **must** encrypt to
`ssh-ed25519` recipients. typage can't do this natively, so we implement age's
`ssh-ed25519` recipient stanza as a custom typage `Recipient`: ed25519→X25519
(`@noble/curves` `edwardsToMontgomeryPub`) + age's HKDF `salt`/`info` +
ChaCha20-Poly1305 key-wrap. This is novel crypto that must match age
byte-for-byte. _Guardrail:_ the acceptance test encrypts in TS and decrypts with
the **real `age` binary** (`age -d -i <key>`); it must round-trip, or the build
fails. An age (X25519) key can only ever prove by Decryption Proof.

**Token**: The signed JWT the Issuer produces. An OIDC ID Token in shape, signed
RS256. Asserts only that the bearer controls a given Identity. Standard claims
(`iss`/`sub`/`aud`/`iat`/`nbf`/`exp`/`jti`) plus `key` (raw public key) and
`key_type`. Lives 15 min. No human-identity claims, by design. _Avoid_: id_token
(in prose), credential, ticket.

**Audience**: The `aud` the requester asks the Issuer to bind into the Challenge
(and thus the Token), naming the Relying Party the Token is for (as with GitHub
Actions' `audience`). For the octo-sts use case this is `octo-sts.dev`. _Avoid_:
scope, resource.

**Relying Party**: A service that consumes a Token. Verifies it via the Issuer's
published keys and decides for itself whether the Key Fingerprint is authorized
for anything. _Avoid_: client, RP (in prose), consumer.

**octo-sts**: The motivating first Relying Party. A Chainguard GitHub App that
exchanges a Token for a short-lived, scoped GitHub token, per a **Trust Policy**
(`.github/chainguard/*.sts.yaml`) matching `issuer` + `subject`. It fetches the
Issuer's JWKS via standard OIDC discovery. Verified to accept RS256 (and EdDSA
if advertised) via coreos/go-oidc.

## Relationships

- A requester asks the **Issuer** for a **Challenge**, naming an **Audience**
- The **Issuer** issues a **Challenge** binding Audience + freshness + public
  key
- The requester returns a **Proof of Possession** (Signing or Decryption)
- The **Issuer** mints one **Token**; its `sub` is the **Key Fingerprint**
- A **Relying Party** verifies the **Token** and maps its Fingerprint to access

## Motivating scenario

A devbox holds an ed25519 SSH Identity. It requests a Challenge for
`aud=octo-sts.dev`, produces a Signing Proof (SSHSIG, namespace `sshid`), and
redeems it for a Token (`sub` = Key Fingerprint). It posts the Token to
octo-sts, which — per a Trust Policy naming that Fingerprint — returns a
short-lived GitHub token the devbox uses for `git`. The Issuer never learns
_who_ owns the devbox.

## Example dialogue

> **Dev:** "age keys can't sign — how do they prove possession?" **Expert:** "By
> **Decryption Proof**. We encrypt a random secret to the age recipient inside
> the **Challenge**; only the holder can decrypt it and hand the secret back.
> That's why the Challenge must be server-issued — the client can't make a
> decryption challenge for itself."

## Flagged ambiguities

- "identity" is overloaded: **Identity** here means a public key, NOT a human.
- "SSH Identity (ed25519)" was too narrow — generalized to **Identity** (SSH
  signing _or_ age decryption) once **Decryption Proof** entered the design.

## Scope (v1)

- Signing Proof: `ssh-ed25519`. Decryption Proof: native age `age1…` (X25519)
  and on-disk `ssh-ed25519`. So the Issuer encrypts to both `age1…` and
  `ssh-ed25519` recipients. `ssh-rsa`/`ecdsa`/`sk-ssh-ed25519` (sign-only) are
  future additions behind the same Challenge envelope.
- `/challenge?key=…&aud=…&method=sign|decrypt`; `method` defaults to `sign` for
  SSH keys, is forced to `decrypt` for age keys.
- Runtime: Deno 2.9 (Node-compat). Libraries: `jose` (RS256 JWT + JWKS),
  `age-encryption`/typage (X25519 encrypt). SSHSIG verify is hand-rolled on Deno
  WebCrypto (`crypto.subtle` Ed25519). Built test-first (heavy TDD).
- Deploy: Docker container on Dokploy; Traefik terminates TLS. Stateless (RSA
  signing key + HMAC challenge secret in env; no database).
