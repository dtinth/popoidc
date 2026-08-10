# popoidc

A public OIDC-compatible token issuer. Anyone who can prove possession of a
supported private key can obtain a signed Token asserting control of the
corresponding public key. It asserts key possession only — never a human
identity.

## Language

**Issuer**: This service. Issues Challenges, mints signed Tokens, and publishes
the keys to verify them. _Avoid_: OP, IdP, auth server (all correct in
spec-speak, but we say Issuer).

**Identity**: A secret held by a requester, of a supported type, named by its
**Key Fingerprint**. Usually the private half of a public key: an SSH key
(ed25519) proven by **Signing Proof**; an age/X25519 recipient proven by
**Decryption Proof**. Or a **Shared Secret** with no public half at all, proven
by **Disclosure Proof**. _Avoid_: account, user, principal, "SSH Identity" (too
narrow now).

**Shared Secret**: An arbitrary high-entropy string (≥ 16 chars) the requester
invents and hands to the Issuer verbatim — "HMAC mode". No key material, no
challenge, one request. Named by the HMAC of the secret under a server-side
**Identity Pepper**, so the Issuer stores nothing and the name discloses
nothing. _Avoid_: password, API key, token (it is none of those to a Relying
Party).

**Harness**: The agent runtime that holds an MCP connector — a Claude harness,
say. It authorizes once over OAuth; the platform stores the resulting access
token and attaches it to each MCP request, so the model never reads it. That
access token _is_ a **Shared Secret**, which makes the connector a vault rather
than an authorization. Named per **Namespace**. Note the granularity: the
Identity belongs to the Harness, so every agent session on it shares one `sub`.
_Avoid_: agent, session, worker (all narrower than what is actually named).

**Namespace**: A path segment on the MCP endpoint (`/mcp/ns1`), mixed into the
Shared Secret so one access token names several Identities. A human sets it in
the connector URL, which is the point — it must never be a tool argument, or a
prompt-injected model could choose which Identity to act as. It is a rotation
lever, not a privilege boundary. _Avoid_: scope, tenant, environment.

**Identity Pepper**: The server-side secret (`POPOIDC_HMAC_IDENTITY_SECRET`)
that keys Shared Secret naming. Deliberately _not_ the challenge HMAC secret:
that one is rotatable at will, this one is permanent — rotating it renames every
Shared Secret Identity at once. Unset by default, which disables HMAC mode.

**Key Fingerprint**: The stable, per-type identifier that becomes the Token's
`sub`. SSH keys → the OpenSSH `SHA256:<base64>` fingerprint (`ssh-keygen -lf`).
age recipients → the `age1…` recipient string. Shared Secrets → the
`HMAC-SHA256:<base64>` **Secret Fingerprint**. Chosen for trust-policy
ergonomics. _Avoid_: key id, thumbprint, did.

**Challenge**: A server-issued, stateless (HMAC-authenticated, never stored)
token that binds the requested **Audience**, a freshness timestamp, and the
target public key. The uniform carrier of audience/freshness binding across all
key types. Redeemed at the token endpoint by returning a **Proof of Possession**
over it. _Avoid_: nonce (it contains one, but is more), session.

**Proof of Possession**: What only the holder of an Identity can produce. Three
methods. Two are **Challenge**-bound, because public keys are public and a Token
would otherwise be worthless: **Signing Proof** (sign the Challenge —
signing-capable keys, via SSHSIG with namespace `popoidc`) and **Decryption
Proof** (decrypt a secret the Challenge encrypted to the public key —
encryption-only keys like age). The third, **Disclosure Proof**, needs no
Challenge: the requester simply sends the **Shared Secret**, which nothing but
possession can produce. _Avoid_: authentication, login.

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
(`iss`/`sub`/`aud`/`iat`/`nbf`/`exp`/`jti`) plus `key` (raw public key — or, for
a Shared Secret, which has no public half, the Secret Fingerprint again; never
the secret itself) and `key_type`. Lives 15 min. No human-identity claims, by
design. _Avoid_: id_token (in prose), credential, ticket.

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

**Shared Secret** short-circuits the first three steps: the requester posts the
secret and the Audience straight to the token endpoint, and the **Issuer** mints
the **Token** — there is nothing for a Challenge to bind.

## Motivating scenario

A devbox holds an ed25519 SSH Identity. It requests a Challenge for
`aud=octo-sts.dev`, produces a Signing Proof (SSHSIG, namespace `popoidc`), and
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

- "identity" is overloaded: **Identity** here means a key or secret, NOT a
  human.
- "SSH Identity (ed25519)" was too narrow — generalized to **Identity** (SSH
  signing _or_ age decryption) once **Decryption Proof** entered the design, and
  again ("a public key" → "a secret") once **Shared Secret** did.
- "HMAC" now names two unrelated things: the **Challenge**'s MAC and the
  **Shared Secret** mode's naming function. They use different secrets on
  purpose (see **Identity Pepper**) — never conflate them.

## Scope (v1)

- Signing Proof: `ssh-ed25519`. Decryption Proof: native age `age1…` (X25519)
  and on-disk `ssh-ed25519`. So the Issuer encrypts to both `age1…` and
  `ssh-ed25519` recipients. `ssh-rsa`/`ecdsa`/`sk-ssh-ed25519` (sign-only) are
  future additions behind the same Challenge envelope. Disclosure Proof: any
  string ≥ 16 chars.
- `/challenge?key=…&aud=…&method=sign|decrypt`; `method` defaults to `sign` for
  SSH keys, is forced to `decrypt` for age keys.
- `POST /token` takes `challenge` (+ `signature` for Signing Proof) **or**
  `secret` + `aud` (Disclosure Proof), never both. HMAC mode is off unless the
  operator sets an **Identity Pepper**.
- Harness identity rides on HMAC mode: an OAuth authorization server at
  `/oauth/*` mints the Shared Secret, and an MCP server at `/mcp[/<namespace>]`
  redeems it. Both are off without an Identity Pepper. See ADR-0004.
- Runtime: Deno 2.9 (Node-compat). Libraries: `jose` (RS256 JWT + JWKS),
  `age-encryption`/typage (X25519 encrypt). SSHSIG verify is hand-rolled on Deno
  WebCrypto (`crypto.subtle` Ed25519). Built test-first (heavy TDD).
- Deploy: Docker container on Dokploy; Traefik terminates TLS. Stateless (RSA
  signing key + HMAC challenge secret in env; no database).
