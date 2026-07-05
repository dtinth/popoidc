# Reimplement age's ssh-ed25519 recipient stanza in TypeScript

Offering Decryption Proof for SSH keys (see ADR-0001) requires the Issuer to
encrypt a challenge secret _to_ an `ssh-ed25519` recipient. Our age library
(typage) does not support SSH recipients. The choices were:

- **(a)** shell out to the audited `age` binary (`age -R <sshpubkey>`), or
- **(b)** reimplement age's `ssh-ed25519` recipient stanza in TypeScript as a
  custom typage `Recipient`.

## Decision

We chose **(b): reimplement in TypeScript.**

## Why (and why this is surprising)

The obvious, safer-looking move is (a) — reuse the reference implementation and
write no crypto. We deliberately did not, to keep the Issuer a **pure,
single-artifact Deno service**: no external binary baked into the image, no
subprocess per challenge, no PATH/version coupling, runs anywhere Deno runs. The
stanza is bounded and fully specified by the age spec, and builds on the same
vetted primitives typage itself uses (`@noble/curves` for ed25519→X25519,
`@noble/hashes` HKDF, `@noble/ciphers` ChaCha20-Poly1305).

## Consequence (the risk we accepted)

This is novel, security-critical crypto that must match age **byte-for-byte** —
a bug here is a security bug, not a cosmetic one. It is therefore gated by a
**mandatory interop acceptance test**: encrypt in TS, decrypt with the _real_
`age` binary; the build fails if it doesn't round-trip. Plus unit vectors for
the ed25519→X25519 conversion. If this correctness burden ever outweighs the
purity benefit, the fallback is ADR-0001's rejected option — shell out to `age`.
