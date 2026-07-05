import { armor, Encrypter, type Recipient, Stanza } from "age-encryption";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { encodeBase64 } from "@std/encoding/base64";
import { parseSshEd25519 } from "./sshkey.ts";

// age's ssh-ed25519 recipient stanza (see ADR-0002). typage has no SSH-recipient
// support, so we reimplement the stanza on the same primitives typage uses.
const SSH_ED25519_LABEL = new TextEncoder().encode(
  "age-encryption.org/v1/ssh-ed25519",
);

/** Standard base64, no padding — the encoding age uses for stanza arguments. */
function b64(bytes: Uint8Array): string {
  return encodeBase64(bytes).replace(/=+$/, "");
}

/** A typage Recipient that wraps the file key for an `ssh-ed25519` key. */
class SshEd25519Recipient implements Recipient {
  readonly #wire: Uint8Array;
  readonly #montgomery: Uint8Array;

  constructor(sshKey: string) {
    const parsed = parseSshEd25519(sshKey);
    this.#wire = parsed.wire;
    this.#montgomery = ed25519.utils.toMontgomery(parsed.ed25519);
  }

  wrapFileKey(fileKey: Uint8Array): Stanza[] {
    const ephemeralSecret = x25519.utils.randomSecretKey();
    const share = x25519.getPublicKey(ephemeralSecret);
    let shared = x25519.getSharedSecret(ephemeralSecret, this.#montgomery);

    // age tweaks the shared secret by a scalar derived from the ssh key.
    const tweak = hkdf(
      sha256,
      new Uint8Array(0),
      this.#wire,
      SSH_ED25519_LABEL,
      32,
    );
    shared = x25519.getSharedSecret(tweak, shared);

    const salt = new Uint8Array(share.length + this.#montgomery.length);
    salt.set(share, 0);
    salt.set(this.#montgomery, share.length);

    const wrapKey = hkdf(sha256, shared, salt, SSH_ED25519_LABEL, 32);
    const body = chacha20poly1305(wrapKey, new Uint8Array(12)).encrypt(fileKey);
    const tag = b64(sha256(this.#wire).subarray(0, 4));

    return [new Stanza(["ssh-ed25519", tag, b64(share)], body)];
  }
}

/** Encrypt `plaintext` to a recipient (native `age1…` or an `ssh-ed25519` key); returns armored age. */
export async function encryptToRecipient(
  recipient: string,
  plaintext: Uint8Array,
): Promise<string> {
  const encrypter = new Encrypter();
  if (recipient.startsWith("age1")) {
    encrypter.addRecipient(recipient);
  } else if (recipient.startsWith("ssh-ed25519 ")) {
    encrypter.addRecipient(new SshEd25519Recipient(recipient));
  } else {
    throw new Error("unsupported recipient");
  }
  return armor.encode(await encrypter.encrypt(plaintext));
}
