// Minimal SSH wire-format primitives (RFC 4251 §5): length-prefixed strings.

/** Sequential reader over an SSH wire buffer. */
export class Reader {
  #buf: Uint8Array;
  #off = 0;

  constructor(buf: Uint8Array) {
    this.#buf = buf;
  }

  readUint32(): number {
    if (this.#off + 4 > this.#buf.length) {
      throw new Error("ssh wire: truncated uint32");
    }
    const v = new DataView(
      this.#buf.buffer,
      this.#buf.byteOffset + this.#off,
      4,
    ).getUint32(0);
    this.#off += 4;
    return v;
  }

  readBytes(n: number): Uint8Array {
    if (this.#off + n > this.#buf.length) {
      throw new Error("ssh wire: truncated bytes");
    }
    const b = this.#buf.subarray(this.#off, this.#off + n);
    this.#off += n;
    return b;
  }

  /** Read a length-prefixed string's bytes. */
  readString(): Uint8Array {
    return this.readBytes(this.readUint32());
  }

  get done(): boolean {
    return this.#off === this.#buf.length;
  }
}

/** Encode bytes as a length-prefixed SSH wire string. */
export function writeString(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

/** Concatenate byte arrays. */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
