import { assertEquals, assertThrows } from "@std/assert";
import { concat, Reader, writeString } from "./sshwire.ts";

Deno.test("Reader.readUint32 throws when truncated", () => {
  assertThrows(() => new Reader(new Uint8Array(3)).readUint32());
});

Deno.test("Reader.readString throws when the body is truncated", () => {
  // length prefix says 8 bytes, but only 2 follow
  assertThrows(() =>
    new Reader(new Uint8Array([0, 0, 0, 8, 1, 2])).readString()
  );
});

Deno.test("writeString + concat round-trip through Reader", () => {
  const r = new Reader(
    concat(
      writeString(new Uint8Array([9, 8, 7])),
      writeString(new Uint8Array([1])),
    ),
  );
  assertEquals([...r.readString()], [9, 8, 7]);
  assertEquals([...r.readString()], [1]);
  assertEquals(r.done, true);
});
