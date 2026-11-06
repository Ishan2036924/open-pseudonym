// A small deterministic random source.
//
// Every choice the library makes (which fake name, which test card, how far to shift dates) comes from here. Given
// the same seed, Python and TypeScript make exactly the same choices, which is what lets both SDKs share test vectors.
//
// The construction is plain HMAC-SHA256 in counter mode: block(label, n) = HMAC(seed, label || 0x00 || n as 8 bytes).
// Each label keeps its own counter, so adding a new kind of choice never shifts the existing ones.

import { createHmac } from "node:crypto";

const TWO_64 = 1n << 64n;

export class Drbg {
  readonly seed: Uint8Array;
  counters: Map<string, number>;

  constructor(seed: Uint8Array, counters?: Map<string, number> | Record<string, number> | null) {
    if (seed.length < 16) throw new RangeError("the seed must be at least 16 bytes");
    this.seed = seed;
    this.counters = counters instanceof Map ? new Map(counters) : new Map(Object.entries(counters ?? {}));
  }

  block(label: string): Buffer {
    const n = this.counters.get(label) ?? 0;
    this.counters.set(label, n + 1);
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(n));
    const msg = Buffer.concat([Buffer.from(label, "utf-8"), Buffer.from([0]), counter]);
    return createHmac("sha256", this.seed).update(msg).digest();
  }

  /** A uniform integer in [0, n). Rejection sampling keeps it unbiased. */
  below(label: string, n: number): number {
    if (!(n > 0)) throw new RangeError("n must be positive");
    const big = BigInt(n);
    const limit = (TWO_64 / big) * big;
    for (;;) {
      const x = this.block(label).readBigUInt64BE(0);
      if (x < limit) return Number(x % big);
    }
  }

  /** A key for one purpose, fixed for the life of the seed (does not touch any counter). */
  derive(purpose: string): Buffer {
    return createHmac("sha256", this.seed).update(Buffer.from("opn-derive\0" + purpose, "utf-8")).digest();
  }
}
