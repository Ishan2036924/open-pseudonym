// Format-preserving encryption: NIST SP 800-38G FF1 with AES.
//
// FF1 turns a string of digits into another string of digits of the same length, and back again with the key. We use
// it for values where a downstream system checks the shape (a 16-digit card field, a 9-digit routing field) and the
// model never needs the real number. NIST's 2025 draft revision drops FF3, so FF1 is the only mode here.
//
// Plain text and output are arrays of numerals (0..radix-1). Lengths must satisfy radix**len >= 1,000,000.

import { createCipheriv } from "node:crypto";

function bigFromBytes(b: Uint8Array): bigint {
  return b.length === 0 ? 0n : BigInt("0x" + Buffer.from(b).toString("hex"));
}

/** `n` as exactly `len` big-endian bytes. */
function toBytes(n: bigint, len: number): Buffer {
  const hex = n.toString(16).padStart(len * 2, "0");
  if (hex.length > len * 2) throw new RangeError("integer too large for its byte length");
  return Buffer.from(hex, "hex");
}

function xor(a: Uint8Array, b: Uint8Array): Buffer {
  const out = Buffer.alloc(Math.min(a.length, b.length));
  for (let i = 0; i < out.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function mod(a: bigint, m: bigint): bigint {
  return ((a % m) + m) % m;
}

export class FF1 {
  private readonly key: Buffer;
  readonly radix: number;
  private readonly bigRadix: bigint;

  constructor(key: Uint8Array, radix = 10) {
    if (![16, 24, 32].includes(key.length)) throw new RangeError("FF1 keys are 16, 24 or 32 bytes");
    if (!(radix >= 2 && radix <= 65536)) throw new RangeError("radix must be between 2 and 65536");
    this.key = Buffer.from(key);
    this.radix = radix;
    this.bigRadix = BigInt(radix);
  }

  private aes(block: Uint8Array): Buffer {
    const cipher = createCipheriv(`aes-${this.key.length * 8}-ecb`, this.key, null);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(block), cipher.final()]);
  }

  // CBC-MAC with a zero IV, as the standard defines it
  private prf(data: Buffer): Buffer {
    let y: Buffer = Buffer.alloc(16);
    for (let i = 0; i < data.length; i += 16) y = this.aes(xor(y, data.subarray(i, i + 16)));
    return y;
  }

  private num(xs: number[]): bigint {
    let n = 0n;
    for (const x of xs) n = n * this.bigRadix + BigInt(x);
    return n;
  }

  private str(n: bigint, length: number): number[] {
    const out = new Array<number>(length).fill(0);
    for (let i = length - 1; i >= 0; i--) {
      out[i] = Number(n % this.bigRadix);
      n /= this.bigRadix;
    }
    return out;
  }

  private roundValues(n: number, tweak: Buffer) {
    const u = Math.floor(n / 2);
    const v = n - u;
    const b = Math.ceil(Math.ceil(v * Math.log2(this.radix)) / 8);
    const d = 4 * Math.ceil(b / 4) + 4;
    const p = Buffer.concat([
      Buffer.from([1, 2, 1]), toBytes(BigInt(this.radix), 3), Buffer.from([10, u % 256]),
      toBytes(BigInt(n), 4), toBytes(BigInt(tweak.length), 4),
    ]);
    return { u, v, b, d, p };
  }

  private f(p: Buffer, tweak: Buffer, i: number, half: number[], b: number, d: number): bigint {
    const padLen = (((-tweak.length - b - 1) % 16) + 16) % 16;
    const q = Buffer.concat([tweak, Buffer.alloc(padLen), Buffer.from([i]), toBytes(this.num(half), b)]);
    const r = this.prf(Buffer.concat([p, q]));
    let s = r;
    let j = 1;
    while (s.length < d) {
      s = Buffer.concat([s, this.aes(xor(r, toBytes(BigInt(j), 16)))]);
      j += 1;
    }
    return bigFromBytes(s.subarray(0, d));
  }

  private check(xs: number[]): void {
    if (this.bigRadix ** BigInt(xs.length) < 1_000_000n) {
      throw new RangeError("input too short for FF1 (radix**length must be at least 1,000,000)");
    }
    if (xs.some((x) => !(Number.isInteger(x) && x >= 0 && x < this.radix))) throw new RangeError("numeral out of range");
  }

  encrypt(xs: number[], tweak: Uint8Array = new Uint8Array()): number[] {
    this.check(xs);
    const t = Buffer.from(tweak);
    const { u, v, b, d, p } = this.roundValues(xs.length, t);
    let a = xs.slice(0, u);
    let bb = xs.slice(u);
    for (let i = 0; i < 10; i++) {
      const y = this.f(p, t, i, bb, b, d);
      const m = i % 2 === 0 ? u : v;
      const c = mod(this.num(a) + y, this.bigRadix ** BigInt(m));
      [a, bb] = [bb, this.str(c, m)];
    }
    return [...a, ...bb];
  }

  decrypt(xs: number[], tweak: Uint8Array = new Uint8Array()): number[] {
    this.check(xs);
    const t = Buffer.from(tweak);
    const { u, v, b, d, p } = this.roundValues(xs.length, t);
    let a = xs.slice(0, u);
    let bb = xs.slice(u);
    for (let i = 9; i >= 0; i--) {
      const y = this.f(p, t, i, a, b, d);
      const m = i % 2 === 0 ? u : v;
      const c = mod(this.num(bb) - y, this.bigRadix ** BigInt(m));
      [bb, a] = [a, this.str(c, m)];
    }
    return [...a, ...bb];
  }

  // Digit-string helpers, the only way the rest of the library uses FF1.

  encryptDigits(digits: string, tweak: Uint8Array = new Uint8Array()): string {
    return this.encrypt([...digits].map(Number), tweak).join("");
  }

  decryptDigits(digits: string, tweak: Uint8Array = new Uint8Array()): string {
    return this.decrypt([...digits].map(Number), tweak).join("");
  }
}
