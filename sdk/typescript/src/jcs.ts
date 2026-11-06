// Canonical JSON (RFC 8785) for the shapes we sign: objects, arrays, strings, integers, booleans and null.
//
// We never sign floats, which keeps this small. Keys are sorted by UTF-16 code units, as RFC 8785 asks, which is
// also what JavaScript's default string sort does.

import { createHash } from "node:crypto";

export function canonical(value: unknown): Buffer {
  return Buffer.from(encode(value), "utf-8");
}

function encode(v: unknown): string {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new TypeError("floats are not allowed in signed objects; use integers");
    if (!Number.isSafeInteger(v)) throw new RangeError("integers in signed objects must fit in 53 bits");
    return String(v);
  }
  if (Array.isArray(v)) return "[" + v.map(encode).join(",") + "]";
  if (typeof v === "object" && v !== undefined) {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + encode(obj[k])).join(",") + "}";
  }
  throw new TypeError(`cannot sign a ${typeof v}`);
}

export function b64url(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

export function b64urlDecode(text: string): Buffer {
  return Buffer.from(text, "base64url");
}

/** The digest string used everywhere in the spec: 'sha-256:' plus base64url without padding. */
export function digest(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  return "sha-256:" + b64url(createHash("sha256").update(bytes).digest());
}
