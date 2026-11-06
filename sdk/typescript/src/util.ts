// Small helpers that give JavaScript strings and regexes the behaviour the Python reference relies on.
// The shared vectors compare bytes, so these are worth keeping exact.

// What Python's str.split() and str.strip() treat as whitespace.
export const WS = "\\t\\n\\v\\f\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const WS_RUN = new RegExp(`[${WS}]+`, "u");
const WS_EDGES = new RegExp(`^[${WS}]+|[${WS}]+$`, "gu");
const WS_START = new RegExp(`^[${WS}]+`, "u");

/** Python's `s.split()`: runs of whitespace separate words, empty pieces are dropped. */
export function splitWs(s: string): string[] {
  return s.split(WS_RUN).filter((w) => w !== "");
}

/** Python's `s.strip()`. */
export function stripWs(s: string): string {
  return s.replace(WS_EDGES, "");
}

/** Python's `s.lstrip()`. */
export function lstripWs(s: string): string {
  return s.replace(WS_START, "");
}

/** Number of code points, which is what Python's len() counts. */
export function cpLength(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
    }
    n++;
  }
  return n;
}

/** Orders strings by code point, as Python does. JavaScript's default compares UTF-16 units, which differs once
 * astral characters are involved. */
export function cmpCodePoints(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a.charCodeAt(i);
    const y = b.charCodeAt(i);
    if (x === y) continue;
    const sx = x >= 0xd800 && x <= 0xdfff;
    const sy = y >= 0xd800 && y <= 0xdfff;
    if (sx !== sy) return sx ? 1 : -1; // a surrogate stands for a code point above the whole BMP
    return x < y ? -1 : 1;
  }
  return Math.sign(a.length - b.length);
}

/** Escapes a literal for use inside a regex built with the `u` flag. Only syntax characters are escaped, because
 * the `u` flag rejects needless escapes such as "\@" or "\ ". */
export function escapeRegExp(s: string): string {
  return s.replace(/[\\^$.*+?()[\]{}|/]/g, "\\$&");
}

const LOWER_MARK = /[\p{Ll}\p{Lowercase}\p{Lt}]/u;
const UPPER_PROP = /\p{Uppercase}/u;
const TITLE_MARK = /\p{Lt}/u;
const UPPER_MARK = /[\p{Lu}\p{Uppercase}\p{Lt}]/u;
const LOWER_PROP = /\p{Lowercase}/u;

/** Python's str.isupper(): at least one cased character, and none of them lower case. */
export function isUpper(s: string): boolean {
  let cased = false;
  for (const ch of s) {
    if (LOWER_MARK.test(ch)) return false;
    if (!cased && UPPER_PROP.test(ch)) cased = true;
  }
  return cased;
}

/** Python's str.islower(): at least one cased character, and none of them upper case. */
export function isLower(s: string): boolean {
  let cased = false;
  for (const ch of s) {
    if (UPPER_MARK.test(ch) || TITLE_MARK.test(ch)) return false;
    if (!cased && LOWER_PROP.test(ch)) cased = true;
  }
  return cased;
}

/** Python's str.capitalize(). */
export function capitalize(s: string): string {
  if (s === "") return s;
  const first = String.fromCodePoint(s.codePointAt(0)!);
  return first.toUpperCase() + s.slice(first.length).toLowerCase();
}

export function isAlphaChar(ch: string): boolean {
  return /^\p{L}/u.test(ch);
}

export function isAlnumChar(ch: string): boolean {
  return /^[\p{L}\p{N}]/u.test(ch);
}

export function isDigitChar(ch: string): boolean {
  return /^\p{Nd}/u.test(ch);
}

/** All matches of a global regex starting at `pos`. Look-behind can still see the text before `pos`, which is how
 * Python's finditer(text, pos) behaves and what the streaming restorer needs. */
export function findAll(re: RegExp, text: string, pos = 0): RegExpExecArray[] {
  const out: RegExpExecArray[] = [];
  re.lastIndex = pos;
  for (;;) {
    const m = re.exec(text);
    if (m === null) break;
    out.push(m);
    if (m[0].length === 0) re.lastIndex += 1;
  }
  return out;
}

/** Python's repr() for the few kinds of values that end up in error messages. */
export function pyRepr(v: unknown): string {
  if (v === null || v === undefined) return "None";
  if (v === true) return "True";
  if (v === false) return "False";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") {
    const quote = v.includes("'") && !v.includes('"') ? '"' : "'";
    let out = "";
    for (const ch of v) {
      const c = ch.codePointAt(0)!;
      if (ch === "\\") out += "\\\\";
      else if (ch === quote) out += "\\" + ch;
      else if (ch === "\n") out += "\\n";
      else if (ch === "\r") out += "\\r";
      else if (ch === "\t") out += "\\t";
      else if (c < 0x20 || c === 0x7f) out += "\\x" + c.toString(16).padStart(2, "0");
      else out += ch;
    }
    return quote + out + quote;
  }
  if (Array.isArray(v)) return "[" + v.map(pyRepr).join(", ") + "]";
  return JSON.stringify(v);
}

/** Python's idea of "falsy" for the JSON values a policy document can hold. */
export function truthy(v: unknown): boolean {
  if (v === null || v === undefined || v === false || v === 0 || v === "") return false;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === "object") return Object.keys(v as object).length > 0;
  return true;
}

export function isPlainObject(v: unknown): v is Record<string, any> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** JSON.stringify never returns undefined for the values we pass; this keeps the type honest. */
export function toJson(v: unknown): string {
  return JSON.stringify(v) as string;
}

/** Python's `base64.b64decode(s, validate=False)`: characters outside the alphabet are skipped, padding ends the
 * data, and a leftover partial group or any non-ASCII character is an error (null here). */
export function lenientBase64(s: string): Uint8Array | null {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  if (/[^\x00-\x7f]/.test(s)) return null; // Python refuses non-ASCII text outright
  const out: number[] = [];
  let quad = 0;
  let left = 0;
  let pads = 0;
  for (const ch of s) {
    if (ch === "=") {
      if (quad >= 2 && quad + ++pads >= 4) return Uint8Array.from(out);
      continue;
    }
    const v = alphabet.indexOf(ch);
    if (v < 0) continue;
    pads = 0;
    if (quad === 0) {
      quad = 1;
      left = v;
    } else if (quad === 1) {
      quad = 2;
      out.push((left << 2) | (v >> 4));
      left = v & 0xf;
    } else if (quad === 2) {
      quad = 3;
      out.push((left << 4) | (v >> 2));
      left = v & 3;
    } else {
      quad = 0;
      out.push((left << 6) | v);
      left = 0;
    }
  }
  return quad === 0 ? Uint8Array.from(out) : null;
}
