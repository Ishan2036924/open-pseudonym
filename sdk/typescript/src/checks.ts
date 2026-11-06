// Checksums and sanity checks that turn a pattern match into a confident detection.
//
// A 16-digit run is only a card if the Luhn digit adds up; nine digits after "routing" are only a routing number if
// the ABA weights do. These checks remove most false alarms (order numbers, tracking ids) for free.

import { pools } from "./data.ts";
import { digitsOf } from "./types.ts";
import { cpLength, splitWs } from "./util.ts";

// IBAN lengths per country (ISO 13616 registry). Unknown countries are rejected rather than guessed.
export const IBAN_LENGTHS: ReadonlyMap<string, number> = new Map(Object.entries({
  AD: 24, AE: 23, AT: 20, BE: 16, BG: 22, BH: 22, BR: 29, CH: 21, CY: 28, CZ: 24, DE: 22,
  DK: 18, EE: 20, ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18, GR: 27,
  HR: 21, HU: 28, IE: 22, IL: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LI: 21,
  LT: 20, LU: 20, LV: 21, MC: 27, MT: 31, NL: 18, NO: 15, PK: 24, PL: 28, PS: 29, PT: 25,
  QA: 29, RO: 24, RS: 22, SA: 24, SE: 24, SI: 19, SK: 24, SM: 27, TR: 26, UA: 29, VA: 22,
}));

export function luhnOk(digits: string): boolean {
  let total = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
  }
  return total % 10 === 0;
}

/** The check digit that makes partial + digit pass Luhn. */
export function luhnDigit(partial: string): string {
  for (const d of "0123456789") {
    if (luhnOk(partial + d)) return d;
  }
  throw new Error("unreachable");
}

export function cardOk(value: string): boolean {
  const d = digitsOf(value);
  if (d.length < 13 || d.length > 19 || !luhnOk(d) || new Set(d).size === 1) return false;
  if ("3456".includes(d[0])) return true;
  if (d[0] !== "2") return false;
  const prefix = Number(d.slice(0, 4));
  return prefix >= 2221 && prefix <= 2720;
}

/** The IBAN as one big number, letters becoming 10..35, after moving the first four characters to the end. */
export function ibanNumeric(iban: string): bigint {
  const moved = iban.slice(4) + iban.slice(0, 4);
  let digits = "";
  for (const ch of moved) digits += parseInt(ch, 36).toString();
  return BigInt(digits);
}

export function ibanOk(value: string): boolean {
  const s = splitWs(value).join("").toUpperCase();
  if (IBAN_LENGTHS.get(s.slice(0, 2)) !== s.length || !/^[\p{L}\p{N}]+$/u.test(s)) return false;
  // the reference raises on letters outside A-Z here; saying "not an IBAN" is the safer way to fail
  if (!/^[0-9A-Z]+$/.test(s)) return false;
  return ibanNumeric(s) % 97n === 1n;
}

export function abaSum(d: string): number {
  const n = (i: number) => d.charCodeAt(i) - 48;
  return 3 * (n(0) + n(3) + n(6)) + 7 * (n(1) + n(4) + n(7)) + (n(2) + n(5) + n(8));
}

export function abaOk(value: string): boolean {
  const d = digitsOf(value);
  if (d.length !== 9) return false;
  const prefix = Number(d.slice(0, 2));
  if (!(prefix <= 12 || (prefix >= 21 && prefix <= 32) || (prefix >= 61 && prefix <= 72) || prefix === 80)) return false;
  return abaSum(d) % 10 === 0;
}

export function ssnOk(value: string): boolean {
  const d = digitsOf(value);
  if (d.length !== 9) return false;
  const area = d.slice(0, 3);
  const group = d.slice(3, 5);
  const serial = d.slice(5);
  return area !== "000" && area !== "666" && area[0] !== "9" && group !== "00" && serial !== "0000";
}

export function phoneOk(value: string): boolean {
  const n = digitsOf(value).length;
  return n >= 10 && n <= 15;
}

export function nameOk(value: string): boolean {
  const stop = stopwords();
  const tokens = splitWs(value);
  return tokens.length > 0 && tokens.every((t) => !stop.has(t.toLowerCase()) && cpLength(t) >= 2);
}

let stop: Set<string> | null = null;

function stopwords(): Set<string> {
  if (stop === null) stop = new Set(pools().name_stopwords.map((w) => w.toLowerCase()));
  return stop;
}
