// The data types the standard knows about, and how each one is normalised for comparison.
//
// Two mentions are "the same thing" when their normalised forms match, so "Dana  Reyes" and "dana reyes" share one
// entry, and "(617) 555-0142" and "617.555.0142" do too.

import { splitWs, stripWs } from "./util.ts";

export const TYPES = [
  "PERSON", "ORG", "LOCATION", "ADDRESS", "EMAIL", "PHONE", "URL", "IP_ADDRESS", "DATE", "MONEY",
  "CARD", "IBAN", "ROUTING", "BANK_ACCOUNT", "SSN", "API_KEY", "PASSWORD", "OTP", "ID", "USERNAME",
] as const;

// Values the model only ever needs to move from one place to another, never to read.
export const SECRET_TYPES: ReadonlySet<string> = new Set([
  "CARD", "IBAN", "ROUTING", "BANK_ACCOUNT", "SSN", "API_KEY", "PASSWORD", "OTP",
]);

// Types whose identity is their digits; separators and spacing do not matter.
export const DIGIT_TYPES: ReadonlySet<string> = new Set(["CARD", "PHONE", "SSN", "ROUTING", "BANK_ACCOUNT", "OTP"]);

// Types where a match is case-insensitive (an email address is the same in any case).
export const CASELESS_TYPES: ReadonlySet<string> = new Set(["EMAIL", "URL", "USERNAME"]);

const TYPE_NAME = /^[A-Z][A-Z0-9_]{1,31}$/;

/** Apps may add their own types (EMPLOYEE_ID, CASE_NUMBER...). They must look like the built-in ones. */
export function checkTypeName(name: string): string {
  if (typeof name !== "string" || !TYPE_NAME.test(name)) {
    throw new TypeError(`type names are upper case letters, digits and underscores, got ${JSON.stringify(name)}`);
  }
  return name;
}

export function digitsOf(value: string): string {
  return value.replace(/[^0-9]/g, "");
}

/** The comparison key for a value of a given type. */
export function normalize(type: string, value: string): string {
  if (DIGIT_TYPES.has(type)) return digitsOf(value);
  if (type === "IBAN") return splitWs(value).join("").toUpperCase();
  if (CASELESS_TYPES.has(type)) return stripWs(value).toLowerCase();
  if (type === "DATE") {
    // dates are compared by the day they name, which the session works out; this is only a fallback
    return stripWs(value).toLowerCase();
  }
  return splitWs(value).join(" ").toLowerCase();
}
