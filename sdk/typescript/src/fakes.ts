// Realistic stand-ins ("surrogates"), one maker per type.
//
// The rules that matter (spec section 7):
//   - A fake is chosen at random from a pool, not computed from the real value, so it says nothing about it.
//   - The same real value always gets the same fake within a vault, and so do its parts: "Dana Reyes" -> "Maya Ortiz",
//     later "Dana" -> "Maya", and dana.reyes@... -> maya.ortiz@...
//   - Fakes come from ranges set aside for examples wherever such ranges exist (.example domains, 555-01xx phone
//     numbers, documentation IP blocks, published test cards, advertising SSNs), so a fake that leaks into a real
//     action cannot reach a real person.
//   - A fake never equals a real value we have seen, and never appears elsewhere in the text being masked.

import * as checks from "./checks.ts";
import { pools } from "./data.ts";
import { digitsOf } from "./types.ts";
import type { Vault } from "./vault.ts";
import {
  capitalize, escapeRegExp, isAlnumChar, isAlphaChar, isDigitChar, isLower, isUpper, lstripWs, splitWs,
} from "./util.ts";

const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";

const KEY_PREFIXES = [
  "sk-proj-", "sk-ant-", "sk-", "sk_live_", "sk_test_", "rk_live_", "rk_test_", "ghp_", "gho_", "ghs_",
  "github_pat_", "glpat-", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-", "hf_", "AKIA", "ASIA", "AIza",
].sort((a, b) => b.length - a.length); // longest first (a stable sort keeps the listed order among equals)
const GENERIC_MAILBOXES = new Set([
  "info", "support", "sales", "hello", "contact", "admin", "noreply", "no", "reply", "team", "billing", "help",
  "office", "hr", "jobs", "careers", "news", "newsletter", "notifications", "mail", "accounts", "security",
  "service", "orders", "do", "not",
]);
const GENERIC_SUBDOMAINS = new Set(["www", "docs", "mail", "app", "login", "api", "blog", "shop", "support", "help",
  "m", "accounts", "auth", "id", "portal", "my"]);
const AREA_CODES = ["201", "212", "312", "415", "512", "617", "720", "206", "305", "404"];
const TEST_NETS = ["192.0.2.", "198.51.100.", "203.0.113."];
const ORG_SUFFIX = / (Inc|LLC|Ltd|Corp|Corporation|GmbH|PLC|LLP|Co)(\.?)$/;
// "[^\n]" instead of "." because Python's dot stops at a newline only, JavaScript's also at \r and U+2028
const ADDRESS_PARTS = new RegExp(
  "^([0-9]+)([A-Z]?) ([^\\n]+?) (Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Way|Court|Ct|Place|Pl" +
  "|Terrace|Parkway|Pkwy|Highway|Hwy|Square|Sq)(\\.?)([^\\n]*)$");
const URL_PARTS = /^(https?:\/\/)([^/?#:]+)(:[0-9]+)?([^\n]*)$/i;

/** What a maker needs besides the real value. */
export class Ctx {
  vault: Vault;
  text: string; // the text being masked, so a fake never collides with something already in it
  options: Record<string, any>;

  constructor(vault: Vault, text: string, options: Record<string, any> = {}) {
    this.vault = vault;
    this.text = text;
    this.options = options;
  }

  free(candidate: string): boolean {
    const low = candidate.toLowerCase();
    if (this.vault.used.has(low) || this.vault.realSeen.has(low)) return false;
    return !new RegExp("(?<![A-Za-z0-9_])" + escapeRegExp(candidate) + "(?![A-Za-z0-9_])", "iu").test(this.text);
  }
}

/** Draw from a pool until we hit a free value. If the pool runs dry, pair two values with a hyphen. */
export function pick(ctx: Ctx, label: string, pool: string[]): string {
  for (let i = 0; i < 3 * pool.length; i++) {
    const c = pool[ctx.vault.drbg.below(label, pool.length)];
    if (ctx.free(c)) return c;
  }
  for (let i = 0; i < 200; i++) {
    const a = pool[ctx.vault.drbg.below(label, pool.length)];
    const b = pool[ctx.vault.drbg.below(label, pool.length)];
    const c = `${a}-${b}`;
    if (ctx.free(c)) return c;
  }
  throw new Error(`ran out of fake values for ${label}`);
}

export function chars(ctx: Ctx, label: string, alphabet: string, n: number): string {
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[ctx.vault.drbg.below(label, alphabet.length)];
  return out;
}

/** Same length, same kind of character in each place: 'Ab3-x9' -> 'Qx7-k2'. */
export function shape(ctx: Ctx, value: string, label = "shape"): string {
  let out = "";
  for (const ch of value) {
    if (ch >= "A" && ch <= "Z") out += chars(ctx, label, UPPER, 1);
    else if (ch >= "a" && ch <= "z") out += chars(ctx, label, LOWER, 1);
    else if (ch >= "0" && ch <= "9") out += chars(ctx, label, DIGITS, 1);
    else out += ch;
  }
  return out;
}

/** Copy the capitalisation style of the real token onto the fake. */
export function styled(fake: string, like: string): string {
  if ([...like].length > 1 && isUpper(like)) return fake.toUpperCase();
  if (isLower(like)) return fake.toLowerCase();
  return fake;
}

/** Put new digits where the old ones were, keeping spaces, dashes and brackets. */
export function fillTemplate(template: string, digits: string): string {
  if (digitsOf(template).length !== digits.length) return digits;
  let i = 0;
  return template.replace(/[0-9]/g, () => digits[i++]);
}

let suffixCache: ReadonlySet<string> | null = null;

function suffixes(): ReadonlySet<string> {
  if (suffixCache === null) suffixCache = new Set(pools().public_suffixes);
  return suffixCache;
}

/**
 * The part of a host that one owner controls: acme.com for login.acme.com, acme.github.io for acme.github.io. Uses
 * the suffix list in pools.json, a small subset of the Public Suffix List; implementations with the full list should
 * use it.
 */
export function isPublicSuffix(host: string): boolean {
  return suffixes().has(host.toLowerCase().replace(/\.+$/, ""));
}

export function registrable(host: string): string {
  const labels = host.toLowerCase().replace(/\.+$/, "").split(".");
  const known = suffixes();
  for (let n = labels.length - 1; n > 0; n--) { // longest known suffix first
    if (known.has(labels.slice(-n).join("."))) return labels.slice(-(n + 1)).join(".");
  }
  return labels.slice(-2).join(".");
}

// People, organisations, places

function gender(token: string): string {
  return pools().name_gender.get(token.toLowerCase().split("-")[0]) ?? "n";
}

export function person(ctx: Ctx, real: string): string {
  const tokens = splitWs(real);
  const names = pools().first_names;
  const keepGender = "keep_gender" in ctx.options ? ctx.options.keep_gender : true;
  const out: string[] = [];
  tokens.forEach((t, i) => {
    const key = t.toLowerCase();
    let fake = ctx.vault.parts.get(key);
    if (fake === undefined) {
      const isFirst = (tokens.length === 1 && pools().name_gender.has(key.split("-")[0])) ||
        (tokens.length > 1 && i < tokens.length - 1);
      if (isFirst) {
        const g = keepGender ? gender(t) : "any";
        const pool = g === "any" ? [...names.f, ...names.m, ...names.n] : (names as Record<string, string[]>)[g];
        fake = pick(ctx, `first.${g}`, pool);
      } else {
        fake = pick(ctx, "last", pools().last_names);
      }
      ctx.vault.addPart(t, fake);
    }
    out.push(styled(fake, t));
  });
  return out.join(" ");
}

export function org(ctx: Ctx, real: string): string {
  const fake = pick(ctx, "org", pools().orgs);
  const m = ORG_SUFFIX.exec(real);
  return m ? `${fake} ${m[1]}${m[2]}` : fake;
}

export function location(ctx: Ctx, _real: string): string {
  return pick(ctx, "city", pools().cities);
}

export function address(ctx: Ctx, real: string): string {
  const m = ADDRESS_PARTS.exec(real);
  const street = pick(ctx, "street", pools().streets);
  if (!m) return `${1 + ctx.vault.drbg.below("addr.num", 999)} ${street} St`;
  const width = m[1].length;
  const low = width > 1 ? 10 ** (width - 1) : 1;
  const number = low + ctx.vault.drbg.below("addr.num", 10 ** width - low);
  const letter = m[2] ? chars(ctx, "addr.num", UPPER, 1) : "";
  const unit = shape(ctx, m[6], "addr.unit");
  return `${number}${letter} ${street} ${m[4]}${m[5]}${unit}`;
}

// Contact details

/** Map a host to a fake one. The registrable part maps consistently; generic subdomains stay. */
export function domain(ctx: Ctx, host: string): string {
  host = host.toLowerCase().replace(/\.+$/, "");
  const reg = registrable(host);
  let fakeReg = ctx.vault.domains.get(reg);
  if (fakeReg === undefined) {
    fakeReg = pick(ctx, "domain", pools().domain_words) + ".example";
    ctx.vault.domains.set(reg, fakeReg);
    ctx.vault.used.add(fakeReg);
    ctx.vault.touch();
  }
  const sub = (reg.length === 0 ? "" : host.slice(0, host.length - reg.length)).replace(/\.+$/, "");
  if (!sub) return fakeReg;
  const labels = sub.split(".").map((lab) => (GENERIC_SUBDOMAINS.has(lab) ? lab : shape(ctx, lab, "subdomain")));
  return labels.join(".") + "." + fakeReg;
}

export function email(ctx: Ctx, real: string, onPerson?: (fullName: string) => void): string {
  const at = real.lastIndexOf("@");
  const local = at >= 0 ? real.slice(0, at) : "";
  const host = at >= 0 ? real.slice(at + 1) : real;
  const runs = local.match(/[A-Za-z]+|[0-9]+|[^A-Za-z0-9]/gu) ?? [];
  const alpha = runs.filter((r) => isAlphaChar(r));
  if (alpha.length >= 2 && pools().name_gender.has(alpha[0].toLowerCase()) && alpha.every((a) => [...a].length >= 2)) {
    // first.last style: the local part is a name, so give it the same fake name as the person
    const full = alpha.map(capitalize).join(" ");
    if (onPerson) onPerson(full);
    else person(new Ctx(ctx.vault, ctx.text, {}), full);
  }
  const out: string[] = [];
  for (const r of runs) {
    if (isAlphaChar(r)) {
      const key = r.toLowerCase();
      const part = ctx.vault.parts.get(key);
      if (part !== undefined) out.push(styled(part, r));
      else if (GENERIC_MAILBOXES.has(key)) out.push(r);
      else if ([...r].length === 1) out.push(styled(chars(ctx, "letter", LOWER, 1), r));
      else out.push(styled(pick(ctx, "mailbox", pools().last_names).toLowerCase(), r));
    } else if (isDigitChar(r)) {
      out.push(chars(ctx, "digits", DIGITS, [...r].length));
    } else {
      out.push(r);
    }
  }
  const body = out.join("");
  let fake = body + "@" + domain(ctx, host);
  for (let i = 0; i < 100; i++) {
    if (ctx.free(fake)) return fake;
    fake = body + chars(ctx, "digits", DIGITS, 1) + "@" + domain(ctx, host);
  }
  throw new Error("could not make a free fake email address");
}

export function phone(ctx: Ctx, real: string): string {
  const d = digitsOf(real);
  if (d.length === 10 || (d.length === 11 && d[0] === "1")) {
    const area = ctx.options.keep_region ? d.slice(-10, -7) : null;
    for (let i = 0; i < 500; i++) {
      const a = area || AREA_CODES[ctx.vault.drbg.below("phone.area", AREA_CODES.length)];
      const line = a + "55501" + chars(ctx, "phone.line", DIGITS, 2); // 555-0100..0199 is set aside for fiction
      const created = (d.length === 11 ? "1" : "") + line;
      const candidate = fillTemplate(real, created);
      if (ctx.free(candidate) && !ctx.vault.used.has(created)) {
        ctx.vault.used.add(created);
        return candidate;
      }
    }
    throw new Error("ran out of fictional phone numbers");
  }
  const uk = (d.startsWith("44") && d.length === 12) || (d.startsWith("07") && d.length === 11);
  for (let i = 0; i < 500; i++) {
    let created: string;
    if (uk) {
      // UK: Ofcom keeps 07700 900000-900999 (mobile) and 020 7946 0000-0999 (London) for drama
      const national = d.startsWith("44") ? d.slice(2) : d.slice(1);
      const body = (national.startsWith("7") ? "7700900" : "2079460") + chars(ctx, "phone.line", DIGITS, 3);
      created = (d.startsWith("44") ? "44" : "0") + body;
    } else {
      // elsewhere there is no reserved range we can rely on; keep the country code, randomise the rest
      const keep = lstripWs(real).startsWith("+") ? 2 : 0;
      created = d.slice(0, keep) + chars(ctx, "phone.line", DIGITS, d.length - keep);
    }
    const candidate = fillTemplate(real, created);
    if (created !== d && ctx.free(candidate) && !ctx.vault.used.has(created)) {
      ctx.vault.used.add(created);
      return candidate;
    }
  }
  throw new Error("ran out of fake phone numbers");
}

export function url(ctx: Ctx, real: string): string {
  const m = URL_PARTS.exec(real);
  if (!m) return shape(ctx, real);
  const restTokens = m[4].match(/[A-Za-z0-9]+|[^A-Za-z0-9]/gu) ?? [];
  const out: string[] = [];
  let afterEquals = false;
  const nameParts = [...ctx.vault.parts.keys()].filter((p) => [...p].length >= 3);
  for (const tok of restTokens) {
    const low = tok.toLowerCase();
    // a slug like /in/danareyes carries a name even without separators, so look inside each piece
    const interesting = afterEquals || [...tok].length >= 12 || [...tok].some(isDigitChar) ||
      nameParts.some((part) => low.includes(part));
    out.push(isAlnumChar(tok) && interesting ? shape(ctx, tok, "url") : tok);
    afterEquals = tok === "=";
  }
  return m[1] + domain(ctx, m[2]) + (m[3] ?? "") + out.join("");
}

export function ipAddress(ctx: Ctx, _real: string): string {
  for (let i = 0; i < 2000; i++) {
    const n = ctx.vault.drbg.below("ip", 3 * 254);
    const candidate = TEST_NETS[Math.floor(n / 254)] + String((n % 254) + 1);
    if (ctx.free(candidate)) return candidate;
  }
  throw new Error("ran out of documentation IP addresses");
}

// Money and secrets

export function card(ctx: Ctx, real: string): string {
  const d = digitsOf(real);
  const pool = pools().test_cards.filter((c) => c.length === d.length && c !== d && !ctx.vault.used.has(c));
  let created: string;
  if (pool.length > 0) {
    created = pool[ctx.vault.drbg.below("card", pool.length)];
  } else {
    // 0000... is not a real issuer prefix, so this can never charge anyone
    const body = "0000" + chars(ctx, "card", DIGITS, d.length - 5);
    created = body + checks.luhnDigit(body);
  }
  ctx.vault.used.add(created);
  return fillTemplate(real, created);
}

export function iban(ctx: Ctx, real: string): string {
  const s = splitWs(real).join("").toUpperCase();
  let created: string;
  for (;;) {
    let bban = "";
    for (const c of s.slice(4)) bban += isAlphaChar(c) ? chars(ctx, "iban", UPPER, 1) : chars(ctx, "iban", DIGITS, 1);
    const check = 98 - Number(checks.ibanNumeric(s.slice(0, 2) + "00" + bban) % 97n);
    created = `${s.slice(0, 2)}${String(check).padStart(2, "0")}${bban}`;
    if (created !== s) break;
  }
  if (real.includes(" ")) return created.match(/.{1,4}/gsu)!.join(" ");
  return created;
}

export function routing(ctx: Ctx, real: string): string {
  for (;;) {
    const body = "0000" + chars(ctx, "routing", DIGITS, 4);
    const last = [...DIGITS].find((d) => checks.abaSum(body + d) % 10 === 0)!;
    const created = body + last;
    if (created !== digitsOf(real)) return fillTemplate(real, created);
  }
}

export function ssn(ctx: Ctx, real: string): string {
  const d = digitsOf(real);
  const free = pools().advertising_ssns.map((a) => a.replaceAll("-", "")).filter((x) => !ctx.vault.used.has(x) && x !== d);
  // area 000 is never issued, so the fallback cannot belong to anyone
  const created = free.length > 0 ? free[ctx.vault.drbg.below("ssn", free.length)] : "000" + chars(ctx, "ssn", DIGITS, 6);
  ctx.vault.used.add(created);
  return fillTemplate(real, created);
}

export function apiKey(ctx: Ctx, real: string): string {
  if (real.startsWith("-----BEGIN")) {
    return real.split("\n").map((line) => (line.startsWith("-----") ? line : shape(ctx, line, "key"))).join("\n");
  }
  if (real.startsWith("eyJ") && real.split(".").length === 3) {
    return real.split(".").map((p) => (p.startsWith("eyJ") ? p.slice(0, 3) + shape(ctx, p.slice(3), "key") : shape(ctx, p, "key"))).join(".");
  }
  for (const prefix of KEY_PREFIXES) {
    if (real.startsWith(prefix)) return prefix + shape(ctx, real.slice(prefix.length), "key");
  }
  return shape(ctx, real, "key");
}

export function secretShape(ctx: Ctx, real: string, label: string): string {
  for (let i = 0; i < 100; i++) {
    const fake = shape(ctx, real, label);
    if (fake !== real) return fake;
  }
  throw new Error("could not make a different value");
}

type Maker = (ctx: Ctx, real: string) => string;

const MAKERS = new Map<string, Maker>([
  ["PERSON", person],
  ["ORG", org],
  ["LOCATION", location],
  ["ADDRESS", address],
  ["EMAIL", (ctx, real) => email(ctx, real)],
  ["PHONE", phone],
  ["URL", url],
  ["IP_ADDRESS", ipAddress],
  ["CARD", card],
  ["IBAN", iban],
  ["ROUTING", routing],
  ["SSN", ssn],
  ["API_KEY", apiKey],
]);

/** A fake for any type except DATE and MONEY, which the session handles (they shift or scale). */
export function make(type: string, ctx: Ctx, real: string): string {
  const maker = MAKERS.get(type);
  if (maker !== undefined) return maker(ctx, real);
  return secretShape(ctx, real, type.toLowerCase());
}
