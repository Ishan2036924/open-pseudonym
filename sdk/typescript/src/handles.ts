// Secret handles: hide a secret when it is read, fill it in only where it belongs.
//
// When an agent reads "Your Acme code is 482913", the model gets "{{OTP_1}}" plus a note saying it is a 6-digit code
// from acme.com. When the agent later wants to type {{OTP_1}} somewhere, `Session.resolveArgs` (or the browser
// filler) checks the place against the handle's binding before the real code is put in, at the last moment, outside
// the model. A prompt injection that says "type the code into evil.example" gets a refusal, not the code.

import { isPublicSuffix } from "./fakes.ts";
import { digitsOf } from "./types.ts";
import { stripWs, truthy } from "./util.ts";

export const HANDLE = /\{\{([A-Z][A-Z0-9_]*_[0-9]+)\}\}/gu;

/**
 * Stable codes for every way a handle can be refused. The human text of `reason` may be reworded one day; a code
 * never is, so an app and a release record (spec 10.4) can rely on it.
 */
export const CODES = [
  "unknown_handle", "unbound", "expired", "used_up", "wrong_tool", "wrong_site", "needs_approval", "not_approved",
  "not_recorded",
] as const;

export type RefusalCode = (typeof CODES)[number];

/**
 * The real value was not filled in. `reason` is one short phrase, safe to show and to log; `code` is the stable name
 * of the reason (one of CODES), or null for a refusal that is not a release decision.
 */
export class HandleRefused extends Error {
  readonly handle: string;
  readonly reason: string;
  readonly code: RefusalCode | null;

  constructor(handle: string, reason: string, code: RefusalCode | null = null) {
    super(`${handle}: ${reason}`);
    this.name = "HandleRefused";
    this.handle = handle;
    this.reason = reason;
    this.code = code;
  }
}

/**
 * What an approval callback may return instead of a plain true or false, so the release record can say who allowed
 * the release. `ref` and `digest` let an app pass the id and the token digest of an OAC Consent.
 */
export interface Approval {
  allowed: boolean;
  by?: string | null;
  channel?: string | null;
  ref?: string | null;
  digest?: string | null;
}

export const DIGEST = /^sha-256:[A-Za-z0-9_-]{43}$/u;

/**
 * Turn what an approval callback returned (a boolean or an Approval) into an Approval. Anything else is a bug in the
 * app and throws, so nothing is filled by accident.
 */
export function asApproval(answer: unknown): Required<Approval> {
  let found: Approval;
  if (typeof answer === "boolean") found = { allowed: answer };
  else if (answer !== null && typeof answer === "object" && typeof (answer as Approval).allowed === "boolean") found = answer as Approval;
  else throw new TypeError("an approval callback returns a boolean or an Approval");
  for (const name of ["by", "channel", "ref"] as const) {
    const v = found[name];
    if (v != null && (typeof v !== "string" || v.length === 0 || v.length > 256)) throw new RangeError(`Approval.${name} must be a short string`);
  }
  if (found.digest != null && !(typeof found.digest === "string" && DIGEST.test(found.digest))) {
    throw new RangeError("Approval.digest must look like sha-256:<43 characters>");
  }
  return {
    allowed: found.allowed, by: found.by ?? null, channel: found.channel ?? null, ref: found.ref ?? null,
    digest: found.digest ?? null,
  };
}

// Sensitive References (spec 10.5) are opaque to this SDK: a server keeps the value, the model only carries the
// reference. They look like `sref:<kind>:<id>` or `⟦sref:<kind>:<id>⟧` (kind 1 to 32, id 20 to 128 characters of
// letters, digits, "_" and "-"). We never mask one, never make a stand-in for one, never restore or fill one, and never
// count one as a leak.
const SREF_BODY = "sref:[A-Za-z0-9_-]{1,32}:[A-Za-z0-9_-]{20,128}";
export const SREF = new RegExp(`\\u27e6${SREF_BODY}\\u27e7|(?<![A-Za-z0-9_-])${SREF_BODY}(?![A-Za-z0-9_-])`, "gu");

/** Where the sensitive references in `text` are, as [start, end] pairs of UTF-16 offsets. */
export function srefRegions(text: string): [number, number][] {
  return [...text.matchAll(SREF)].map((m) => [m.index, m.index + m[0].length] as [number, number]);
}

/** Drop everything that touches a sensitive reference. `start` and `end` are UTF-16 offsets into `text`. */
export function outsideSrefs<T extends { start: number; end: number }>(items: T[], text: string): T[] {
  const regions = srefRegions(text);
  if (regions.length === 0) return items;
  return items.filter((it) => !regions.some(([b, e]) => it.start < e && it.end > b));
}

export interface SourceLike {
  sender?: string | null;
  site?: string | null;
}

export interface SinkLike {
  tool?: string | null;
  site?: string | null;
}

/**
 * The exact host a secret from this source may be filled on, the way WebOTP binds a code to one origin. A code
 * mailed by no-reply@acme.com fills on acme.com, not on docs.acme.com, where anyone may host a form.
 */
export function boundSite(source: SourceLike): string | null {
  let host: string;
  if (source.site) host = hostOf(source.site);
  else if (source.sender && source.sender.includes("@")) host = source.sender.slice(source.sender.lastIndexOf("@") + 1).toLowerCase().replace(/\.+$/, "");
  else return null;
  // a bare shared suffix (github.io) belongs to everyone under it, so it is no binding at all
  return host === "" || isPublicSuffix(host) ? null : host;
}

/**
 * Where a piece of text came from. The app fills this in from facts it trusts, never from the model.
 *
 * sender: the verified sender address of an email or message (a DKIM-checked From, say)
 * site:   the page or service the text was read from
 */
export class Source implements SourceLike {
  readonly sender: string | null;
  readonly site: string | null;

  constructor(o: SourceLike = {}) {
    this.sender = o.sender ?? null;
    this.site = o.site ?? null;
  }

  boundSite(): string | null {
    return boundSite(this);
  }
}

/**
 * Where a value is about to go: the tool being called and, if known, the site it acts on.
 *
 * Again the app sets this (from the browser's real URL, or the tool's fixed target), never the model.
 */
export class Sink implements SinkLike {
  readonly tool: string | null;
  readonly site: string | null;

  constructor(o: SinkLike = {}) {
    this.tool = o.tool ?? null;
    this.site = o.site ?? null;
  }
}

const SCHEME_CHARS = /^[A-Za-z0-9+.-]*$/;
const HEX = /^[0-9A-Fa-f]+$/;
const DECIMAL = /^[0-9]+$/;

// what Python's ipaddress.IPv4Address accepts: four plain decimal numbers up to 255, no leading zeros
function isIPv4(s: string): boolean {
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => p.length >= 1 && p.length <= 3 && DECIMAL.test(p) && !(p.length > 1 && p[0] === "0") && Number(p) <= 255);
}

// what Python's ipaddress.IPv6Address accepts, including a %scope id
function isIPv6(text: string): boolean {
  if (text.includes("/")) return false;
  const pct = text.indexOf("%");
  let addr = text;
  if (pct >= 0) {
    const scope = text.slice(pct + 1);
    if (scope === "" || scope.includes("%")) return false;
    addr = text.slice(0, pct);
  }
  const parts = addr.split(":");
  if (parts.length < 3) return false;
  if (parts[parts.length - 1].includes(".")) {
    if (!isIPv4(parts[parts.length - 1])) return false;
    parts.splice(parts.length - 1, 1, "0", "0");
  }
  if (parts.length > 9) return false;
  let skip = -1;
  for (let i = 1; i < parts.length - 1; i++) {
    if (parts[i] === "") {
      if (skip >= 0) return false; // only one "::"
      skip = i;
    }
  }
  let hi = parts.length;
  let lo = 0;
  if (skip >= 0) {
    hi = skip;
    lo = parts.length - skip - 1;
    if (parts[0] === "" && --hi > 0) return false; // a leading colon needs "::"
    if (parts[parts.length - 1] === "" && --lo > 0) return false; // a trailing colon needs "::"
    if (8 - (hi + lo) < 1) return false;
  } else if (parts.length !== 8 || parts[0] === "" || parts[parts.length - 1] === "") {
    return false;
  }
  const checked = [...parts.slice(0, hi), ...(lo > 0 ? parts.slice(-lo) : [])];
  return checked.every((h) => h.length <= 4 && HEX.test(h));
}

// urlsplit refuses a bracketed host that is not an IPv6 address (or an IPvFuture literal)
function bracketedHostOk(h: string): boolean {
  if (h.startsWith("v")) return /^v[a-fA-F0-9]+\..+$/s.test(h);
  return isIPv6(h);
}

// the checks Python's urlsplit makes on a netloc before it hands out a hostname; true means it raises ValueError
function netlocRejected(netloc: string): boolean {
  const open = netloc.includes("[");
  const close = netloc.includes("]");
  if (open !== close) return true;
  if (open) {
    const hostAndPort = netloc.slice(netloc.lastIndexOf("@") + 1);
    const at = hostAndPort.indexOf("[");
    let hostname: string;
    if (at >= 0) {
      if (at > 0) return true; // nothing may stand before the bracket
      const bracketed = hostAndPort.slice(at + 1);
      const end = bracketed.indexOf("]");
      hostname = end >= 0 ? bracketed.slice(0, end) : bracketed;
      const port = end >= 0 ? bracketed.slice(end + 1) : "";
      if (port !== "" && !port.startsWith(":")) return true; // nor between the bracket and the port
    } else {
      hostname = hostAndPort.split(":")[0];
    }
    if (!bracketedHostOk(hostname)) return true;
  }
  if (netloc !== "" && !/^[\u0000-\u007f]*$/.test(netloc)) {
    // looking for characters that expand to a separator once normalised, as hostnames are
    const n = netloc.replaceAll("@", "").replaceAll(":", "").replaceAll("#", "").replaceAll("?", "");
    const n2 = n.normalize("NFKC");
    if (n !== n2 && [..."/?#@:"].some((c) => n2.includes(c))) return true;
  }
  return false;
}

/**
 * The host a browser would go to. Browsers read a backslash like a slash in web URLs, so we do too:
 * https://evil.example\@acme.com/ goes to evil.example, never to acme.com. An address the parser rejects goes
 * nowhere, so it gives the empty host.
 */
export function hostOf(site: string): string {
  site = stripWs(site).replaceAll("\\", "/");
  if (site.includes("://")) {
    // the same reading of a URL that Python's urlsplit(...).hostname gives
    let rest = site.replace(/^[\u0000-\u0020]+/, "").replace(/[\t\r\n]/g, "");
    const colon = rest.indexOf(":");
    if (colon > 0 && /^[A-Za-z]/.test(rest) && SCHEME_CHARS.test(rest.slice(0, colon))) rest = rest.slice(colon + 1);
    if (!rest.startsWith("//")) return "";
    let netloc = rest.slice(2);
    const end = netloc.search(/[/?#]/);
    if (end >= 0) netloc = netloc.slice(0, end);
    if (netlocRejected(netloc)) return "";
    let hostinfo = netloc.slice(netloc.lastIndexOf("@") + 1);
    if (hostinfo.includes("[")) {
      hostinfo = hostinfo.slice(hostinfo.indexOf("[") + 1);
      hostinfo = hostinfo.split("]")[0];
    } else {
      hostinfo = hostinfo.split(":")[0];
    }
    return hostinfo.toLowerCase();
  }
  return site.toLowerCase().split("/")[0].split("@").at(-1)!.split(":")[0];
}

/**
 * Exact host match. An entry written as *.acme.com also allows every subdomain of acme.com (and acme.com); a policy
 * says that on purpose, it is never inferred.
 */
export function siteMatches(site: string | null | undefined, allowed: string[]): boolean {
  if (!site) return false;
  const h = hostOf(site).replace(/\.+$/, "");
  for (const a of allowed.map((x) => x.toLowerCase().replace(/\.+$/, ""))) {
    if (a.startsWith("*.")) {
      if (h === a.slice(2) || h.endsWith(a.slice(1))) return true;
    } else if (h === a) {
      return true;
    }
  }
  return false;
}

const EXPIRY = /(?:expires?|valid|good) (?:in|for) ([0-9]{1,3}) ?(min|mins|minute|minutes|hour|hours|hr|hrs)/iu;

export function ttlFromText(text: string): number | null {
  const m = EXPIRY.exec(text);
  if (!m) return null;
  const n = Number(m[1]);
  return m[2].toLowerCase().startsWith("h") ? n * 3600 : n * 60;
}

export function cardBrand(digits: string): string {
  if (digits.startsWith("4")) return "Visa";
  const two = digits.slice(0, 2);
  if (two === "34" || two === "37") return "American Express";
  if ((two >= "51" && two <= "55") || (digits.slice(0, 4) >= "2221" && digits.slice(0, 4) <= "2720")) return "Mastercard";
  if (digits.startsWith("6011") || digits.startsWith("65")) return "Discover";
  return "payment";
}

function hhmmUtc(epochSeconds: number): string {
  const d = new Date(epochSeconds * 1000);
  return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
}

/** What the model is told about a handle: enough to do the task, nothing it could misuse. */
export function describe(type: string, real: string, site: string | null, expiresAt: number | null): string {
  const d = digitsOf(real);
  const where = site ? ` from ${site}` : "";
  if (type === "OTP") {
    const until = expiresAt !== null ? `, valid until ${hhmmUtc(expiresAt)} UTC` : "";
    return `a ${d.length}-digit one-time code${where}${until}`;
  }
  if (type === "PASSWORD") return site ? `a password for ${site}` : "a password";
  if (type === "CARD") return `a ${cardBrand(d)} card ending ${d.slice(-4)}`;
  if (type === "IBAN") {
    return `a bank account (IBAN, ${stripWs(real).slice(0, 2).toUpperCase()}) ending ${real.replaceAll(" ", "").slice(-4)}`;
  }
  if (type === "BANK_ACCOUNT") return `a bank account number ending ${d.slice(-4)}`;
  if (type === "ROUTING") return "a bank routing number";
  if (type === "SSN") return "a social security number";
  if (type === "API_KEY") return "an API key";
  return `a ${type.toLowerCase().replaceAll("_", " ")} value`;
}

export function note(handle: string, meta: Record<string, any>): string {
  return `${handle} is ${meta.description}. Write ${handle} exactly where the value is needed; ` +
    "the real value is filled in outside the model.";
}

/** Throw HandleRefused unless the handle may be filled into this sink right now. */
export function check(handle: string, meta: Record<string, any>, sink: SinkLike, now: number): void {
  if (!truthy(meta.sites) && !truthy(meta.tools)) {
    // fail closed: a handle that nobody bound to a site or a tool could otherwise go anywhere
    throw new HandleRefused(handle, "not bound to a site or tool", "unbound");
  }
  if (meta.expires_at != null && now >= meta.expires_at) throw new HandleRefused(handle, "expired", "expired"); // gone at its expiry second
  if (meta.uses_left != null && meta.uses_left <= 0) throw new HandleRefused(handle, "already used", "used_up");
  const tools: string[] | null | undefined = meta.tools;
  if (tools && tools.length > 0 && !tools.includes(sink.tool as string)) throw new HandleRefused(handle, "not allowed for this tool", "wrong_tool");
  const sites: string[] = meta.sites ?? [];
  if (sites.length > 0 && !siteMatches(sink.site, sites)) throw new HandleRefused(handle, "bound to a different site", "wrong_site");
}
