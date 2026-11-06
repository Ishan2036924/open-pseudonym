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

/** The real value was not filled in. `reason` is one short phrase, safe to show and to log. */
export class HandleRefused extends Error {
  readonly handle: string;
  readonly reason: string;

  constructor(handle: string, reason: string) {
    super(`${handle}: ${reason}`);
    this.name = "HandleRefused";
    this.handle = handle;
    this.reason = reason;
  }
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
    throw new HandleRefused(handle, "not bound to a site or tool");
  }
  if (meta.expires_at != null && now >= meta.expires_at) throw new HandleRefused(handle, "expired"); // gone at its expiry second
  if (meta.uses_left != null && meta.uses_left <= 0) throw new HandleRefused(handle, "already used");
  const tools: string[] | null | undefined = meta.tools;
  if (tools && tools.length > 0 && !tools.includes(sink.tool as string)) throw new HandleRefused(handle, "not allowed for this tool");
  const sites: string[] = meta.sites ?? [];
  if (sites.length > 0 && !siteMatches(sink.site, sites)) throw new HandleRefused(handle, "bound to a different site");
}
