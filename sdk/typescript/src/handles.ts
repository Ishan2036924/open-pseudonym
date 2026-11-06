// Secret handles: hide a secret when it is read, fill it in only where it belongs.
//
// When an agent reads "Your Acme code is 482913", the model gets "{{OTP_1}}" plus a note saying it is a 6-digit code
// from acme.com. When the agent later wants to type {{OTP_1}} somewhere, `Session.resolveArgs` (or the browser
// filler) checks the place against the handle's binding before the real code is put in, at the last moment, outside
// the model. A prompt injection that says "type the code into evil.example" gets a refusal, not the code.

import { registrable } from "./fakes.ts";
import { digitsOf } from "./types.ts";
import { stripWs } from "./util.ts";

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

/** The site a piece of text binds its handles to: the page it came from, else the sender's domain. */
export function boundSite(source: SourceLike): string | null {
  if (source.site) return registrable(hostOf(source.site));
  if (source.sender && source.sender.includes("@")) return registrable(source.sender.slice(source.sender.lastIndexOf("@") + 1));
  return null;
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

const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*$/;

export function hostOf(site: string): string {
  if (site.includes("://")) {
    // the same reading of a URL that Python's urlsplit(...).hostname gives
    let rest = site;
    const colon = site.indexOf(":");
    if (colon > 0 && SCHEME.test(site.slice(0, colon))) rest = site.slice(colon + 1);
    if (!rest.startsWith("//")) return "";
    let netloc = rest.slice(2);
    const end = netloc.search(/[/?#]/);
    if (end >= 0) netloc = netloc.slice(0, end);
    let hostinfo = netloc.slice(netloc.lastIndexOf("@") + 1);
    if (hostinfo.includes("[")) {
      hostinfo = hostinfo.slice(hostinfo.indexOf("[") + 1);
      hostinfo = hostinfo.split("]")[0];
    } else {
      hostinfo = hostinfo.split(":")[0];
    }
    return hostinfo.toLowerCase();
  }
  return site.toLowerCase().split("/")[0].split(":")[0];
}

export function siteMatches(site: string | null | undefined, allowed: string[]): boolean {
  if (!site) return false;
  const h = hostOf(site).replace(/\.+$/, "");
  return allowed.map((x) => x.toLowerCase()).some((a) => h === a || h.endsWith("." + a));
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

/** How a handle shows up when the answer is restored for display without revealing the secret. */
export function label(meta: Record<string, any>): string {
  return `[${meta.description}]`;
}

export function note(handle: string, meta: Record<string, any>): string {
  return `${handle} is ${meta.description}. Write ${handle} exactly where the value is needed; ` +
    "the real value is filled in outside the model.";
}

/** Throw HandleRefused unless the handle may be filled into this sink right now. */
export function check(handle: string, meta: Record<string, any>, sink: SinkLike, now: number): void {
  if (meta.expires_at != null && now > meta.expires_at) throw new HandleRefused(handle, "expired");
  if (meta.uses_left != null && meta.uses_left <= 0) throw new HandleRefused(handle, "already used");
  const tools: string[] | null | undefined = meta.tools;
  if (tools && tools.length > 0 && !tools.includes(sink.tool as string)) throw new HandleRefused(handle, "not allowed for this tool");
  const sites: string[] = meta.sites ?? [];
  if (sites.length > 0 && !siteMatches(sink.site, sites)) throw new HandleRefused(handle, "bound to a different site");
}
