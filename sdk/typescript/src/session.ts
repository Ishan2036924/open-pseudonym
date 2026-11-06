// The session: one conversation, task or batch, with one policy and one vault.
//
//     const s = new Session("draft_reply");
//     const masked = s.mask(emailText, new Source({ sender: "no-reply@acme.com" }));
//     const answer = await callYourModel(masked.text, masked.notes);
//     console.log(s.restore(answer));
//
// Everything the model sees goes through `mask`; everything it says comes back through `restore`, `stream` or
// `resolveArgs`. The vault stays here.

import { createHmac, randomUUID } from "node:crypto";
import { abaOk, luhnOk, ssnOk } from "./checks.ts";
import { pools } from "./data.ts";
import * as dates from "./dates.ts";
import { check as egressCheck, EgressLeak, EgressLog, knownMode, type Leak } from "./egress.ts";
import * as fakes from "./fakes.ts";
import { Ctx, fillTemplate } from "./fakes.ts";
import { FF1 } from "./fpe.ts";
import * as handles from "./handles.ts";
import { HANDLE, HandleRefused, type SinkLike, type SourceLike } from "./handles.ts";
import { KnownDetector, PatternDetector, resolve, type Detector, type Form, type Span } from "./detect.ts";
import type { PatternSpec } from "./data.ts";
import { Policy, loadProfile, type Rule } from "./policy.ts";
import { apply, Restorer, StreamRestorer } from "./restore.ts";
import { DIGIT_TYPES, digitsOf, normalize } from "./types.ts";
import { Vault, type Entry } from "./vault.ts";
import { cpLength, findAll, lenientBase64, splitWs, stripWs, toJson, truthy, WS } from "./util.ts";

const MAX_TEXT_TTL = 3600; // an expiry read from text alone is capped at one hour
const GENERAL: Record<string, string> = {
  PERSON: "someone", ORG: "an organization", LOCATION: "a place", ADDRESS: "a street address",
  EMAIL: "an email address", PHONE: "a phone number", URL: "a web link", IP_ADDRESS: "an IP address",
};
const MONEY_PREFIX = /^([$€£])( ?)([0-9][0-9,]*)(\.[0-9]{2})?$/;
const MONEY_SUFFIX = /^([0-9][0-9,]*)(\.[0-9]{2})?( ?)(USD|EUR|GBP|dollars|euros)$/;
// Keys whose string values must reach the provider exactly as written, or the protocol breaks: ids that come back,
// roles, the model name, media types, and signed or encrypted blobs. Masking leaves them alone; the egress check still
// reads them, so personal data hidden under one of these names stops the request instead of slipping out.
const SKIP_KEYS: ReadonlySet<string> = new Set([
  "role", "type", "id", "tool_call_id", "tool_use_id", "call_id", "media_type", "mime_type", "mimeType",
  "cache_control",
  // the same structure as the Vercel AI SDK spells it
  "toolCallId", "toolName", "mediaType",
]);
// Only at the top of a request body: the model name.
const TOP_KEYS: ReadonlySet<string> = new Set(["model"]);
const REASONING_TYPES: ReadonlySet<string> = new Set(["thinking", "redacted_thinking", "reasoning"]);
const NO_KEYS: ReadonlySet<string> = new Set();
// [A-Za-z0-9+/=_\-\s] with \s meaning what Python's \s does
const BASE64 = new RegExp(`^[A-Za-z0-9+/=_\\-${WS}]*$`, "u");

/** Real base64 payloads (images, PDFs) are not text we can mask; leave them byte for byte. Only strings that really
 * are base64 count, so text dressed up as a data: URL is still masked and checked. */
export function isBinary(key: string | null, value: string, parent: Record<string, any> | null): boolean {
  if (value.startsWith("data:") && [...value.slice(0, 200)].slice(0, 100).join("").includes(";base64,")) {
    return BASE64.test(value.slice(value.indexOf(";base64,") + ";base64,".length));
  }
  if (key === "data" && parent !== null && parent.type === "base64") return BASE64.test(value);
  return false;
}

/** Model reasoning blocks are signed or encrypted by the provider and must go back unchanged. The model only ever
 * saw stand-ins, so they hold stand-ins, never real values. Only inside such a block: a `signature` key anywhere
 * else is ordinary content. */
export function isSignedThinking(key: string | null, parent: Record<string, any> | null): boolean {
  if (parent === null || typeof parent.type !== "string" || !REASONING_TYPES.has(parent.type)) return false;
  return key === "thinking" || key === "signature" || key === "encrypted_content" || (key === "data" && parent.type === "redacted_thinking");
}

// Python's truthiness, where a parsed JSON number may arrive wrapped (see JsonNumber below)
const pyTruthy = (x: unknown): boolean => (x instanceof JsonNumber ? x.value !== 0 : truthy(x));

const TEXT_MEDIA = /^(text\/|application\/(json|xml|csv|x-yaml|yaml))/iu;

/** Base64 that holds text (a data:text/plain URL, a text document sent as base64): returns [prefix, media type,
 * decoded text] so it can be masked and checked like any text. Null for real binary such as images and PDFs. */
export function textBase64(key: string | null, value: string, parent: Record<string, any> | null): [string, string, string] | null {
  let head: string | null;
  let body: string;
  let media: unknown;
  if (value.startsWith("data:") && [...value.slice(0, 200)].slice(0, 100).join("").includes(";base64,")) {
    const at = value.indexOf(";base64,");
    head = value.slice(0, at);
    body = value.slice(at + ";base64,".length);
    media = head.slice(5);
  } else if (key === "data" && parent !== null && parent.type === "base64") {
    head = null;
    body = value;
    media = pyTruthy(parent.media_type) ? parent.media_type : pyTruthy(parent.mediaType) ? parent.mediaType : "";
  } else {
    return null;
  }
  // Python's case-insensitive match also treats the dotless and dotted capital I as an i
  if (typeof media !== "string" || !TEXT_MEDIA.test(media.replace(/[\u0131\u0130]/g, "i"))) return null;
  const bytes = lenientBase64(body);
  if (bytes === null) return null;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
  return [head !== null ? head + ";base64," : "", media, text];
}

// a JSON number that remembers the digits it was written with, so a long card number is not rounded away
class JsonNumber {
  readonly source: string;
  readonly value: number;

  constructor(source: string, value: number) {
    this.source = source;
    this.value = value;
  }
}

/**
 * Everything in a payload a person could have written, as text, for the detection pass: for JSON every key and every
 * string except the top-level model name, signed or encrypted reasoning and real binary base64 (text sent as base64
 * is decoded and read). Plain text is used as is.
 */
export function contentText(payload: Uint8Array | string): string {
  const raw = typeof payload === "string" ? payload : new TextDecoder("utf-8", { ignoreBOM: true }).decode(payload);
  let doc: unknown;
  try {
    const reviver = (_key: string, value: unknown, ctx?: { source?: string }): unknown =>
      typeof value === "number" && ctx?.source !== undefined ? new JsonNumber(ctx.source, value) : value;
    doc = (JSON.parse as (text: string, reviver: unknown) => unknown)(raw, reviver);
  } catch {
    return raw;
  }
  const out: string[] = [];
  const stack: [unknown, string | null, Record<string, any> | null][] = [[doc, null, null]];
  while (stack.length > 0) { // a loop, not recursion, so deeply nested JSON cannot crash the check
    const [v, key, parent] = stack.pop()!;
    if (typeof v === "string") {
      if ((key !== null && TOP_KEYS.has(key) && parent === doc) || isSignedThinking(key, parent)) continue;
      const decoded = textBase64(key, v, parent);
      if (decoded !== null) out.push(decoded[2]);
      else if (!isBinary(key, v, parent)) out.push(v);
    } else if (Array.isArray(v)) {
      for (const x of v) stack.push([x, key, parent]);
    } else if (v instanceof JsonNumber) {
      out.push(/^-?[0-9]+$/.test(v.source) ? BigInt(v.source).toString() : String(v.value));
    } else if (v !== null && typeof v === "object") {
      for (const [k, x] of Object.entries(v)) {
        out.push(k);
        stack.push([x, k, v as Record<string, any>]);
      }
    }
  }
  return out.join("\n");
}

/** The policy says this type must never reach the model, so the request stops here. */
export class RefusedData extends Error {
  readonly type: string;

  constructor(type: string) {
    super(`the policy refuses to send ${type} data`);
    this.name = "RefusedData";
    this.type = type;
  }
}

export interface Replacement {
  start: number;
  end: number;
  type: string;
  action: string;
  standIn: string;
  entryId: string;
}

export interface Masked {
  text: string;
  replacements: Replacement[];
  notes: string[];
}

export interface Resolved {
  args: any;
  report: Record<string, any>[];
}

export type Approve = (handle: string, description: string, sink: SinkLike) => boolean;

export interface SessionOptions {
  vault?: Vault;
  /** Values the app already knows are personal, by type (contacts, the user's own company). */
  known?: Record<string, Iterable<string>>;
  /** Text that may stay visible even though a detector flags it (compared in lower case). */
  allow?: Iterable<string>;
  /** Extra detectors with a `detect(text)` method. */
  detectors?: Iterable<Detector>;
  extraPatterns?: Iterable<PatternSpec>;
  dayfirst?: boolean;
  /** Seconds since the epoch; tests pin it so dates and expiry times are repeatable. */
  clock?: () => number;
  /** Asked before a handle is filled in somewhere new (or always, when the rule says `ask`). */
  approve?: Approve;
  sessionId?: string;
  /**
   * By default every input is treated as real: a real name that happens to equal an earlier fake is masked like any
   * other value. Set this to true only if you feed back text that already went through `mask`.
   */
  maskedInput?: boolean;
}

export class Session {
  readonly policy: Policy;
  readonly vault: Vault;
  readonly known: Record<string, string[]>;
  readonly allow: Set<string>;
  readonly extraDetectors: Detector[];
  readonly dayfirst: boolean;
  readonly clock: () => number;
  readonly approve: Approve | null;
  readonly id: string;
  readonly maskedInput: boolean;
  private readonly patterns: PatternDetector;
  private knownCache: [number, KnownDetector] | null = null;
  private restorerCache: Restorer | null = null;

  constructor(policy: Policy | string, o: SessionOptions = {}) {
    this.policy = typeof policy === "string" ? loadProfile(policy) : policy;
    this.vault = o.vault ?? new Vault();
    this.known = Object.fromEntries(Object.entries(o.known ?? {}).map(([t, v]) => [t, [...v]]));
    this.allow = new Set([...this.policy.allow, ...(o.allow ?? [])].map((a) => a.toLowerCase()));
    this.extraDetectors = [...(o.detectors ?? [])];
    this.dayfirst = o.dayfirst ?? false;
    this.clock = o.clock ?? (() => Date.now() / 1000);
    this.approve = o.approve ?? null;
    this.id = o.sessionId ?? randomUUID().replaceAll("-", "");
    this.maskedInput = o.maskedInput ?? false;
    this.patterns = new PatternDetector(o.extraPatterns ?? [], this.dayfirst, () => this.year());
  }

  // Small helpers

  now(): number {
    return Math.trunc(this.clock());
  }

  private year(): number {
    return new Date(this.now() * 1000).getUTCFullYear();
  }

  detectorNames(): string[] {
    return ["rules@1", "known@1", ...this.extraDetectors.map((d) => d.name ?? d.constructor.name)];
  }

  private knownDetector(): KnownDetector {
    if (this.knownCache && this.knownCache[0] === this.vault.version) return this.knownCache[1];
    const forms: Form[] = [];
    const stopWords = new Set(pools().name_stopwords.map((w) => w.toLowerCase()));
    for (const [t, values] of Object.entries(this.known)) {
      for (const v of values) {
        forms.push([t, v, knownMode(t, v)]);
        if (t === "PERSON" && splitWs(v).length > 1) {
          // the app vouched for this person, so "Dana called" and "Reyes, Dana" are them too
          for (const w of splitWs(v)) if (cpLength(w) >= 2 && !stopWords.has(w.toLowerCase())) forms.push(["PERSON", w, "case"]);
        }
      }
    }
    for (const e of this.vault.entries) {
      if (e.type === "DATE" || e.type === "MONEY") continue; // the patterns find these again, and their stand-ins depend on the format
      for (const real of new Set(e.surfaces.values())) {
        if (DIGIT_TYPES.has(e.type) && digitsOf(real).length >= 6) forms.push([e.type, digitsOf(real), "digits"]);
        else forms.push([e.type, real, knownMode(e.type, real)]);
      }
    }
    const stop = new Set(pools().name_stopwords.map((w) => w.toLowerCase()));
    for (const realPart of this.vault.partsBack.values()) {
      if ([...realPart].length >= 2 && !stop.has(realPart.toLowerCase())) forms.push(["PERSON", realPart, "case"]);
    }
    const det = new KnownDetector(forms);
    this.knownCache = [this.vault.version, det];
    return det;
  }

  restorer(): Restorer {
    let r = this.restorerCache;
    if (r === null || r.version !== this.vault.version) {
      r = new Restorer(this.vault, this.year(), this.dayfirst);
      this.restorerCache = r;
    }
    return r;
  }

  // Detection

  detect(text: string): Span[] {
    const spans = [...this.patterns.detect(text), ...this.knownDetector().detect(text)];
    for (const d of this.extraDetectors) spans.push(...d.detect(text));
    return resolve(spans).filter((s) => !this.allow.has(s.text.toLowerCase()) && !this.isOurs(s.text));
  }

  private isOurs(text: string): boolean {
    return this.maskedInput && this.vault.isStandIn(text);
  }

  // Masking

  mask(text: string, source?: SourceLike | null): Masked {
    let spans = this.detect(text);
    const stand = new Map<Span, [string, Entry] | null>();
    let todo = spans;
    let settled = false;
    for (let round = 0; round < 3; round++) {
      // people first, so an email like dana.reyes@... can reuse the fake name chosen for "Dana Reyes"
      const ordered = [...todo].sort((a, b) => Number(a.type !== "PERSON") - Number(b.type !== "PERSON") || a.start - b.start);
      for (const span of ordered) stand.set(span, this.standIn(span, text, source ?? null));
      // what we just learned (a name, its parts) may appear elsewhere in this same text without a cue,
      // like a sign-off "Dana" under "From: Dana Reyes"; look once more for known values only
      const current = spans;
      todo = resolve(this.knownDetector().detect(text)).filter((sp) =>
        !current.some((o) => sp.start < o.end && o.start < sp.end) && !this.allow.has(sp.text.toLowerCase()) &&
        !this.isOurs(sp.text));
      if (todo.length === 0) {
        settled = true;
        break;
      }
      spans = [...spans, ...todo].sort((a, b) => a.start - b.start);
    }
    if (!settled) {
      // three rounds is plenty in practice; whatever the last one found still gets a stand-in
      const ordered = [...todo].sort((a, b) => Number(a.type !== "PERSON") - Number(b.type !== "PERSON") || a.start - b.start);
      for (const span of ordered) stand.set(span, this.standIn(span, text, source ?? null));
    }
    const out: string[] = [];
    const reps: Replacement[] = [];
    const notes: string[] = [];
    let last = 0;
    let pos = 0;
    for (const span of spans) {
      const made = stand.get(span);
      if (!made) continue;
      const [value, entry] = made;
      out.push(text.slice(last, span.start));
      pos += span.start - last;
      reps.push({ start: pos, end: pos + value.length, type: span.type, action: entry.action, standIn: value, entryId: entry.id });
      out.push(value);
      pos += value.length;
      last = span.end;
      if (entry.action === "handle") {
        const n = handles.note(entry.standIn, entry.meta);
        if (!notes.includes(n)) notes.push(n);
      }
    }
    out.push(text.slice(last));
    return { text: out.join(""), replacements: reps, notes };
  }

  private standIn(span: Span, text: string, source: SourceLike | null): [string, Entry] | null {
    const rule = this.policy.ruleFor(span.type);
    let action = rule.action;
    const type = span.type;
    if (action === "keep") return null;
    if (action === "refuse") throw new RefusedData(type);
    let parsed: dates.ParsedDate | null = null;
    let norm: string;
    if (type === "DATE") {
      parsed = dates.parse(span.text, this.year(), this.dayfirst);
      if (action === "fake") action = "shift";
      if (parsed === null && action === "shift") action = "tag";
      norm = parsed ? parsed.day.isoformat() : normalize(type, span.text);
    } else {
      if (action === "shift") action = "fake";
      norm = normalize(type, span.text);
    }
    if (action === "fpe" && (!DIGIT_TYPES.has(type) || digitsOf(span.text).length < 6)) action = "fake";
    const entry = this.vault.find(type, norm, action);
    if (entry !== undefined) return [this.reuse(entry, span, parsed, text), entry];
    return this.create(type, span, norm, action, rule, parsed, text, source);
  }

  private reuse(entry: Entry, span: Span, parsed: dates.ParsedDate | null, text: string): string {
    for (const [fake, real] of entry.surfaces) if (real === span.text) return fake;
    const a = entry.action;
    const t = entry.type;
    let value: string;
    if (a === "shift" && parsed !== null) {
      value = dates.render(dates.Day.fromIso(entry.meta.shifted), parsed);
    } else if (a === "fake" && t === "PERSON") {
      value = fakes.person(new Ctx(this.vault, text, this.policy.ruleFor(t).options), span.text);
    } else if ((a === "fake" || a === "fpe") && DIGIT_TYPES.has(t)) {
      value = fillTemplate(span.text, digitsOf(entry.standIn));
    } else if (a === "fake" && t === "MONEY") {
      value = this.moneyScaled(span.text);
    } else if (a === "generalize") {
      value = this.generalize(t, span.text, parsed);
    } else {
      value = entry.standIn;
    }
    this.vault.addSurface(entry, value, span.text);
    return value;
  }

  private create(type: string, span: Span, norm: string, action: string, rule: Rule, parsed: dates.ParsedDate | null,
    text: string, source: SourceLike | null): [string, Entry] {
    const real = span.text;
    let meta: Record<string, any> = {};
    const restorable = action !== "generalize" && action !== "drop";
    const ctx = new Ctx(this.vault, text, rule.options);
    let value: string;
    if (action === "fake") {
      if (type === "MONEY") value = this.moneyScaled(real);
      else if (type === "EMAIL") value = fakes.email(ctx, real, (full) => this.personFromEmail(full, text));
      else value = fakes.make(type, ctx, real);
    } else if (action === "shift") {
      const shifted = parsed!.day.plusDays(this.vault.getDateOffset());
      value = dates.render(shifted, parsed!);
      meta = { day: parsed!.day.isoformat(), shifted: shifted.isoformat() };
    } else if (action === "tag") {
      value = `[${type}_${this.vault.nextNumber(type)}]`;
    } else if (action === "token") {
      const mac = createHmac("sha256", this.vault.getTokenKey()).update(`${type}:${norm}`, "utf-8").digest("hex");
      value = `${type.toLowerCase()}_${mac.slice(0, 8)}`;
    } else if (action === "fpe") {
      value = this.fpe(type, real);
    } else if (action === "generalize") {
      value = this.generalize(type, real, parsed);
    } else if (action === "drop") {
      value = `[${type} removed]`;
    } else if (action === "handle") {
      value = "{{" + `${type}_${this.vault.nextNumber(type)}` + "}}";
      meta = this.handleMeta(type, real, rule, text, source);
    } else {
      throw new Error(`unknown action ${JSON.stringify(action)}`); // policy validation keeps us out of here
    }
    const entry = this.vault.add(type, real, norm, action, value, restorable, meta);
    return [value, entry];
  }

  /** An address like dana.reyes@ names a person; give them the same fake name everywhere. */
  private personFromEmail(fullName: string, text: string): void {
    const rule = this.policy.ruleFor("PERSON");
    const norm = normalize("PERSON", fullName);
    if (rule.action === "fake" && this.vault.find("PERSON", norm, "fake") === undefined) {
      const value = fakes.person(new Ctx(this.vault, text, rule.options), fullName);
      this.vault.add("PERSON", fullName, norm, "fake", value, true);
    } else {
      fakes.person(new Ctx(this.vault, text, { keep_gender: true }), fullName);
    }
  }

  private handleMeta(type: string, real: string, rule: Rule, text: string, source: SourceLike | null): Record<string, any> {
    let sites: string[] = [...(rule.options.sites ?? [])];
    const bound = source ? handles.boundSite(source) : null;
    if (sites.length === 0 && bound) sites = [bound];
    // text is untrusted: a phrase like "valid for 999 hours" may only shorten the policy's limit, never extend it
    const textTtl = type === "OTP" ? handles.ttlFromText(text) : null;
    const policyTtl: number | null = rule.options.ttl_s ?? null;
    const limits = [textTtl, policyTtl].filter((x): x is number => x !== null);
    if (textTtl !== null && policyTtl === null) limits.push(MAX_TEXT_TTL);
    const ttl = limits.length > 0 ? Math.min(...limits) : null;
    const expires = ttl !== null && ttl !== undefined ? this.now() + Math.trunc(Number(ttl)) : null; // 0 means already expired, not never
    return {
      sites,
      tools: rule.options.tools ?? null,
      uses_left: rule.options.uses ?? null,
      expires_at: expires,
      ask: Boolean(rule.options.ask ?? false),
      description: handles.describe(type, real, sites.length > 0 ? sites[0] : null, expires),
      sinks: [],
    };
  }

  private fpe(type: string, real: string): string {
    const ff1 = new FF1(this.vault.getFpeKey());
    const tweak = Buffer.from(type, "ascii");
    const d = digitsOf(real);
    if (type === "CARD") {
      const head = d[0];
      const tail = d.slice(-4);
      let mid = d.slice(1, -4);
      for (;;) { // cycle-walk until the Luhn digit works out, so the fake is still a well-formed card
        mid = ff1.encryptDigits(mid, tweak);
        if (luhnOk(head + mid + tail)) return fillTemplate(real, head + mid + tail);
      }
    }
    if (type === "ROUTING") {
      let x = d;
      for (;;) {
        x = ff1.encryptDigits(x, tweak);
        if (abaOk(x)) return fillTemplate(real, x);
      }
    }
    if (type === "PHONE" && (d.length === 10 || d.length === 11)) {
      const keep = d.length - 7; // country code and area code stay
      return fillTemplate(real, d.slice(0, keep) + ff1.encryptDigits(d.slice(keep), tweak));
    }
    if (type === "SSN") {
      let x = d;
      for (;;) {
        x = ff1.encryptDigits(x, tweak);
        if (ssnOk(x)) return fillTemplate(real, x);
      }
    }
    return fillTemplate(real, ff1.encryptDigits(d, tweak));
  }

  /** Undo `fpe` with the key alone, for systems that have the key but not the vault. */
  fpeDecrypt(type: string, value: string): string {
    const ff1 = new FF1(this.vault.getFpeKey());
    const tweak = Buffer.from(type, "ascii");
    const d = digitsOf(value);
    if (type === "CARD") {
      const head = d[0];
      const tail = d.slice(-4);
      let mid = d.slice(1, -4);
      for (;;) {
        mid = ff1.decryptDigits(mid, tweak);
        if (luhnOk(head + mid + tail)) return fillTemplate(value, head + mid + tail);
      }
    }
    if (type === "ROUTING" || type === "SSN") {
      const ok = type === "ROUTING" ? abaOk : ssnOk;
      let x = d;
      for (;;) {
        x = ff1.decryptDigits(x, tweak);
        if (ok(x)) return fillTemplate(value, x);
      }
    }
    if (type === "PHONE" && (d.length === 10 || d.length === 11)) {
      const keep = d.length - 7;
      return fillTemplate(value, d.slice(0, keep) + ff1.decryptDigits(d.slice(keep), tweak));
    }
    return fillTemplate(value, ff1.decryptDigits(d, tweak));
  }

  private moneyScaled(real: string): string {
    const [cents, fmt] = parseMoney(real);
    if (cents === null) return real;
    return formatMoney(cents * BigInt(this.vault.getMoneyFactor()), fmt);
  }

  private generalize(type: string, real: string, parsed: dates.ParsedDate | null): string {
    if (type === "DATE") {
      if (parsed === null) return "a date";
      const month = dates.MONTHS[parsed.day.month - 1];
      return parsed.hasYear ? `${month} ${parsed.day.year}` : month;
    }
    if (type === "MONEY") {
      const [cents, fmt] = parseMoney(real);
      if (cents === null) return "an amount";
      let dollars = (cents + 50n) / 100n;
      if (dollars >= 100n) {
        const step = 10n ** BigInt(String(dollars).length - 2);
        dollars = ((dollars + step / 2n) / step) * step;
      }
      return "about " + formatMoney(dollars * 100n, { ...fmt, decimals: false });
    }
    return GENERAL[type] ?? `[${type}]`;
  }

  // JSON and chat messages

  /**
   * Mask a JSON value that is data (a tool result): every string, and the keys too, since a result keyed by email
   * address is as personal as one with emails in it.
   */
  maskJson(value: any, source?: SourceLike | null): [any, string[]] {
    const notes: string[] = [];
    const src = source ?? null;
    return [this.maskTree(this.maskKeys(value, src, notes), src, notes, NO_KEYS), notes];
  }

  private maskKeys(v: any, source: SourceLike | null, notes: string[]): any {
    if (Array.isArray(v)) return v.map((x) => this.maskKeys(x, source, notes));
    if (v !== null && typeof v === "object") {
      const out: Record<string, any> = {};
      for (const [k, x] of Object.entries(v)) {
        const m = this.mask(k, source);
        for (const n of m.notes) if (!notes.includes(n)) notes.push(n);
        Object.defineProperty(out, m.text, { value: this.maskKeys(x, source, notes), writable: true, enumerable: true, configurable: true });
      }
      return out;
    }
    return v;
  }

  private maskTree(v: any, source: SourceLike | null, notes: string[], skipKeys: ReadonlySet<string>, key: string | null = null,
    parent: Record<string, any> | null = null): any {
    if (typeof v === "string") {
      if ((key !== null && skipKeys.has(key)) || isSignedThinking(key, parent)) return v;
      const decoded = textBase64(key, v, parent);
      if (decoded !== null) { // text sent as base64: mask the text, send it back as base64
        const m = this.mask(decoded[2], source);
        for (const n of m.notes) if (!notes.includes(n)) notes.push(n);
        return decoded[0] + Buffer.from(m.text, "utf-8").toString("base64");
      }
      if (isBinary(key, v, parent)) return v;
      if (key === "arguments" && /^[{[]/.test(stripWs(v))) {
        let inner: unknown;
        let ok = true;
        try {
          inner = JSON.parse(v);
        } catch {
          ok = false;
        }
        if (ok) return toJson(this.maskTree(inner, source, notes, NO_KEYS));
      }
      const m = this.mask(v, source);
      for (const n of m.notes) if (!notes.includes(n)) notes.push(n);
      return m.text;
    }
    if (Array.isArray(v)) return v.map((x) => this.maskTree(x, source, notes, skipKeys, key, parent));
    if (v !== null && typeof v === "object") {
      const out: Record<string, any> = {};
      for (const [k, x] of Object.entries(v)) {
        Object.defineProperty(out, k, { value: this.maskTree(x, source, notes, skipKeys, k, v), writable: true, enumerable: true, configurable: true });
      }
      return out;
    }
    return v;
  }

  /**
   * Mask a chat history in OpenAI or Anthropic shape. Handle notes go at the end of the message that mentions the
   * handle, so the model learns what {{OTP_1}} is right where it first sees it.
   */
  maskMessages(messages: any[], source?: SourceLike | null): [any[], string[]] {
    const allNotes: string[] = [];
    const out: any[] = [];
    for (const msg of messages) {
      const notes: string[] = [];
      const masked = this.maskTree(structuredClone(msg), source ?? null, notes, SKIP_KEYS);
      const fresh = notes.filter((n) => !alreadyNoted(masked, n));
      if (fresh.length > 0 && masked !== null && typeof masked === "object" && !Array.isArray(masked)) appendNotes(masked, fresh);
      out.push(masked);
      for (const n of notes) if (!allNotes.includes(n)) allNotes.push(n);
    }
    return [out, allNotes];
  }

  /** Mask any request body part (a system prompt string or block list, tool results...). */
  maskValue(value: any, source?: SourceLike | null): [any, string[]] {
    const notes: string[] = [];
    return [this.maskTree(structuredClone(value), source ?? null, notes, SKIP_KEYS), notes];
  }

  // Restoring

  private reveal = (entryId: string): string => this.vault.byId(entryId)?.real ?? "";

  /** Put the real values back for the person to read. Handles become a short label unless revealed. */
  restore(text: string, revealHandles = false): string {
    return this.restorer().restore(text, revealHandles ? this.reveal : null);
  }

  unknownStandIns(text: string): string[] {
    return this.restorer().unknown(text);
  }

  stream(revealHandles = false): StreamRestorer {
    return new StreamRestorer(() => this.restorer(), revealHandles ? this.reveal : null);
  }

  /** Restore every string in a JSON value for display (handles stay as labels). */
  restoreJson(value: any): any {
    if (typeof value === "string") return this.restore(value);
    if (Array.isArray(value)) return value.map((v) => this.restoreJson(v));
    if (value !== null && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, this.restoreJson(v)]));
    }
    return value;
  }

  /**
   * Restore a tool call's arguments right before the tool runs.
   *
   * Fakes and tags turn back into real values. Handles are filled in only if their binding allows this sink;
   * otherwise HandleRefused is thrown and nothing is filled. Strings that hold contact or payment details the
   * vault never issued are flagged with origin "model": the model wrote them itself.
   */
  resolveArgs(args: any, sink: SinkLike): Resolved {
    if (typeof args === "string" && /^[{[]/.test(stripWs(args))) {
      let parsed: unknown = null;
      try {
        parsed = JSON.parse(args);
      } catch {
        parsed = null;
      }
      if (parsed !== null) {
        const res = this.resolveArgs(parsed, sink);
        return { args: toJson(res.args), report: res.report };
      }
    }
    const restorer = this.restorer();
    const now = this.now();
    const wanted = new Map<string, Entry>();
    for (const text of strings(args)) {
      for (const m of findAll(HANDLE, text)) {
        const eid = restorer.handles.get(m[0]);
        if (eid === undefined) throw new HandleRefused(m[0], "unknown handle");
        wanted.set(m[0], this.vault.byId(eid)!);
      }
    }
    const placeOf = (): [string | null, string | null] => [sink.tool ?? null, sink.site ? handles.hostOf(sink.site) : null];
    for (const [handle, entry] of wanted) {
      handles.check(handle, entry.meta, sink, now);
      const place = placeOf();
      const firstTimeHere = !(entry.meta.sinks ?? []).some((p: any[]) => samePlace(p, place));
      if (entry.meta.ask || (firstTimeHere && this.approve !== null)) {
        if (this.approve === null) throw new HandleRefused(handle, "needs the person's approval");
        if (!this.approve(handle, entry.meta.description, sink)) throw new HandleRefused(handle, "not approved");
      }
    }
    const report: Record<string, any>[] = [];
    const walk = (v: any, path: string): any => {
      if (typeof v === "string") {
        const found = restorer.matches(v, 0, this.reveal);
        if (found.length > 0) {
          report.push({ path, restored: found.length, handles: found.filter((m) => m.kind === "handle").map((m) => m.entryId) });
          return apply(v, found);
        }
        const kinds = [...new Set(this.patterns.detect(v).map((s) => s.type)
          .filter((t) => ["EMAIL", "PHONE", "CARD", "IBAN", "BANK_ACCOUNT", "URL"].includes(t)))].sort();
        if (kinds.length > 0) report.push({ path, origin: "model", types: kinds });
        return v;
      }
      if (Array.isArray(v)) return v.map((x, i) => walk(x, `${path}[${i}]`));
      if (v !== null && typeof v === "object") {
        return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x, path ? `${path}.${k}` : k)]));
      }
      return v;
    };
    const result = walk(args, "");
    for (const entry of wanted.values()) {
      if (entry.meta.uses_left != null) entry.meta.uses_left -= 1;
      const place = placeOf();
      entry.meta.sinks ??= [];
      if (!entry.meta.sinks.some((p: any[]) => samePlace(p, place))) entry.meta.sinks.push(place);
      this.vault.touch();
    }
    return { args: result, report };
  }

  // Egress

  /**
   * Two checks on the exact bytes about to leave: every real value the vault knows, and a fresh detection pass over
   * the content fields, so a field that was never masked (a document, a metadata note) is caught too.
   */
  checkEgress(payload: Uint8Array | string): Leak[] {
    const leaks = egressCheck(this.vault, payload, this.restorer());
    const seen = new Set(leaks.map((lk) => JSON.stringify([lk.type, lk.entryId])));
    for (const span of this.detect(contentText(payload))) {
      if (this.policy.ruleFor(span.type).action !== "keep" && !this.vault.isStandIn(span.text)) {
        const key = JSON.stringify([span.type, "detected"]);
        if (!seen.has(key)) {
          seen.add(key);
          leaks.push({ type: span.type, entryId: "detected" });
        }
      }
    }
    return leaks;
  }

  /** Check the exact bytes about to be sent and sign a receipt. Throws EgressLeak instead of sending a leak. */
  recordEgress(log: EgressLog, payload: Uint8Array | string, dest: string): string {
    const leaks = this.checkEgress(payload);
    if (leaks.length > 0) throw new EgressLeak(leaks);
    return log.record(this.vault, payload, {
      session: this.id, policyDigest: this.policy.digest, dest, now: this.now(), detectors: this.detectorNames(),
      restorer: this.restorer(),
    });
  }
}

function samePlace(a: any[], b: any[]): boolean {
  return a[0] === b[0] && a[1] === b[1];
}

function* strings(v: any): Generator<string> {
  if (typeof v === "string") {
    yield v;
  } else if (Array.isArray(v)) {
    for (const x of v) yield* strings(x);
  } else if (v !== null && typeof v === "object") {
    for (const x of Object.values(v)) yield* strings(x);
  }
}

function alreadyNoted(msg: any, note: string): boolean {
  return toJson(msg).includes(note);
}

function appendNotes(msg: Record<string, any>, notes: string[]): void {
  const text = notes.map((n) => `Note: ${n}`).join("\n");
  const content = msg.content;
  if (typeof content === "string") msg.content = content + "\n\n" + text;
  else if (Array.isArray(content)) msg.content = [...content, { type: "text", text }];
  else msg.content = text;
}

interface MoneyFormat {
  symbol: string | null;
  space: string;
  suffix: string | null;
  commas: boolean;
  decimals: boolean;
}

function parseMoney(real: string): [bigint, MoneyFormat] | [null, null] {
  let whole: string;
  let dec: string | undefined;
  let fmt: MoneyFormat;
  let m = MONEY_PREFIX.exec(real);
  if (m) {
    whole = m[3];
    dec = m[4];
    fmt = { symbol: m[1], space: m[2], suffix: null, commas: whole.includes(","), decimals: Boolean(dec) };
  } else {
    m = MONEY_SUFFIX.exec(real);
    if (!m) return [null, null];
    whole = m[1];
    dec = m[2];
    fmt = { symbol: null, space: m[3], suffix: m[4], commas: whole.includes(","), decimals: Boolean(dec) };
  }
  // BigInt: the pattern allows any number of digits
  const cents = BigInt(whole.replaceAll(",", "")) * 100n + (dec ? BigInt(dec.slice(1)) : 0n);
  return [cents, fmt];
}

function formatMoney(cents: bigint, fmt: MoneyFormat): string {
  const whole = cents / 100n;
  const rest = cents % 100n;
  let number = fmt.commas ? String(whole).replace(/\B(?=(\d{3})+(?!\d))/g, ",") : String(whole);
  if (fmt.decimals) number += `.${String(rest).padStart(2, "0")}`;
  if (fmt.symbol) return `${fmt.symbol}${fmt.space}${number}`;
  return `${number}${fmt.space}${fmt.suffix}`;
}
