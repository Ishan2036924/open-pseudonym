// Putting real values back into what the model wrote.
//
// Four kinds of match, all found in one pass and settled earliest-first, longest-first:
//   1. exact stand-ins the vault issued (names match as written or in capitals; emails and links in any case)
//   2. handles {{TYPE_n}}, which become a label for display, or the real value when a caller is allowed to see it
//   3. digits: a fake phone or card the model reformatted ("617-555-0142" for "(617) 555-0142")
//   4. dates: a shifted date the model wrote in another format ("March 12" for "2026-03-12")
//
// The streaming restorer holds back only the tail of the text that could still be the start of a stand-in, so the
// person sees words appear almost as fast as without us, and never sees half a fake name.
//
// Positions are UTF-16 offsets, and lengths below are in UTF-16 units too, so the hold-back is always long enough.

import { patterns as sharedPatterns } from "./data.ts";
import * as dates from "./dates.ts";
import { fillTemplate } from "./fakes.ts";
import { HANDLE } from "./handles.ts";
import { CASELESS_TYPES, DIGIT_TYPES, digitsOf } from "./types.ts";
import type { Vault } from "./vault.ts";
import { cmpCodePoints, escapeRegExp, findAll, splitWs } from "./util.ts";

const NB = "(?<![A-Za-z0-9_])";
const NA = "(?![A-Za-z0-9_])";
const TAG = /\[([A-Z][A-Z0-9_]*)_([0-9]+)\]/gu;
const DIGIT_RUN = /(?<![0-9])\+?[0-9](?:[ .()-]{0,2}[0-9]){5,22}(?![0-9])/gu;

let dateRegexes: [RegExp, number][] | null = null;

function getDateRegexes(): [RegExp, number][] {
  if (dateRegexes === null) {
    dateRegexes = sharedPatterns()
      .filter((p) => p.type === "DATE")
      .map((p) => [new RegExp(p.pattern, "gud" + ((p.flags ?? "").includes("i") ? "i" : "")), p.group ?? 0]);
  }
  return dateRegexes;
}

export type Reveal = (entryId: string) => string;

export interface Match {
  start: number;
  end: number;
  replacement: string;
  entryId: string | null;
  kind: "exact" | "handle" | "digits" | "date";
}

/** A snapshot of the vault's stand-ins, compiled for fast matching. Rebuild it when the vault changes. */
export class Restorer {
  readonly vault: Vault;
  readonly version: number;
  readonly defaultYear: number;
  readonly dayfirst: boolean;
  readonly case = new Map<string, [string, string]>(); // stand-in -> (real, entry id)
  readonly nocase = new Map<string, [string, string]>(); // lower stand-in -> (real, entry id)
  readonly digits = new Map<string, [string, string, string]>(); // stand-in digits -> (real surface, entry id, type)
  readonly dates = new Map<string, [string, string]>(); // shifted ISO day -> (real ISO day, entry id)
  readonly handles = new Map<string, string>(); // handle text -> entry id
  readonly longest: number;
  private readonly caseRe: RegExp | null;
  private readonly nocaseRe: RegExp | null;

  constructor(vault: Vault, defaultYear = 2000, dayfirst = false) {
    this.vault = vault;
    this.version = vault.version;
    this.defaultYear = defaultYear;
    this.dayfirst = dayfirst;
    let longest = 0;
    for (const e of vault.entries) {
      if (!e.restorable) continue;
      if (e.action === "handle") {
        this.handles.set(e.standIn, e.id);
        longest = Math.max(longest, e.standIn.length);
        continue;
      }
      for (const [fake, real] of e.surfaces) {
        longest = Math.max(longest, fake.length);
        if (CASELESS_TYPES.has(e.type) || e.action === "token") {
          setDefault(this.nocase, fake.toLowerCase(), [real, e.id]);
        } else {
          setDefault(this.case, fake, [real, e.id]);
          if (fake.toUpperCase() !== fake) setDefault(this.case, fake.toUpperCase(), [real.toUpperCase(), e.id]);
        }
        if (DIGIT_TYPES.has(e.type) && (e.action === "fake" || e.action === "fpe")) {
          const fd = digitsOf(fake);
          setDefault(this.digits, fd, [real, e.id, e.type]);
          if (e.type === "PHONE" && fd.length === 11 && fd[0] === "1") setDefault(this.digits, fd.slice(1), [real, e.id, e.type]);
        }
      }
      if (e.type === "DATE" && e.action === "shift") this.dates.set(e.meta.shifted, [e.meta.day, e.id]);
    }
    for (const [fakeLow, realPart] of vault.partsBack) {
      const owner = this.partOwner(fakeLow);
      const fake = vault.parts.get(realPart.toLowerCase())!;
      longest = Math.max(longest, fake.length);
      setDefault(this.case, fake, [realPart, owner]);
      setDefault(this.case, fake.toUpperCase(), [realPart.toUpperCase(), owner]);
    }
    this.longest = Math.max(longest, 40);
    this.caseRe = union(this.case.keys(), "gu");
    this.nocaseRe = union(this.nocase.keys(), "giu");
  }

  private partOwner(fakeLow: string): string {
    for (const e of this.vault.entries) {
      if (e.type !== "PERSON") continue;
      for (const s of e.surfaces.keys()) if (splitWs(s.toLowerCase()).includes(fakeLow)) return e.id;
    }
    return "part";
  }

  // Matching

  matches(text: string, pos = 0, reveal?: Reveal | null): Match[] {
    const found: Match[] = [];
    if (this.caseRe) {
      for (const m of findAll(this.caseRe, text, pos)) {
        const [real, eid] = this.case.get(m[1])!;
        found.push({ start: m.index, end: m.index + m[1].length, replacement: real, entryId: eid, kind: "exact" });
      }
    }
    if (this.nocaseRe) {
      for (const m of findAll(this.nocaseRe, text, pos)) {
        const [real, eid] = this.nocase.get(m[1].toLowerCase())!;
        found.push({ start: m.index, end: m.index + m[1].length, replacement: real, entryId: eid, kind: "exact" });
      }
    }
    for (const m of findAll(HANDLE, text, pos)) {
      const eid = this.handles.get(m[0]);
      if (eid !== undefined) {
        const entry = this.vault.byId(eid)!;
        const shown = reveal ? reveal(eid) : `[${entry.meta.description}]`;
        found.push({ start: m.index, end: m.index + m[0].length, replacement: shown, entryId: eid, kind: "handle" });
      }
    }
    if (this.digits.size > 0) {
      for (const m of findAll(DIGIT_RUN, text, pos)) {
        const hit = this.digits.get(digitsOf(m[0]));
        if (hit) {
          found.push({ start: m.index, end: m.index + m[0].length, replacement: realInShape(hit[0], m[0]), entryId: hit[1], kind: "digits" });
        }
      }
    }
    if (this.dates.size > 0) {
      for (const [regex, group] of getDateRegexes()) {
        for (const m of findAll(regex, text, pos)) {
          const idx = (m as any).indices[group] as [number, number] | undefined;
          if (!idx) continue;
          const [s, e] = idx;
          const parsed = dates.parse(text.slice(s, e), this.defaultYear, this.dayfirst);
          if (parsed === null) continue;
          const hit = this.dates.get(parsed.day.isoformat());
          if (hit) {
            found.push({ start: s, end: e, replacement: dates.render(dates.Day.fromIso(hit[0]), parsed), entryId: hit[1], kind: "date" });
          }
        }
      }
    }
    return settle(found);
  }

  restore(text: string, reveal?: Reveal | null): string {
    return apply(text, this.matches(text, 0, reveal));
  }

  /** Tags and handles that look like ours but are not in the vault (the model made them up). */
  unknown(text: string): string[] {
    const out: string[] = [];
    for (const m of findAll(TAG, text)) if (!this.case.has(m[0])) out.push(m[0]);
    for (const m of findAll(HANDLE, text)) if (!this.handles.has(m[0])) out.push(m[0]);
    return out;
  }
}

function setDefault<V>(map: Map<string, V>, key: string, value: V): void {
  if (!map.has(key)) map.set(key, value);
}

function union(forms: Iterable<string>, flags: string): RegExp | null {
  // longest first, so a longer stand-in wins over one that is a prefix of it
  const sorted = [...new Set(forms)].sort((a, b) => b.length - a.length || cmpCodePoints(a, b));
  if (sorted.length === 0) return null;
  return new RegExp(NB + "(" + sorted.map(escapeRegExp).join("|") + ")" + NA, flags);
}

function settle(found: Match[]): Match[] {
  const out: Match[] = [];
  let end = -1;
  for (const m of [...found].sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start))) {
    if (m.start >= end) {
      out.push(m);
      end = m.end;
    }
  }
  return out;
}

/** The real number, laid out the way the model wrote the fake one when the digit counts line up. */
function realInShape(real: string, written: string): string {
  const rd = digitsOf(real);
  const wd = digitsOf(written);
  if (rd.length === wd.length) return fillTemplate(written, rd);
  if (rd.length === wd.length + 1 && rd[0] === "1") return fillTemplate(written, rd.slice(1)); // the model dropped a leading +1
  return real;
}

function shifted(matches: Match[], offset: number): Match[] {
  return matches.map((m) => ({ ...m, start: m.start - offset, end: m.end - offset }));
}

export function apply(text: string, matches: Match[]): string {
  const parts: string[] = [];
  let last = 0;
  for (const m of matches) {
    parts.push(text.slice(last, m.start), m.replacement);
    last = m.end;
  }
  parts.push(text.slice(last));
  return parts.join("");
}

function isHigh(c: number): boolean {
  return c >= 0xd800 && c <= 0xdbff;
}

function isLow(c: number): boolean {
  return c >= 0xdc00 && c <= 0xdfff;
}

/**
 * Feed it chunks of model output as they arrive; it returns restored text that is safe to show.
 *
 * A stand-in is at most `longest` characters, so any match that starts more than `longest` characters before the
 * end of what we have is already complete. We emit up to that point (never cutting a match in half) and keep the
 * tail. One character of context is kept so word-edge checks work across the cut.
 */
export class StreamRestorer {
  private readonly get: () => Restorer;
  private readonly reveal: Reveal | null;
  private buf = "";
  private prev = "";

  constructor(getRestorer: () => Restorer, reveal?: Reveal | null) {
    this.get = getRestorer;
    this.reveal = reveal ?? null;
  }

  feed(chunk: string): string {
    this.buf += chunk;
    const r = this.get();
    const hold = r.longest + 1;
    if (this.buf.length <= hold) return "";
    const context = this.prev + this.buf;
    const offset = this.prev.length;
    const found = r.matches(context, offset, this.reveal);
    let cut = this.buf.length - hold;
    // never cut between the two halves of a surrogate pair
    if (cut > 0 && isHigh(this.buf.charCodeAt(cut - 1)) && isLow(this.buf.charCodeAt(cut))) cut -= 1;
    for (const m of found) {
      const ms = m.start - offset;
      const me = m.end - offset;
      if (ms < cut && cut < me) cut = ms;
    }
    const emit = found.filter((m) => m.end - offset <= cut);
    const out = apply(this.buf.slice(0, cut), shifted(emit, offset));
    if (cut > 0) {
      // keep the last full character before the cut as context
      const before = isLow(this.buf.charCodeAt(cut - 1)) && cut > 1 && isHigh(this.buf.charCodeAt(cut - 2)) ? 2 : 1;
      this.prev = this.buf.slice(cut - before, cut);
      this.buf = this.buf.slice(cut);
    }
    return out;
  }

  flush(): string {
    const r = this.get();
    const context = this.prev + this.buf;
    const offset = this.prev.length;
    const found = r.matches(context, offset, this.reveal);
    const out = apply(this.buf, shifted(found, offset));
    this.buf = "";
    this.prev = "";
    return out;
  }
}
