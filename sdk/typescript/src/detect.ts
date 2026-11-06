// Finding personal data in text.
//
// Three kinds of detector feed one list of spans:
//
//   - PatternDetector: the shared patterns from data/patterns.json plus checksums (Luhn, IBAN, ABA...).
//   - KnownDetector: exact values we already know about. Everything already in the vault is matched again, so a value
//     that was hidden once is hidden every time after, even without the cue that found it the first time. Apps can
//     also pass their own lists (contacts, the user's own company), which is the cheapest way to catch names.
//   - Anything with a `detect(text) -> Span[]` method: optional detectors such as a local NER model.
//
// Overlaps are settled by priority, then length: a known value beats a pattern, an email beats the name inside it.
//
// Positions are UTF-16 offsets into the text, the way JavaScript strings are indexed.

import * as checks from "./checks.ts";
import * as dates from "./dates.ts";
import { patterns as sharedPatterns, type PatternSpec } from "./data.ts";
import { checkTypeName } from "./types.ts";
import { cmpCodePoints, cpLength, escapeRegExp, findAll } from "./util.ts";

const NB = "(?<![A-Za-z0-9_])";
const NA = "(?![A-Za-z0-9_])";

export interface Span {
  start: number;
  end: number;
  type: string;
  text: string;
  source: string;
  priority: number;
}

export function span(start: number, end: number, type: string, text: string, source = "rules", priority = 50): Span {
  return { start, end, type, text, source, priority };
}

export interface Detector {
  name?: string;
  detect(text: string): Span[];
}

interface Compiled {
  type: string;
  regex: RegExp;
  group: number;
  check: string | null;
  priority: number;
}

/** The shared rule set. `dayfirst` and `defaultYear` only matter for reading dates. */
export class PatternDetector {
  private readonly dayfirst: boolean;
  private readonly defaultYear: () => number;
  private readonly compiled: Compiled[];

  constructor(extra: Iterable<PatternSpec> = [], dayfirst = false, defaultYear?: () => number) {
    this.dayfirst = dayfirst;
    this.defaultYear = defaultYear ?? (() => 2000);
    this.compiled = [...sharedPatterns(), ...extra].map(PatternDetector.compile);
  }

  private static compile(p: PatternSpec): Compiled {
    // "d" gives the start and end of each capture group, which is what a pattern's `group` refers to
    const flags = "gud" + ((p.flags ?? "").includes("i") ? "i" : "");
    return {
      type: checkTypeName(p.type),
      regex: new RegExp(p.pattern, flags),
      group: p.group ?? 0,
      check: p.check ?? null,
      priority: p.priority ?? 50,
    };
  }

  private passes(check: string | null, value: string): boolean {
    switch (check) {
      case null: return true;
      case "card": return checks.cardOk(value);
      case "iban": return checks.ibanOk(value);
      case "ssn": return checks.ssnOk(value);
      case "aba": return checks.abaOk(value);
      case "phone": return checks.phoneOk(value);
      case "name": return checks.nameOk(value);
      case "date": return dates.parse(value, this.defaultYear(), this.dayfirst) !== null;
      default: throw new Error(`unknown check ${JSON.stringify(check)}`);
    }
  }

  detect(text: string): Span[] {
    const out: Span[] = [];
    for (const c of this.compiled) {
      for (const m of findAll(c.regex, text)) {
        const idx = (m as any).indices[c.group] as [number, number] | undefined;
        if (!idx) continue; // the group did not take part in this match
        const [start, end] = idx;
        if (start === end) continue;
        const value = text.slice(start, end);
        if (this.passes(c.check, value)) out.push(span(start, end, c.type, value, "rules", c.priority));
      }
    }
    return out;
  }
}

/** A value to look for: (type, text, mode). */
export type Form = [type: string, text: string, mode: "case" | "nocase" | "digits"];

/**
 * Exact values: what the vault already holds plus lists the app hands over.
 *
 * `forms` is a list of (type, text, mode) where mode is:
 *   "case"   match as written, or in all capitals (names: "Maya" but not the word "maya")
 *   "nocase" match in any case (emails, links)
 *   "digits" match the same digits with any light formatting in between ("617 555 0142" = "(617) 555-0142")
 */
export class KnownDetector {
  static readonly PRIORITY = 100;
  private readonly lookup = new Map<string, string>();
  private readonly regexes: [RegExp, "case" | "nocase"][] = [];
  private readonly digitForms: [RegExp, string][] = [];

  constructor(forms: Iterable<Form>) {
    const byMode: Record<string, [string, string][]> = { case: [], nocase: [], digits: [] };
    const seen = new Set<string>();
    for (const [type, text, mode] of forms) {
      const key = JSON.stringify([type, text, mode]);
      if (!text || seen.has(key)) continue;
      seen.add(key);
      byMode[mode].push([type, text]);
    }
    const caseAlts: string[] = [];
    for (const [type, text] of byMode.case) {
      for (const variant of new Set([text, text.toUpperCase()])) {
        this.lookup.set(JSON.stringify(["case", variant]), type);
        caseAlts.push(variant);
      }
    }
    const nocaseAlts: string[] = [];
    for (const [type, text] of byMode.nocase) {
      this.lookup.set(JSON.stringify(["nocase", text.toLowerCase()]), type);
      nocaseAlts.push(text);
    }
    if (caseAlts.length > 0) {
      this.regexes.push([new RegExp(NB + "(" + alternation(caseAlts) + ")" + NA, "gu"), "case"]);
    }
    if (nocaseAlts.length > 0) {
      this.regexes.push([new RegExp(NB + "(" + alternation(nocaseAlts) + ")" + NA, "giu"), "nocase"]);
    }
    for (const [type, digits] of byMode.digits) {
      if (digits.length >= 6) {
        const pattern = "(?<![0-9])[(+]?" + [...digits].join("[ .()+-]{0,2}") + "(?![0-9])";
        this.digitForms.push([new RegExp(pattern, "gu"), type]);
      }
    }
  }

  detect(text: string): Span[] {
    const out: Span[] = [];
    for (const [regex, mode] of this.regexes) {
      for (const m of findAll(regex, text)) {
        const key = mode === "case" ? m[1] : m[1].toLowerCase();
        const type = this.lookup.get(JSON.stringify([mode, key]));
        if (type) out.push(span(m.index, m.index + m[1].length, type, m[1], "known", KnownDetector.PRIORITY));
      }
    }
    for (const [regex, type] of this.digitForms) {
      for (const m of findAll(regex, text)) {
        out.push(span(m.index, m.index + m[0].length, type, m[0], "known", KnownDetector.PRIORITY));
      }
    }
    return out;
  }
}

function alternation(alts: string[]): string {
  // longest first, so "Dana Reyes" wins over "Dana"
  const sorted = [...new Set(alts)].sort((a, b) => cpLength(b) - cpLength(a) || cmpCodePoints(a, b));
  return sorted.map(escapeRegExp).join("|");
}

/** Pick non-overlapping spans: higher priority first, then longer, then earlier. Returned in text order. */
export function resolve(spans: Iterable<Span>): Span[] {
  const chosen: Span[] = [];
  const taken: [number, number][] = [];
  const ranked = [...spans].sort((a, b) =>
    b.priority - a.priority || cpLength(b.text) - cpLength(a.text) || a.start - b.start || cmpCodePoints(a.type, b.type));
  for (const s of ranked) {
    if (taken.some(([b, e]) => s.start < e && b < s.end)) continue;
    chosen.push(s);
    taken.push([s.start, s.end]);
  }
  return chosen.sort((a, b) => a.start - b.start);
}
