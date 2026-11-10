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
import { patterns as sharedPatterns, pools, type PatternSpec } from "./data.ts";
import { checkTypeName } from "./types.ts";
import { cmpCodePoints, cpLength, escapeRegExp, findAll, splitWs } from "./util.ts";

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
    this.compiled = [...sharedCompiled(), ...[...extra].map(PatternDetector.compile)];
  }

  static compile(p: PatternSpec): Compiled {
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

let shared: Compiled[] | null = null;

/** The shared patterns, compiled once per process: some are large word lists. */
function sharedCompiled(): Compiled[] {
  shared ??= sharedPatterns().map(PatternDetector.compile);
  return shared;
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
  private readonly digitTypes = new Map<string, string>();
  private readonly digitRe: RegExp | null = null;

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
        this.lookup.set(JSON.stringify(["case", squash(variant)]), type);
        caseAlts.push(variant);
      }
    }
    const nocaseAlts: string[] = [];
    for (const [type, text] of byMode.nocase) {
      this.lookup.set(JSON.stringify(["nocase", squash(text).toLowerCase()]), type);
      nocaseAlts.push(text);
    }
    if (caseAlts.length > 0) {
      this.regexes.push([new RegExp(NB + "(" + alternation(caseAlts) + ")" + NA, "gu"), "case"]);
    }
    if (nocaseAlts.length > 0) {
      this.regexes.push([new RegExp(NB + "(" + alternation(nocaseAlts) + ")" + NA, "giu"), "nocase"]);
    }
    // all known numbers in one regex; a match is mapped back to its type by its digits
    for (const [type, digits] of byMode.digits) {
      if (digits.length >= 6 && !this.digitTypes.has(digits)) this.digitTypes.set(digits, type);
    }
    if (this.digitTypes.size > 0) {
      const alts = [...this.digitTypes.keys()].sort((a, b) => cpLength(b) - cpLength(a) || cmpCodePoints(a, b));
      const body = alts.map((d) => [...d].join("[ .()+-]{0,2}")).join("|");
      this.digitRe = new RegExp("(?<![0-9])[(+]?(?:" + body + ")(?![0-9])", "gu");
    }
  }

  detect(text: string): Span[] {
    const out: Span[] = [];
    for (const [regex, mode] of this.regexes) {
      for (const m of findAll(regex, text)) {
        const key = mode === "case" ? squash(m[1]) : squash(m[1]).toLowerCase();
        const type = this.lookup.get(JSON.stringify([mode, key]));
        if (type) out.push(span(m.index, m.index + m[1].length, type, m[1], "known", KnownDetector.PRIORITY));
      }
    }
    if (this.digitRe !== null) {
      for (const m of findAll(this.digitRe, text)) {
        const type = this.digitTypes.get(m[0].replace(/[^0-9]/g, ""));
        if (type) out.push(span(m.index, m.index + m[0].length, type, m[0], "known", KnownDetector.PRIORITY));
      }
    }
    return out;
  }
}

// any run of whitespace, as one regex piece
const WS_PIECE = "[ \\t\\r\\n\\u00a0]+";

/** Runs of whitespace as one space, so "Dana  Reyes" and "Dana\nReyes" look up the same entry. */
function squash(text: string): string {
  return splitWs(text.replaceAll("\u00a0", " ")).join(" ");
}

function alternation(alts: string[]): string {
  // longest first, so "Dana Reyes" wins over "Dana"; words may be split by any run of whitespace
  const sorted = [...new Set(alts.map(squash))].sort((a, b) => cpLength(b) - cpLength(a) || cmpCodePoints(a, b));
  return sorted.map((a) => a.split(" ").map(escapeRegExp).join(WS_PIECE)).join("|");
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

const TOKEN = /[^ \t\r\n ]+/gu;

/**
 * `resolve`, with two extra rules so a person is never half hidden.
 *
 * 1. A name that contains a shorter name takes that name's priority. "Ms. Reyes" teaches us "Reyes"; later
 *    "Dana Reyes" must be hidden whole, not as "Dana" plus a fake surname. A full name whose surname is also a
 *    place ("Isla Fairbanks") beats the place.
 * 2. A name that loses to another type keeps the words that type did not cover: if "Reyes, TX" wins as a place,
 *    "Dana" in front of it is still a person.
 */
export function resolvePeople(input: Iterable<Span>): Span[] {
  const spans = [...input];
  const people = spans.filter((s) => s.type === "PERSON");
  const promoted = spans.map((s) => {
    if (s.type !== "PERSON") return s;
    const inner = people
      .filter((t) => t !== s && s.start <= t.start && t.end <= s.end && cpLength(t.text) < cpLength(s.text))
      .map((t) => t.priority);
    const surnamePlaces = spans
      .filter((t) => t.type === "LOCATION" && s.start < t.start && t.end === s.end)
      .map((t) => t.priority + 1);
    const best = Math.max(s.priority, ...inner, ...surnamePlaces);
    return best > s.priority ? span(s.start, s.end, s.type, s.text, s.source, best) : s;
  });
  const chosen = resolve(promoted);
  const extra: Span[] = [];
  for (const s of promoted) {
    if (s.type !== "PERSON" || chosen.includes(s)) continue;
    const rivals = chosen.filter((c) => c.start < s.end && s.start < c.end);
    if (rivals.length === 0 || rivals.some((c) => c.type === "PERSON")) continue;
    let run: [number, number][] = [];
    for (const m of findAll(TOKEN, s.text)) {
      const a = s.start + m.index;
      const b = a + m[0].length;
      if (rivals.some((c) => a < c.end && c.start < b)) {
        extra.push(...nameRun(run, s));
        run = [];
      } else {
        run.push([a, b]);
      }
    }
    extra.push(...nameRun(run, s));
  }
  return extra.length > 0 ? resolve([...chosen, ...extra]) : chosen;
}

function nameRun(run: [number, number][], whole: Span): Span[] {
  if (run.length === 0) return [];
  const a = run[0][0];
  const b = run[run.length - 1][1];
  const text = whole.text.slice(a - whole.start, b - whole.start);
  return checks.nameOk(text) ? [span(a, b, "PERSON", text, whole.source, whole.priority)] : [];
}

const NAME_WORD = /^[A-ZÀ-ÖØ-ÞĀ-Ž][A-Za-zÀ-ÖØ-öø-ÿĀ-ž'-]*[A-Za-zÀ-ÖØ-öø-ÿĀ-ž]$/u;
const INITIAL = /^[A-Z]\.$/u;
const BREAKS = new Set([" ", "\t", "\r", "\n", "(", "\"", "'"]);

/**
 * A name the vault or the app already knows ("Reyes") may sit next to a part we have not seen: "Dana Reyes",
 * "D. Reyes", "met Zorblax Reyes". Grow such a span by one word on each side when that word reads as part of the
 * name, so the whole person is hidden. Only known values grow; the patterns already take whole names.
 */
export function growNames(spans: Span[], text: string): Span[] {
  const data = pools();
  const stop = checks.stopwords();
  const given = data.name_gender;
  const places = data.places;
  const out: Span[] = [];
  spans.forEach((s, i) => {
    if (s.type !== "PERSON" || s.source !== "known") {
      out.push(s);
      return;
    }
    const lo = out.length > 0 ? out[out.length - 1].end : 0;
    const hi = i + 1 < spans.length ? spans[i + 1].start : text.length;
    let start = s.start;
    let end = s.end;
    if (start >= 2 && text[start - 1] === " ") {
      let a = start - 1;
      while (a > lo && !BREAKS.has(text[a - 1])) a--;
      const word = text.slice(a, start - 1);
      if (a >= lo && word && !stop.has(word.toLowerCase()) && !places.has(word) &&
        (INITIAL.test(word) || (NAME_WORD.test(word) && (given.has(word.toLowerCase()) || !sentenceStart(text, a))))) {
        start = a;
      }
    }
    if (!s.text.includes(" ") && end + 1 < hi && text[end] === " ") {
      let b = end + 1;
      while (b < hi && !BREAKS.has(text[b]) && !".,;:!?)".includes(text[b])) b++;
      const word = text.slice(end + 1, b);
      if (word && NAME_WORD.test(word) && !stop.has(word.toLowerCase()) && !places.has(word)) end = b;
    }
    out.push(start !== s.start || end !== s.end ? span(start, end, s.type, text.slice(start, end), s.source, s.priority) : s);
  });
  return out;
}

function sentenceStart(text: string, at: number): boolean {
  const before = text.slice(0, at).replace(/[ \t]+$/u, "");
  return before.length === 0 || ".!?:\n\"(".includes(before[before.length - 1]);
}
