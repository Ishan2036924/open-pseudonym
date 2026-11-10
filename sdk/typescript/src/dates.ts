import { pools } from "./data.ts";
import { cmpCodePoints, cpLength, escapeRegExp } from "./util.ts";

// Reading and writing the date formats we detect, so a shifted date comes back in the same shape.
//
// If the text says "Thu, March 5", the shifted version must still look like "March 12" and not "2026-03-12";
// otherwise the model notices the seams. Every format we parse, we can also render.

export const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September",
  "October", "November", "December"];
const MONTH_KEYS = new Map(MONTHS.map((m, i) => [m.slice(0, 3).toLowerCase(), i + 1] as [string, number]));
const MON = "(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)";

const ISO = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/;
const SLASH = /^([0-9]{1,2})\/([0-9]{1,2})\/([0-9]{4})$/;
const MDY = new RegExp("^" + MON + "(\\.?) ([0-9]{1,2})(st|nd|rd|th)?(?:, ([0-9]{4}))?$");
const DMY = new RegExp("^([0-9]{1,2})(st|nd|rd|th)? " + MON + "(\\.?)(?: ([0-9]{4}))?$");

// A calendar day in the proleptic Gregorian calendar, years 1 to 9999: the same range as Python's datetime.date.
// JavaScript's Date is avoided on purpose, since it reads years 0 to 99 as 1900 to 1999.
export class Day {
  readonly year: number;
  readonly month: number;
  readonly day: number;

  private constructor(year: number, month: number, day: number) {
    this.year = year;
    this.month = month;
    this.day = day;
  }

  /** The day, or null when it does not exist (February 30, year 0...). */
  static of(year: number, month: number, day: number): Day | null {
    if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) return null;
    if (year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) return null;
    return new Day(year, month, day);
  }

  static fromIso(text: string): Day {
    const m = ISO.exec(text);
    const day = m ? Day.of(Number(m[1]), Number(m[2]), Number(m[3])) : null;
    if (day === null) throw new RangeError(`Invalid isoformat string: ${JSON.stringify(text)}`);
    return day;
  }

  static fromOrdinal(n: number): Day {
    const [y, m, d] = civilFromDays(n);
    const day = Day.of(y, m, d);
    if (day === null) throw new RangeError("date value out of range");
    return day;
  }

  /** Days since 1970-01-01. */
  toOrdinal(): number {
    return daysFromCivil(this.year, this.month, this.day);
  }

  plusDays(n: number): Day {
    return Day.fromOrdinal(this.toOrdinal() + n);
  }

  isoformat(): string {
    return `${String(this.year).padStart(4, "0")}-${pad2(this.month)}-${pad2(this.day)}`;
  }
}

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}

function isLeap(y: number): boolean {
  return y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
}

function daysInMonth(y: number, m: number): number {
  return m === 2 ? (isLeap(y) ? 29 : 28) : [4, 6, 9, 11].includes(m) ? 30 : 31;
}

// Howard Hinnant's civil-calendar algorithms.
function daysFromCivil(y: number, m: number, d: number): number {
  if (m <= 2) y -= 1;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

function civilFromDays(z: number): [number, number, number] {
  z += 719468;
  const era = Math.floor(z / 146097);
  const doe = z - era * 146097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const m = mp < 10 ? mp + 3 : mp - 9;
  return [yoe + era * 400 + (m <= 2 ? 1 : 0), m, d];
}

export interface ParsedDate {
  day: Day;
  kind: "iso" | "slash" | "mdy" | "dmy";
  monthToken: string;
  dot: string;
  ordinal: boolean;
  hasYear: boolean;
  padFirst: boolean;
  padSecond: boolean;
  dayfirst: boolean;
}

function parsed(day: Day, kind: ParsedDate["kind"], extra: Partial<ParsedDate> = {}): ParsedDate {
  return {
    day, kind, monthToken: "", dot: "", ordinal: false, hasYear: true, padFirst: false, padSecond: false,
    dayfirst: false, ...extra,
  };
}

function monthNumber(token: string): number {
  return MONTH_KEYS.get(token.slice(0, 3).toLowerCase())!;
}

/** Parse one detected date. Returns null if it is not a real calendar day (say, February 30). */
export function parse(text: string, defaultYear: number, dayfirst = false): ParsedDate | null {
  let m = ISO.exec(text);
  if (m) {
    const day = Day.of(Number(m[1]), Number(m[2]), Number(m[3]));
    return day ? parsed(day, "iso") : null;
  }
  m = SLASH.exec(text);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    const [month, dom] = dayfirst ? [b, a] : [a, b];
    const day = Day.of(Number(m[3]), month, dom);
    if (!day) return null;
    return parsed(day, "slash", { padFirst: m[1].length === 2, padSecond: m[2].length === 2, dayfirst });
  }
  m = MDY.exec(text);
  if (m) {
    const year = m[5] !== undefined ? Number(m[5]) : defaultYear;
    const day = Day.of(year, monthNumber(m[1]), Number(m[3]));
    if (!day) return null;
    return parsed(day, "mdy", { monthToken: m[1], dot: m[2], ordinal: m[4] !== undefined, hasYear: m[5] !== undefined });
  }
  m = DMY.exec(text);
  if (m) {
    const year = m[5] !== undefined ? Number(m[5]) : defaultYear;
    const day = Day.of(year, monthNumber(m[3]), Number(m[1]));
    if (!day) return null;
    return parsed(day, "dmy", { monthToken: m[3], dot: m[4], ordinal: m[2] !== undefined, hasYear: m[5] !== undefined });
  }
  return null;
}

function ordinalOf(n: number): string {
  const r = n % 100;
  if (r >= 11 && r <= 13) return `${n}th`;
  const suffix = ({ 1: "st", 2: "nd", 3: "rd" } as Record<number, string>)[n % 10] ?? "th";
  return `${n}${suffix}`;
}

/** Render a month in the same style as `token`: full name, 'Sept', or three letters. */
function monthLike(token: string, month: number): string {
  const full = MONTHS[month - 1];
  const t = token.toLowerCase();
  if (t === "may") return full; // "May" reads as a full name, so keep full names
  if (t === "sept") return month === 9 ? "Sept" : full.slice(0, 3);
  if (t.length === 3) return full.slice(0, 3);
  return full;
}

export function render(day: Day, like: ParsedDate): string {
  if (like.kind === "iso") return day.isoformat();
  if (like.kind === "slash") {
    const [first, second] = like.dayfirst ? [day.day, day.month] : [day.month, day.day];
    const a = like.padFirst ? pad2(first) : String(first);
    const b = like.padSecond ? pad2(second) : String(second);
    return `${a}/${b}/${day.year}`;
  }
  const month = monthLike(like.monthToken, day.month);
  const dom = like.ordinal ? ordinalOf(day.day) : String(day.day);
  if (like.kind === "mdy") {
    return `${month}${like.dot} ${dom}` + (like.hasYear ? `, ${day.year}` : "");
  }
  return `${dom} ${month}${like.dot}` + (like.hasYear ? ` ${day.year}` : "");
}

// Context around a date. Both lists live in data/pools.json so every SDK reads the same words.
let holidayRe: RegExp | null = null;
let birthRe: RegExp | null = null;

function wordsRe(items: string[]): RegExp {
  const alts = [...new Set(items.map(escapeRegExp))].sort((a, b) => cpLength(b) - cpLength(a) || cmpCodePoints(a, b));
  return new RegExp("(?<![A-Za-z])(?:" + alts.join("|") + ")(?![A-Za-z])", "iu");
}

function context(text: string): string {
  return text.replaceAll("’", "'");
}

/**
 * True when a holiday is named right next to the date ("Christmas Day, December 25"). Such a date stays as it is:
 * the holiday already names the day, and a shifted date would contradict it.
 */
export function nearHoliday(text: string, start: number, end: number): boolean {
  holidayRe ??= wordsRe(pools().holidays);
  return holidayRe.test(context(text.slice(Math.max(0, start - 30), start) + " " + text.slice(end, end + 20)));
}

/** True when the words just before the date say it is a birth date. */
export function nearBirth(text: string, start: number): boolean {
  birthRe ??= wordsRe(pools().birth_cues);
  return birthRe.test(context(text.slice(Math.max(0, start - 40), start)));
}

/** Whole years from `born` to `on`, the way people count their age. */
export function age(born: Day, on: Day): number {
  const before = on.month < born.month || (on.month === born.month && on.day < born.day);
  return on.year - born.year - (before ? 1 : 0);
}
