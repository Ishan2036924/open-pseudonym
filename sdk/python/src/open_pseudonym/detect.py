"""Finding personal data in text.

Three kinds of detector feed one list of spans:

  - PatternDetector: the shared patterns from data/patterns.json plus checksums (Luhn, IBAN, ABA...).
  - KnownDetector: exact values we already know about. Everything already in the vault is matched again, so a value
    that was hidden once is hidden every time after, even without the cue that found it the first time. Apps can
    also pass their own lists (contacts, the user's own company), which is the cheapest way to catch names.
  - Anything with a `detect(text) -> list[Span]` method: optional ML detectors such as GLiNER or spaCy
    (see `open_pseudonym.ml`).

Overlaps are settled by priority, then length: a known value beats a pattern, an email beats the name inside it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol

from . import checks, dates
from ._data import patterns as shared_patterns, pools
from .types import check_type_name

NB = "(?<![A-Za-z0-9_])"
NA = "(?![A-Za-z0-9_])"


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    type: str
    text: str
    source: str = "rules"
    priority: int = 50


class Detector(Protocol):
    def detect(self, text: str) -> list[Span]: ...


@dataclass
class _Compiled:
    type: str
    regex: re.Pattern
    group: int
    check: str | None
    priority: int


class PatternDetector:
    """The shared rule set. `dayfirst` and `default_year` only matter for reading dates."""

    def __init__(self, extra: Iterable[dict] = (), dayfirst: bool = False, default_year: Callable[[], int] | None = None):
        self.dayfirst = dayfirst
        self._default_year = default_year or (lambda: 2000)
        self._compiled = _shared_compiled() + [self._compile(p) for p in extra]

    @staticmethod
    def _compile(p: dict) -> _Compiled:
        flags = re.IGNORECASE if "i" in p.get("flags", "") else 0
        return _Compiled(check_type_name(p["type"]), re.compile(p["pattern"], flags), p.get("group", 0),
                         p.get("check"), p.get("priority", 50))

    def _passes(self, check: str | None, value: str) -> bool:
        if check is None:
            return True
        if check == "card":
            return checks.card_ok(value)
        if check == "iban":
            return checks.iban_ok(value)
        if check == "ssn":
            return checks.ssn_ok(value)
        if check == "aba":
            return checks.aba_ok(value)
        if check == "phone":
            return checks.phone_ok(value)
        if check == "name":
            return checks.name_ok(value)
        if check == "date":
            return dates.parse(value, self._default_year(), self.dayfirst) is not None
        raise ValueError(f"unknown check {check!r}")

    def detect(self, text: str) -> list[Span]:
        out = []
        for c in self._compiled:
            for m in c.regex.finditer(text):
                start, end = m.span(c.group)
                if start < 0 or start == end:
                    continue
                value = text[start:end]
                if self._passes(c.check, value):
                    out.append(Span(start, end, c.type, value, "rules", c.priority))
        return out


_SHARED: list[_Compiled] | None = None


def _shared_compiled() -> list[_Compiled]:
    """The shared patterns, compiled once per process: some are large word lists, and `re`'s own cache can drop
    them when an app compiles many other expressions."""
    global _SHARED
    if _SHARED is None:
        _SHARED = [PatternDetector._compile(p) for p in shared_patterns()]
    return list(_SHARED)


class KnownDetector:
    """Exact values: what the vault already holds plus lists the app hands over.

    `forms` is a list of (type, text, mode) where mode is:
      "case"   match as written, or in all capitals (names: "Maya" but not the word "maya")
      "nocase" match in any case (emails, links)
      "digits" match the same digits with any light formatting in between ("617 555 0142" = "(617) 555-0142")
    """

    PRIORITY = 100

    def __init__(self, forms: Iterable[tuple[str, str, str]]):
        by_mode: dict[str, list[tuple[str, str]]] = {"case": [], "nocase": [], "digits": []}
        seen = set()
        for type_, text, mode in forms:
            if not text or (type_, text, mode) in seen:
                continue
            seen.add((type_, text, mode))
            by_mode[mode].append((type_, text))
        self._lookup: dict[tuple[str, str], str] = {}
        self._regexes: list[tuple[re.Pattern, str]] = []
        case_alts = []
        for type_, text in by_mode["case"]:
            for variant in {text, text.upper()}:
                self._lookup[("case", _squash(variant))] = type_
                case_alts.append(variant)
        nocase_alts = []
        for type_, text in by_mode["nocase"]:
            self._lookup[("nocase", _squash(text).lower())] = type_
            nocase_alts.append(text)
        if case_alts:
            self._regexes.append((re.compile(NB + "(" + _alternation(case_alts) + ")" + NA), "case"))
        if nocase_alts:
            self._regexes.append(
                (re.compile(NB + "(" + _alternation(nocase_alts) + ")" + NA, re.IGNORECASE), "nocase")
            )
        # all known numbers in one regex; a match is mapped back to its type by its digits
        self._digit_types: dict[str, str] = {}
        for type_, digits in by_mode["digits"]:
            if len(digits) >= 6:
                self._digit_types.setdefault(digits, type_)
        self._digit_re = None
        if self._digit_types:
            alts = sorted(self._digit_types, key=lambda d: (-len(d), d))
            body = "|".join("[ .()+-]{0,2}".join(d) for d in alts)
            self._digit_re = re.compile("(?<![0-9])[(+]?(?:" + body + ")(?![0-9])")

    def detect(self, text: str) -> list[Span]:
        out = []
        for regex, mode in self._regexes:
            for m in regex.finditer(text):
                key = _squash(m[1]) if mode == "case" else _squash(m[1]).lower()
                type_ = self._lookup.get((mode, key))
                if type_:
                    out.append(Span(m.start(1), m.end(1), type_, m[1], "known", self.PRIORITY))
        if self._digit_re is not None:
            for m in self._digit_re.finditer(text):
                type_ = self._digit_types.get("".join(c for c in m[0] if "0" <= c <= "9"))
                if type_:
                    out.append(Span(m.start(), m.end(), type_, m[0], "known", self.PRIORITY))
        return out


_WS = "[ \\t\\r\\n\\u00a0]+"


def _squash(text: str) -> str:
    """Runs of whitespace as one space, so "Dana  Reyes" and "Dana\\nReyes" look up the same entry."""
    return " ".join(text.replace("\u00a0", " ").split())


def _alternation(alts: list[str]) -> str:
    # longest first, so "Dana Reyes" wins over "Dana"; words may be split by any run of whitespace
    words = sorted({_squash(a) for a in alts}, key=lambda s: (-len(s), s))
    return "|".join(_WS.join(re.escape(w) for w in a.split(" ")) for a in words)


def resolve(spans: Iterable[Span]) -> list[Span]:
    """Pick non-overlapping spans: higher priority first, then longer, then earlier. Returned in text order."""
    chosen: list[Span] = []
    taken: list[tuple[int, int]] = []
    for s in sorted(spans, key=lambda s: (-s.priority, -(s.end - s.start), s.start, s.type)):
        if any(s.start < e and b < s.end for b, e in taken):
            continue
        chosen.append(s)
        taken.append((s.start, s.end))
    return sorted(chosen, key=lambda s: s.start)


_TOKEN = re.compile(r"[^ \t\r\n ]+")


def resolve_people(spans: Iterable[Span]) -> list[Span]:
    """`resolve`, with two extra rules so a person is never half hidden.

    1. A name that contains a shorter name takes that name's priority. "Ms. Reyes" teaches us "Reyes"; later
       "Dana Reyes" must be hidden whole, not as "Dana" plus a fake surname. A full name whose surname is also a
       place ("Isla Fairbanks") beats the place.
    2. A name that loses to another type keeps the words that type did not cover: if "Reyes, TX" wins as a place,
       "Dana" in front of it is still a person.
    """
    spans = list(spans)
    people = [s for s in spans if s.type == "PERSON"]
    promoted = []
    for s in spans:
        if s.type == "PERSON":
            inner = [t.priority for t in people
                     if t is not s and s.start <= t.start and t.end <= s.end and t.end - t.start < s.end - s.start]
            surname_places = [t.priority + 1 for t in spans
                              if t.type == "LOCATION" and s.start < t.start and t.end == s.end]
            best = max([s.priority, *inner, *surname_places])
            if best > s.priority:
                s = Span(s.start, s.end, s.type, s.text, s.source, best)
        promoted.append(s)
    chosen = resolve(promoted)
    extra = []
    for s in promoted:
        if s.type != "PERSON" or s in chosen:
            continue
        rivals = [c for c in chosen if c.start < s.end and s.start < c.end]
        if not rivals or any(c.type == "PERSON" for c in rivals):
            continue
        run: list[tuple[int, int]] = []
        for m in _TOKEN.finditer(s.text):
            a, b = s.start + m.start(), s.start + m.end()
            if any(a < c.end and c.start < b for c in rivals):
                extra.extend(_name_run(run, s))
                run = []
            else:
                run.append((a, b))
        extra.extend(_name_run(run, s))
    return resolve(chosen + extra) if extra else chosen


def _name_run(run: list[tuple[int, int]], whole: Span) -> list[Span]:
    if not run:
        return []
    a, b = run[0][0], run[-1][1]
    text = whole.text[a - whole.start:b - whole.start]
    return [Span(a, b, "PERSON", text, whole.source, whole.priority)] if checks.name_ok(text) else []


_NAME_WORD = re.compile(r"[A-ZÀ-ÖØ-ÞĀ-Ž][A-Za-zÀ-ÖØ-öø-ÿĀ-ž'-]*[A-Za-zÀ-ÖØ-öø-ÿĀ-ž]")
_INITIAL = re.compile(r"[A-Z]\.")
_BREAKS = " \t\r\n(\"'"


def grow_names(spans: list[Span], text: str) -> list[Span]:
    """A name the vault or the app already knows ("Reyes") may sit next to a part we have not seen: "Dana Reyes",
    "D. Reyes", "met Zorblax Reyes". Grow such a span by one word on each side when that word reads as part of the
    name, so the whole person is hidden. Only known values grow; the patterns already take whole names."""
    data = pools()
    stop = checks.stopwords()
    given = data["name_gender"]
    places = data["places"]
    out = []
    for i, s in enumerate(spans):
        if s.type != "PERSON" or s.source != "known":
            out.append(s)
            continue
        lo = out[-1].end if out else 0
        hi = spans[i + 1].start if i + 1 < len(spans) else len(text)
        start, end = s.start, s.end
        if start >= 2 and text[start - 1] == " ":
            a = start - 1
            while a > lo and text[a - 1] not in _BREAKS:
                a -= 1
            word = text[a:start - 1]
            if a >= lo and word and word.lower() not in stop and word not in places and (
                    _INITIAL.fullmatch(word)
                    or (_NAME_WORD.fullmatch(word) and (word.lower() in given or not _sentence_start(text, a)))):
                start = a
        if " " not in s.text and end + 1 < hi and text[end] == " ":
            b = end + 1
            while b < hi and text[b] not in _BREAKS and text[b] not in ".,;:!?)":
                b += 1
            word = text[end + 1:b]
            if word and _NAME_WORD.fullmatch(word) and word.lower() not in stop and word not in places:
                end = b
        if (start, end) != (s.start, s.end):
            s = Span(start, end, s.type, text[start:end], s.source, s.priority)
        out.append(s)
    return out


def _sentence_start(text: str, at: int) -> bool:
    before = text[:at].rstrip(" \t")
    return not before or before[-1] in ".!?:\n\"(" or before.endswith("\n")
