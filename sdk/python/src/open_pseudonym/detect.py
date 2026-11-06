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
from ._data import patterns as shared_patterns
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
        self._compiled = [self._compile(p) for p in [*shared_patterns(), *extra]]

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
                self._lookup[("case", variant)] = type_
                case_alts.append(variant)
        nocase_alts = []
        for type_, text in by_mode["nocase"]:
            self._lookup[("nocase", text.lower())] = type_
            nocase_alts.append(text)
        if case_alts:
            self._regexes.append((re.compile(NB + "(" + _alternation(case_alts) + ")" + NA), "case"))
        if nocase_alts:
            self._regexes.append(
                (re.compile(NB + "(" + _alternation(nocase_alts) + ")" + NA, re.IGNORECASE), "nocase")
            )
        self._digit_forms = []
        for type_, digits in by_mode["digits"]:
            if len(digits) >= 6:
                pattern = "(?<![0-9])[(+]?" + "[ .()+-]{0,2}".join(digits) + "(?![0-9])"
                self._digit_forms.append((re.compile(pattern), type_))

    def detect(self, text: str) -> list[Span]:
        out = []
        for regex, mode in self._regexes:
            for m in regex.finditer(text):
                key = m[1] if mode == "case" else m[1].lower()
                type_ = self._lookup.get((mode, key))
                if type_:
                    out.append(Span(m.start(1), m.end(1), type_, m[1], "known", self.PRIORITY))
        for regex, type_ in self._digit_forms:
            for m in regex.finditer(text):
                out.append(Span(m.start(), m.end(), type_, m[0], "known", self.PRIORITY))
        return out


def _alternation(alts: list[str]) -> str:
    # longest first, so "Dana Reyes" wins over "Dana"
    return "|".join(re.escape(a) for a in sorted(set(alts), key=lambda s: (-len(s), s)))


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
