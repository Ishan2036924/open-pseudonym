"""Putting real values back into what the model wrote.

Four kinds of match, all found in one pass and settled earliest-first, longest-first:
  1. exact stand-ins the vault issued (names match as written or in capitals; emails and links in any case)
  2. handles {{TYPE_n}}, which become a label for display, or the real value when a caller is allowed to see it
  3. digits: a fake phone or card the model reformatted ("617-555-0142" for "(617) 555-0142")
  4. dates: a shifted date the model wrote in another format ("March 12" for "2026-03-12")

The streaming restorer holds back only the tail of the text that could still be the start of a stand-in, so the
person sees words appear almost as fast as without us, and never sees half a fake name.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from typing import Callable

from . import dates
from ._data import patterns as shared_patterns
from .fakes import fill_template
from .handles import HANDLE
from .types import CASELESS_TYPES, DIGIT_TYPES, digits_of
from .vault import Vault

NB = "(?<![A-Za-z0-9_])"
NA = "(?![A-Za-z0-9_])"
TAG = re.compile(r"\[([A-Z][A-Z0-9_]*)_([0-9]+)\]")
DIGIT_RUN = re.compile(r"(?<![0-9])\+?[0-9](?:[ .()-]{0,2}[0-9]){5,22}(?![0-9])")
_DATE_REGEXES = None


def _date_regexes():
    global _DATE_REGEXES
    if _DATE_REGEXES is None:
        _DATE_REGEXES = [(re.compile(p["pattern"], re.I if "i" in p["flags"] else 0), p["group"])
                         for p in shared_patterns() if p["type"] == "DATE"]
    return _DATE_REGEXES


@dataclass(frozen=True)
class Match:
    start: int
    end: int
    replacement: str
    entry_id: str | None
    kind: str  # exact | handle | digits | date


class Restorer:
    """A snapshot of the vault's stand-ins, compiled for fast matching. Rebuild it when the vault changes."""

    def __init__(self, vault: Vault, default_year: int = 2000, dayfirst: bool = False):
        self.vault = vault
        self.version = vault.version
        self.default_year = default_year
        self.dayfirst = dayfirst
        self.case: dict[str, tuple[str, str]] = {}  # stand-in -> (real, entry id)
        self.nocase: dict[str, tuple[str, str]] = {}  # lower stand-in -> (real, entry id)
        self.digits: dict[str, tuple[str, str, str]] = {}  # stand-in digits -> (real surface, entry id, type)
        self.dates: dict[str, tuple[str, str]] = {}  # shifted ISO day -> (real ISO day, entry id)
        self.handles: dict[str, str] = {}  # handle text -> entry id
        longest = 0
        for e in vault.entries:
            if not e.restorable:
                continue
            if e.action == "handle":
                self.handles[e.stand_in] = e.id
                longest = max(longest, len(e.stand_in))
                continue
            for fake, real in e.surfaces.items():
                longest = max(longest, len(fake))
                if e.type in CASELESS_TYPES or e.action == "token":
                    self.nocase.setdefault(fake.lower(), (real, e.id))
                else:
                    self.case.setdefault(fake, (real, e.id))
                    if fake.upper() != fake:
                        self.case.setdefault(fake.upper(), (real.upper(), e.id))
                if e.type in DIGIT_TYPES and e.action in ("fake", "fpe"):
                    fd = digits_of(fake)
                    self.digits.setdefault(fd, (real, e.id, e.type))
                    if e.type == "PHONE" and len(fd) == 11 and fd[0] == "1":
                        self.digits.setdefault(fd[1:], (real, e.id, e.type))
            if e.type == "DATE" and e.action == "shift":
                self.dates[e.meta["shifted"]] = (e.meta["day"], e.id)
        for fake_low, real_part in vault.parts_back.items():
            owner = self._part_owner(fake_low)
            fake = vault.parts[real_part.lower()]
            longest = max(longest, len(fake))
            self.case.setdefault(fake, (real_part, owner))
            self.case.setdefault(fake.upper(), (real_part.upper(), owner))
        self.longest = max(longest, 40)
        self._case_re = _union(self.case.keys(), 0)
        self._nocase_re = _union(self.nocase.keys(), re.IGNORECASE)

    def _part_owner(self, fake_low: str) -> str:
        for e in self.vault.entries:
            if e.type == "PERSON" and any(fake_low in s.lower().split() for s in e.surfaces):
                return e.id
        return "part"

    # Matching

    def matches(self, text: str, pos: int = 0, reveal: Callable[[str], str] | None = None) -> list[Match]:
        found: list[Match] = []
        if self._case_re:
            for m in self._case_re.finditer(text, pos):
                real, eid = self.case[m[1]]
                found.append(Match(m.start(1), m.end(1), real, eid, "exact"))
        if self._nocase_re:
            for m in self._nocase_re.finditer(text, pos):
                real, eid = self.nocase[m[1].lower()]
                found.append(Match(m.start(1), m.end(1), real, eid, "exact"))
        for m in HANDLE.finditer(text, pos):
            eid = self.handles.get(m[0])
            if eid is not None:
                entry = self.vault.by_id(eid)
                shown = reveal(eid) if reveal else f"[{entry.meta['description']}]"
                found.append(Match(m.start(), m.end(), shown, eid, "handle"))
        if self.digits:
            for m in DIGIT_RUN.finditer(text, pos):
                hit = self.digits.get(digits_of(m[0]))
                if hit:
                    real, eid, _ = hit
                    found.append(Match(m.start(), m.end(), _real_in_shape(real, m[0]), eid, "digits"))
        if self.dates:
            for regex, group in _date_regexes():
                for m in regex.finditer(text, pos):
                    s, e = m.span(group)
                    parsed = dates.parse(text[s:e], self.default_year, self.dayfirst)
                    if parsed is None:
                        continue
                    hit = self.dates.get(parsed.day.isoformat())
                    if hit:
                        real_day = dt.date.fromisoformat(hit[0])
                        found.append(Match(s, e, dates.render(real_day, parsed), hit[1], "date"))
        return _settle(found)

    def restore(self, text: str, reveal: Callable[[str], str] | None = None) -> str:
        return apply(text, self.matches(text, 0, reveal))

    def unknown(self, text: str) -> list[str]:
        """Tags and handles that look like ours but are not in the vault (the model made them up)."""
        out = []
        for m in TAG.finditer(text):
            if m[0] not in self.case:
                out.append(m[0])
        for m in HANDLE.finditer(text):
            if m[0] not in self.handles:
                out.append(m[0])
        return out


def _union(forms, flags) -> re.Pattern | None:
    forms = sorted(set(forms), key=lambda s: (-len(s), s))
    if not forms:
        return None
    return re.compile(NB + "(" + "|".join(re.escape(f) for f in forms) + ")" + NA, flags)


def _settle(found: list[Match]) -> list[Match]:
    out: list[Match] = []
    end = -1
    for m in sorted(found, key=lambda m: (m.start, -(m.end - m.start))):
        if m.start >= end:
            out.append(m)
            end = m.end
    return out


def _real_in_shape(real: str, written: str) -> str:
    """The real number, laid out the way the model wrote the fake one when the digit counts line up."""
    rd, wd = digits_of(real), digits_of(written)
    if len(rd) == len(wd):
        return fill_template(written, rd)
    if len(rd) == len(wd) + 1 and rd[0] == "1":  # the model dropped a leading +1
        return fill_template(written, rd[1:])
    return real


def _shift(matches: list[Match], offset: int) -> list[Match]:
    return [Match(m.start - offset, m.end - offset, m.replacement, m.entry_id, m.kind) for m in matches]


def apply(text: str, matches: list[Match]) -> str:
    parts, last = [], 0
    for m in matches:
        parts.append(text[last:m.start])
        parts.append(m.replacement)
        last = m.end
    parts.append(text[last:])
    return "".join(parts)


class StreamRestorer:
    """Feed it chunks of model output as they arrive; it returns restored text that is safe to show.

    A stand-in is at most `longest` characters, so any match that starts more than `longest` characters before the
    end of what we have is already complete. We emit up to that point (never cutting a match in half) and keep the
    tail. One character of context is kept so word-edge checks work across the cut.
    """

    def __init__(self, get_restorer: Callable[[], Restorer], reveal: Callable[[str], str] | None = None):
        self._get = get_restorer
        self._reveal = reveal
        self._buf = ""
        self._prev = ""

    def feed(self, chunk: str) -> str:
        self._buf += chunk
        r = self._get()
        hold = r.longest + 1
        if len(self._buf) <= hold:
            return ""
        context = self._prev + self._buf
        offset = len(self._prev)
        found = r.matches(context, offset, self._reveal)
        cut = len(self._buf) - hold
        for m in found:
            ms, me = m.start - offset, m.end - offset
            if ms < cut < me:
                cut = ms
        emit = [m for m in found if m.end - offset <= cut]
        out = apply(self._buf[:cut], _shift(emit, offset))
        if cut > 0:
            self._prev = self._buf[cut - 1]
            self._buf = self._buf[cut:]
        return out

    def flush(self) -> str:
        r = self._get()
        context = self._prev + self._buf
        offset = len(self._prev)
        found = r.matches(context, offset, self._reveal)
        out = apply(self._buf, _shift(found, offset))
        self._buf, self._prev = "", ""
        return out
