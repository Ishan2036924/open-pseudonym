"""Reading and writing the date formats we detect, so a shifted date comes back in the same shape.

If the text says "Thu, March 5", the shifted version must still look like "March 12" and not "2026-03-12";
otherwise the model notices the seams. Every format we parse, we can also render.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass

MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
          "November", "December"]
_MONTH_KEYS = {m[:3].lower(): i + 1 for i, m in enumerate(MONTHS)}
_MON = r"(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"

_ISO = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})$")
_SLASH = re.compile(r"^([0-9]{1,2})/([0-9]{1,2})/([0-9]{4})$")
_MDY = re.compile(r"^" + _MON + r"(\.?) ([0-9]{1,2})(st|nd|rd|th)?(?:, ([0-9]{4}))?$")
_DMY = re.compile(r"^([0-9]{1,2})(st|nd|rd|th)? " + _MON + r"(\.?)(?: ([0-9]{4}))?$")


@dataclass(frozen=True)
class ParsedDate:
    day: dt.date
    kind: str  # iso | slash | mdy | dmy
    month_token: str = ""
    dot: str = ""
    ordinal: bool = False
    has_year: bool = True
    pad_first: bool = False
    pad_second: bool = False
    dayfirst: bool = False


def _month_number(token: str) -> int:
    return _MONTH_KEYS[token[:3].lower()]


def _safe_date(y: int, m: int, d: int) -> dt.date | None:
    try:
        return dt.date(y, m, d)
    except ValueError:
        return None


def parse(text: str, default_year: int, dayfirst: bool = False) -> ParsedDate | None:
    """Parse one detected date. Returns None if it is not a real calendar day (say, February 30)."""
    m = _ISO.match(text)
    if m:
        day = _safe_date(int(m[1]), int(m[2]), int(m[3]))
        return ParsedDate(day, "iso") if day else None
    m = _SLASH.match(text)
    if m:
        a, b, y = int(m[1]), int(m[2]), int(m[3])
        month, dom = (b, a) if dayfirst else (a, b)
        day = _safe_date(y, month, dom)
        if not day:
            return None
        return ParsedDate(day, "slash", pad_first=len(m[1]) == 2, pad_second=len(m[2]) == 2, dayfirst=dayfirst)
    m = _MDY.match(text)
    if m:
        year = int(m[5]) if m[5] else default_year
        day = _safe_date(year, _month_number(m[1]), int(m[3]))
        if not day:
            return None
        return ParsedDate(day, "mdy", month_token=m[1], dot=m[2], ordinal=bool(m[4]), has_year=bool(m[5]))
    m = _DMY.match(text)
    if m:
        year = int(m[5]) if m[5] else default_year
        day = _safe_date(year, _month_number(m[3]), int(m[1]))
        if not day:
            return None
        return ParsedDate(day, "dmy", month_token=m[3], dot=m[4], ordinal=bool(m[2]), has_year=bool(m[5]))
    return None


def _ordinal(n: int) -> str:
    if 11 <= n % 100 <= 13:
        return f"{n}th"
    return f"{n}" + {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")


def _month_like(token: str, month: int) -> str:
    """Render a month in the same style as `token`: full name, 'Sept', or three letters."""
    full = MONTHS[month - 1]
    t = token.lower()
    if t == "may":  # "May" reads as a full name, so keep full names
        return full
    if t == "sept":
        return "Sept" if month == 9 else full[:3]
    if len(t) == 3:
        return full[:3]
    return full


def render(day: dt.date, like: ParsedDate) -> str:
    if like.kind == "iso":
        return day.isoformat()
    if like.kind == "slash":
        first, second = (day.day, day.month) if like.dayfirst else (day.month, day.day)
        a = f"{first:02d}" if like.pad_first else str(first)
        b = f"{second:02d}" if like.pad_second else str(second)
        return f"{a}/{b}/{day.year}"
    month = _month_like(like.month_token, day.month)
    dom = _ordinal(day.day) if like.ordinal else str(day.day)
    if like.kind == "mdy":
        out = f"{month}{like.dot} {dom}"
        return out + (f", {day.year}" if like.has_year else "")
    out = f"{dom} {month}{like.dot}"
    return out + (f" {day.year}" if like.has_year else "")
