"""Checksums and sanity checks that turn a pattern match into a confident detection.

A 16-digit run is only a card if the Luhn digit adds up; nine digits after "routing" are only a routing number if
the ABA weights do. These checks remove most false alarms (order numbers, tracking ids) for free.
"""

from __future__ import annotations

from ._data import pools
from .types import digits_of

# IBAN lengths per country (ISO 13616 registry). Unknown countries are rejected rather than guessed.
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AT": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29, "CH": 21, "CY": 28, "CZ": 24, "DE": 22,
    "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27,
    "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LI": 21,
    "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MT": 31, "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25,
    "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "TR": 26, "UA": 29, "VA": 22,
}


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_digit(partial: str) -> str:
    """The check digit that makes partial + digit pass Luhn."""
    for d in "0123456789":
        if luhn_ok(partial + d):
            return d
    raise AssertionError("unreachable")


def card_ok(value: str) -> bool:
    d = digits_of(value)
    if not 13 <= len(d) <= 19 or not luhn_ok(d) or len(set(d)) == 1:
        return False
    if d[0] in "3456":
        return True
    return d[0] == "2" and 2221 <= int(d[:4]) <= 2720


def iban_numeric(iban: str) -> int:
    moved = iban[4:] + iban[:4]
    return int("".join(str(int(ch, 36)) for ch in moved))


def iban_ok(value: str) -> bool:
    s = "".join(value.split()).upper()
    if IBAN_LENGTHS.get(s[:2]) != len(s) or not s.isascii() or not s.isalnum():
        return False
    return iban_numeric(s) % 97 == 1


def aba_sum(d: str) -> int:
    return 3 * (int(d[0]) + int(d[3]) + int(d[6])) + 7 * (int(d[1]) + int(d[4]) + int(d[7])) + (
        int(d[2]) + int(d[5]) + int(d[8])
    )


def aba_ok(value: str) -> bool:
    d = digits_of(value)
    if len(d) != 9:
        return False
    prefix = int(d[:2])
    if not (prefix <= 12 or 21 <= prefix <= 32 or 61 <= prefix <= 72 or prefix == 80):
        return False
    return aba_sum(d) % 10 == 0


def ssn_ok(value: str) -> bool:
    d = digits_of(value)
    if len(d) != 9:
        return False
    area, group, serial = d[:3], d[3:5], d[5:]
    return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"


def phone_ok(value: str) -> bool:
    return 10 <= len(digits_of(value)) <= 15


def name_ok(value: str) -> bool:
    stop = _stopwords()
    tokens = value.split()
    return bool(tokens) and all(t.lower() not in stop and len(t) >= 2 for t in tokens)


_STOP: frozenset[str] | None = None


def _stopwords() -> frozenset[str]:
    global _STOP
    if _STOP is None:
        _STOP = frozenset(w.lower() for w in pools()["name_stopwords"])
    return _STOP
