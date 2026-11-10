"""The data types the standard knows about, and how each one is normalised for comparison.

Two mentions are "the same thing" when their normalised forms match, so "Dana  Reyes" and "dana reyes" share one
entry, and "(617) 555-0142" and "617.555.0142" do too.
"""

from __future__ import annotations

import re

TYPES = (
    "PERSON", "ORG", "LOCATION", "ADDRESS", "EMAIL", "PHONE", "URL", "IP_ADDRESS", "DATE", "MONEY",
    "CARD", "IBAN", "ROUTING", "BANK_ACCOUNT", "SSN", "API_KEY", "PASSWORD", "OTP", "ID", "USERNAME",
)

# Values the model only ever needs to move from one place to another, never to read.
SECRET_TYPES = frozenset({"CARD", "IBAN", "ROUTING", "BANK_ACCOUNT", "SSN", "API_KEY", "PASSWORD", "OTP"})

# Types whose identity is their digits; separators and spacing do not matter.
DIGIT_TYPES = frozenset({"CARD", "PHONE", "SSN", "ROUTING", "BANK_ACCOUNT", "OTP"})

# Types where a match is case-insensitive (an email address is the same in any case).
CASELESS_TYPES = frozenset({"EMAIL", "URL", "USERNAME"})

_TYPE_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")


def check_type_name(name: str) -> str:
    """Apps may add their own types (EMPLOYEE_ID, CASE_NUMBER...). They must look like the built-in ones."""
    if not isinstance(name, str) or not _TYPE_NAME.fullmatch(name):
        raise ValueError(f"type names are upper case letters, digits and underscores, got {name!r}")
    return name


def digits_of(value: str) -> str:
    return "".join(ch for ch in value if "0" <= ch <= "9")


def normalize(type_: str, value: str) -> str:
    """The comparison key for a value of a given type."""
    if type_ in DIGIT_TYPES:
        return digits_of(value)
    if type_ == "IBAN":
        return "".join(value.split()).upper()
    if type_ in CASELESS_TYPES:
        return value.strip().lower()
    if type_ == "DATE":
        # dates are compared by the day they name, which the session works out; this is only a fallback
        return value.strip().lower()
    return " ".join(value.split()).lower()
