"""Canonical JSON (RFC 8785) for the shapes we sign: objects, arrays, strings, integers, booleans and null.

We never sign floats, which keeps this small. Keys are sorted by UTF-16 code units, as RFC 8785 asks; that matters
only for keys outside the Basic Multilingual Plane, which we never use, but it costs nothing to get right.
"""

from __future__ import annotations

import base64
import hashlib
import json


def _utf16_key(s: str) -> list[int]:
    return list(s.encode("utf-16-be"))


def canonical(value) -> bytes:
    return _enc(value).encode("utf-8")


def _enc(v) -> str:
    if v is None or isinstance(v, bool) or isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        raise TypeError("floats are not allowed in signed objects; use integers")
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_enc(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=_utf16_key)
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _enc(v[k]) for k in keys) + "}"
    raise TypeError(f"cannot sign a {type(v).__name__}")


def canonical_args(value) -> bytes:
    """Canonical JSON for tool-call arguments. Unlike `canonical`, it accepts floats (written the way JavaScript
    writes them, as RFC 8785 asks), because a model's arguments may hold any JSON number. Not for signed objects."""
    return _enc_loose(value).encode("utf-8")


def _es6_number(x: float) -> str:
    if x != x or x in (float("inf"), float("-inf")):
        raise TypeError("NaN and infinity are not JSON")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    text = repr(abs(x))
    mant, _, exp = text.partition("e")
    whole, _, frac = mant.partition(".")
    run = whole + frac
    lead = len(run) - len(run.lstrip("0"))
    digits = run[lead:].rstrip("0")
    n = len(whole) - lead + (int(exp) if exp else 0)  # the value is 0.DIGITS x 10^n
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * -n + digits
    else:
        e = n - 1
        tail = ("e+" if e >= 0 else "e-") + str(abs(e))
        out = digits + tail if k == 1 else digits[0] + "." + digits[1:] + tail
    return sign + out


def _enc_loose(v) -> str:
    if isinstance(v, float):
        return _es6_number(v)
    if isinstance(v, int) and not isinstance(v, bool):
        # RFC 8785 numbers are IEEE doubles: an integer past 2^53 is written as the nearest double, as JavaScript does
        return str(v) if -(2 ** 53) <= v <= 2 ** 53 else _es6_number(float(v))  # float() raises OverflowError past 1e308
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_enc_loose(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=_utf16_key)
        return "{" + ",".join(_enc_str(k) + ":" + _enc_loose(v[k]) for k in keys) + "}"
    if isinstance(v, str):
        return _enc_str(v)
    return _enc(v)


def _enc_str(s: str) -> str:
    # a lone surrogate is not text: canonical_args() ends in .encode("utf-8"), which refuses it with UnicodeEncodeError,
    # where JavaScript would escape it; the TypeScript SDK refuses it too, so both give no canonical form
    return json.dumps(s, ensure_ascii=False)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def digest(data: bytes) -> str:
    """The digest string used everywhere in the spec: 'sha-256:' plus base64url without padding."""
    return "sha-256:" + b64url(hashlib.sha256(data).digest())
