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


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def digest(data: bytes) -> str:
    """The digest string used everywhere in the spec: 'sha-256:' plus base64url without padding."""
    return "sha-256:" + b64url(hashlib.sha256(data).digest())
