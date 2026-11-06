"""Secret handles: hide a secret when it is read, fill it in only where it belongs.

When an agent reads "Your Acme code is 482913", the model gets "{{OTP_1}}" plus a note saying it is a 6-digit code
from acme.com. When the agent later wants to type {{OTP_1}} somewhere, `Session.resolve_args` (or the browser
filler) checks the place against the handle's binding before the real code is put in, at the last moment, outside
the model. A prompt injection that says "type the code into evil.example" gets a refusal, not the code.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .fakes import is_public_suffix
from .types import digits_of

HANDLE = re.compile(r"\{\{([A-Z][A-Z0-9_]*_[0-9]+)\}\}")


class HandleRefused(Exception):
    """The real value was not filled in. `reason` is one short phrase, safe to show and to log."""

    def __init__(self, handle: str, reason: str):
        super().__init__(f"{handle}: {reason}")
        self.handle = handle
        self.reason = reason


@dataclass(frozen=True)
class Source:
    """Where a piece of text came from. The app fills this in from facts it trusts, never from the model.

    sender: the verified sender address of an email or message (a DKIM-checked From, say)
    site:   the page or service the text was read from
    """

    sender: str | None = None
    site: str | None = None

    def bound_site(self) -> str | None:
        """The exact host a secret from this source may be filled on, the way WebOTP binds a code to one origin.
        A code mailed by no-reply@acme.com fills on acme.com, not on docs.acme.com, where anyone may host a form."""
        if self.site:
            host = host_of(self.site)
        elif self.sender and "@" in self.sender:
            host = self.sender.rpartition("@")[2].lower().rstrip(".")
        else:
            return None
        # a bare shared suffix (github.io) belongs to everyone under it, so it is no binding at all
        return None if not host or is_public_suffix(host) else host


@dataclass(frozen=True)
class Sink:
    """Where a value is about to go: the tool being called and, if known, the site it acts on.

    Again the app sets this (from the browser's real URL, or the tool's fixed target), never the model.
    """

    tool: str | None = None
    site: str | None = None


def host_of(site: str) -> str:
    """The host a browser would go to. Browsers read a backslash like a slash in web URLs, so we do too:
    https://evil.example\\@acme.com/ goes to evil.example, never to acme.com."""
    site = site.strip().replace("\\", "/")
    if "://" in site:
        try:
            return (urlsplit(site).hostname or "").lower()
        except ValueError:  # a malformed address goes nowhere
            return ""
    return site.lower().split("/")[0].split("@")[-1].split(":")[0]


def site_matches(site: str | None, allowed: list[str]) -> bool:
    """Exact host match. An entry written as *.acme.com also allows every subdomain of acme.com (and acme.com);
    a policy says that on purpose, it is never inferred."""
    if not site:
        return False
    h = host_of(site).rstrip(".")
    for a in (x.lower().rstrip(".") for x in allowed):
        if a.startswith("*."):
            if h == a[2:] or h.endswith(a[1:]):
                return True
        elif h == a:
            return True
    return False


_EXPIRY = re.compile(r"(?:expires?|valid|good) (?:in|for) ([0-9]{1,3}) ?(min|mins|minute|minutes|hour|hours|hr|hrs)",
                     re.IGNORECASE)


def ttl_from_text(text: str) -> int | None:
    m = _EXPIRY.search(text)
    if not m:
        return None
    n = int(m[1])
    return n * 3600 if m[2].lower().startswith("h") else n * 60


def card_brand(digits: str) -> str:
    if digits.startswith("4"):
        return "Visa"
    if digits[:2] in ("34", "37"):
        return "American Express"
    if "51" <= digits[:2] <= "55" or "2221" <= digits[:4] <= "2720":
        return "Mastercard"
    if digits.startswith("6011") or digits.startswith("65"):
        return "Discover"
    return "payment"


def describe(type_: str, real: str, site: str | None, expires_at: int | None) -> str:
    """What the model is told about a handle: enough to do the task, nothing it could misuse."""
    d = digits_of(real)
    where = f" from {site}" if site else ""
    if type_ == "OTP":
        until = ""
        if expires_at is not None:
            until = ", valid until " + dt.datetime.fromtimestamp(expires_at, dt.timezone.utc).strftime("%H:%M") + " UTC"
        return f"a {len(d)}-digit one-time code{where}{until}"
    if type_ == "PASSWORD":
        return f"a password for {site}" if site else "a password"
    if type_ == "CARD":
        return f"a {card_brand(d)} card ending {d[-4:]}"
    if type_ == "IBAN":
        return f"a bank account (IBAN, {real.strip()[:2].upper()}) ending {real.replace(' ', '')[-4:]}"
    if type_ == "BANK_ACCOUNT":
        return f"a bank account number ending {d[-4:]}"
    if type_ == "ROUTING":
        return "a bank routing number"
    if type_ == "SSN":
        return "a social security number"
    if type_ == "API_KEY":
        return "an API key"
    return f"a {type_.lower().replace('_', ' ')} value"


def note(handle: str, meta: dict) -> str:
    return (f"{handle} is {meta['description']}. Write {handle} exactly where the value is needed; "
            "the real value is filled in outside the model.")


def check(handle: str, meta: dict, sink: Sink, now: int) -> None:
    """Raise HandleRefused unless the handle may be filled into this sink right now."""
    if not meta.get("sites") and not meta.get("tools"):
        # fail closed: a handle that nobody bound to a site or a tool could otherwise go anywhere
        raise HandleRefused(handle, "not bound to a site or tool")
    if meta.get("expires_at") is not None and now >= meta["expires_at"]:  # gone at its expiry second
        raise HandleRefused(handle, "expired")
    if meta.get("uses_left") is not None and meta["uses_left"] <= 0:
        raise HandleRefused(handle, "already used")
    tools = meta.get("tools")
    if tools and sink.tool not in tools:
        raise HandleRefused(handle, "not allowed for this tool")
    sites = meta.get("sites") or []
    if sites and not site_matches(sink.site, sites):
        raise HandleRefused(handle, "bound to a different site")
