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


# Stable codes for every way a handle can be refused. The human text of `reason` may be reworded one day; a code
# never is, so an app and a release record (spec 10.4) can rely on it.
CODES = ("unknown_handle", "unbound", "expired", "used_up", "wrong_tool", "wrong_site", "needs_approval",
         "not_approved", "not_recorded", "malformed")


class HandleRefused(Exception):
    """The real value was not filled in. `reason` is one short phrase, safe to show and to log; `code` is the stable
    name of the reason (one of CODES), or None for a refusal that is not a release decision."""

    def __init__(self, handle: str, reason: str, code: str | None = None):
        super().__init__(f"{handle}: {reason}")
        self.handle = handle
        self.reason = reason
        self.code = code


@dataclass(frozen=True)
class Approval:
    """What an approval callback may return instead of a plain yes or no, so the release record can say who allowed
    the release. `ref` and `digest` let an app pass the id and the token digest of an OAC Consent."""

    allowed: bool
    by: str | None = None
    channel: str | None = None
    ref: str | None = None
    digest: str | None = None


DIGEST = re.compile(r"^sha-256:[A-Za-z0-9_-]{43}$")


def as_approval(answer) -> Approval:
    """Turn what an approval callback returned (a bool, an Approval, or a dict with the same fields) into an Approval.
    Anything else is a bug in the app and raises, so nothing is filled by accident."""
    if isinstance(answer, Approval):
        found = answer
    elif isinstance(answer, bool):
        found = Approval(answer)
    elif isinstance(answer, dict) and isinstance(answer.get("allowed"), bool):
        found = Approval(**{k: answer.get(k) for k in ("allowed", "by", "channel", "ref", "digest")})
    else:
        raise TypeError("an approval callback returns a bool or an Approval")
    for name in ("by", "channel", "ref"):
        v = getattr(found, name)
        if v is not None and (not isinstance(v, str) or not 0 < len(v) <= 256):
            raise ValueError(f"Approval.{name} must be a short string")
    if found.digest is not None and not (isinstance(found.digest, str) and DIGEST.match(found.digest)):
        raise ValueError("Approval.digest must look like sha-256:<43 characters>")
    if not isinstance(found.allowed, bool):
        raise TypeError("Approval.allowed must be a bool")
    return found


# Sensitive References (spec 10.5) are opaque to this SDK: a server keeps the value, the model only carries the
# reference. They look like `sref:<kind>:<id>` or `\u27e6sref:<kind>:<id>\u27e7`. We read only the strict form: a kind
# of lower-case letters, digits, "_" and "-" (1 to 32, starting with a letter) and an id that is a 26-character ULID
# (Crockford base32, upper case). A looser id would let a value hide inside a "reference". The bare form must not
# continue into more text ("...ULID.dana@example.org" is not a reference). We never mask a value that lies inside one,
# never make a stand-in for one, never restore or fill one, and never report one as a value the model wrote.
_SREF_BODY = r"sref:[a-z][a-z0-9_-]{0,31}:[0-9A-HJKMNP-TV-Z]{26}"
SREF = re.compile(r"\u27e6" + _SREF_BODY + r"\u27e7|(?<![A-Za-z0-9_@.-])" + _SREF_BODY
                  + r"(?![A-Za-z0-9_@-]|\.[A-Za-z0-9_@-])")


def sref_regions(text: str) -> list[tuple[int, int]]:
    """Where the sensitive references in `text` are, as (start, end) pairs."""
    return [(m.start(), m.end()) for m in SREF.finditer(text)]


def inside_sref(start: int, end: int, regions: list[tuple[int, int]]) -> bool:
    """True when the span lies fully inside one reference. A span that reaches outside is ordinary text."""
    return any(b <= start and end <= e for b, e in regions)


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
        raise HandleRefused(handle, "not bound to a site or tool", "unbound")
    if meta.get("expires_at") is not None and now >= meta["expires_at"]:  # gone at its expiry second
        raise HandleRefused(handle, "expired", "expired")
    if meta.get("uses_left") is not None and meta["uses_left"] <= 0:
        raise HandleRefused(handle, "already used", "used_up")
    tools = meta.get("tools")
    if tools and sink.tool not in tools:
        raise HandleRefused(handle, "not allowed for this tool", "wrong_tool")
    sites = meta.get("sites") or []
    if sites and not site_matches(sink.site, sites):
        raise HandleRefused(handle, "bound to a different site", "wrong_site")


def shown_digest(nonce: str, handle: str, description: str, tool: str | None, site: str | None) -> str:
    """The `shown` commitment of a release record (spec 10.4): a digest of the canonical JSON of what the approver was
    given, with the entry's secret nonce so that the digest hides the description. `site` is the host."""
    from .jcs import canonical, digest

    return digest(canonical({"nonce": nonce, "handle": handle, "description": description, "tool": tool, "site": site}))
