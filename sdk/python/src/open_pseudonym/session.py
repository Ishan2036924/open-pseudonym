"""The session: one conversation, task or batch, with one policy and one vault.

    s = Session("draft_reply")
    masked = s.mask(email_text, source=Source(sender="no-reply@acme.com"))
    answer = call_your_model(masked.text, masked.notes)
    print(s.restore(answer))

Everything the model sees goes through `mask`; everything it says comes back through `restore`, `stream` or
`resolve_args`. The vault stays here.
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import hmac
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from . import dates, fakes, handles
from .checks import aba_ok, ambiguous_names, cue_only, luhn_ok, ssn_ok, stopwords
from .detect import KnownDetector, PatternDetector, Span, grow_names, resolve, resolve_people
from .egress import EgressLeak, EgressLog, Leak, blank_stand_ins, check as egress_check, known_mode
from .fakes import Ctx, fill_template
from .fpe import FF1
from .handles import HANDLE, HandleRefused, Sink, Source
from .policy import Policy, Rule, load_profile
from .restore import Restorer, StreamRestorer
from .types import DIGIT_TYPES, digits_of, normalize
from .vault import Entry, Vault

MAX_TEXT_TTL = 3600  # an expiry read from text alone is capped at one hour
GENERAL = {
    "PERSON": "someone", "ORG": "an organization", "LOCATION": "a place", "ADDRESS": "a street address",
    "EMAIL": "an email address", "PHONE": "a phone number", "URL": "a web link", "IP_ADDRESS": "an IP address",
}
MONEY_PREFIX = re.compile(r"^([$€£])( ?)([0-9][0-9,]*)(\.[0-9]{2})?$")
MONEY_SUFFIX = re.compile(r"^([0-9][0-9,]*)(\.[0-9]{2})?( ?)(USD|EUR|GBP|dollars|euros)$")
# Keys whose string values must reach the provider exactly as written, or the protocol breaks: ids that come back,
# roles, the model name, media types, and signed or encrypted blobs. Masking leaves them alone; the egress check still
# reads them, so personal data hidden under one of these names stops the request instead of slipping out.
SKIP_KEYS = frozenset({"role", "type", "id", "tool_call_id", "tool_use_id", "call_id", "media_type",
                       "mime_type", "mimeType", "cache_control",
                       # the same structure as the Vercel AI SDK spells it
                       "toolCallId", "toolName", "mediaType"})
# Only at the top of a request body: the model name.
TOP_KEYS = frozenset({"model"})
REASONING_TYPES = frozenset({"thinking", "redacted_thinking", "reasoning"})
_BASE64 = re.compile(r"[A-Za-z0-9+/=_\-\s]*")


def is_binary(key: str | None, value: str, parent: dict | None) -> bool:
    """Real base64 payloads (images, PDFs) are not text we can mask; leave them byte for byte. Only strings that
    really are base64 count, so text dressed up as a data: URL is still masked and checked."""
    if value.startswith("data:") and ";base64," in value[:100]:
        return _BASE64.fullmatch(value.split(";base64,", 1)[1]) is not None
    if key == "data" and parent is not None and parent.get("type") == "base64":
        return _BASE64.fullmatch(value) is not None
    return False


def is_signed_thinking(key: str | None, parent: dict | None) -> bool:
    """Model reasoning blocks are signed or encrypted by the provider and must go back unchanged. The model only
    ever saw stand-ins, so they hold stand-ins, never real values. Only inside such a block: a `signature` key
    anywhere else is ordinary content."""
    kind = parent.get("type") if parent is not None else None
    if not isinstance(kind, str) or kind not in REASONING_TYPES:  # odd input (a list as type) is just content
        return False
    return key in ("thinking", "signature", "encrypted_content") or (
        key == "data" and parent.get("type") == "redacted_thinking")


_TEXT_MEDIA = re.compile(r"^(text/|application/(json|xml|csv|x-yaml|yaml))", re.IGNORECASE)


def text_base64(key: str | None, value: str, parent: dict | None) -> tuple[str, str, str] | None:
    """Base64 that holds text (a data:text/plain URL, a text document sent as base64): returns (prefix, media type,
    decoded text) so it can be masked and checked like any text. None for real binary such as images and PDFs."""
    if value.startswith("data:") and ";base64," in value[:100]:
        head, body = value.split(";base64,", 1)
        media = head[5:]
    elif key == "data" and parent is not None and parent.get("type") == "base64":
        head, body, media = None, value, str(parent.get("media_type") or parent.get("mediaType") or "")
    else:
        return None
    if not _TEXT_MEDIA.match(media):
        return None
    try:
        text = base64.b64decode(body, validate=False).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return (head + ";base64," if head is not None else "", media, text)


class RefusedData(Exception):
    """The policy says this type must never reach the model, so the request stops here."""

    def __init__(self, type_: str):
        super().__init__(f"the policy refuses to send {type_} data")
        self.type = type_


@dataclass(frozen=True)
class Replacement:
    start: int
    end: int
    type: str
    action: str
    stand_in: str
    entry_id: str


@dataclass
class Masked:
    text: str
    replacements: list[Replacement] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Resolved:
    args: Any
    report: list[dict] = field(default_factory=list)


class Session:
    def __init__(
        self,
        policy: Policy | str,
        vault: Vault | None = None,
        *,
        known: dict[str, Iterable[str]] | None = None,
        allow: Iterable[str] = (),
        detectors: Iterable = (),
        extra_patterns: Iterable[dict] = (),
        dayfirst: bool = False,
        clock: Callable[[], float] | None = None,
        approve: Callable[[str, str, Sink], bool] | None = None,
        session_id: str | None = None,
        masked_input: bool = False,
    ):
        self.policy = load_profile(policy) if isinstance(policy, str) else policy
        self.vault = vault or Vault()
        self.known = {t: list(v) for t, v in (known or {}).items()}
        self.allow = {a.lower() for a in [*self.policy.allow, *allow]}
        self.extra_detectors = list(detectors)
        self.dayfirst = dayfirst
        self.clock = clock or time.time
        self.approve = approve
        self.id = session_id or uuid.uuid4().hex
        # By default every input is treated as real: a real name that happens to equal an earlier fake is masked
        # like any other value. Set masked_input=True only if you feed back text that already went through mask().
        self.masked_input = masked_input
        self._patterns = PatternDetector(extra_patterns, dayfirst, self._year)
        self._known_cache: tuple[int, KnownDetector] | None = None
        self._known_forms: tuple[tuple, KnownDetector] | None = None
        self._restorer_cache: Restorer | None = None

    # Small helpers

    def now(self) -> int:
        return int(self.clock())

    def _year(self) -> int:
        return dt.datetime.fromtimestamp(self.now(), dt.timezone.utc).year

    def detector_names(self) -> list[str]:
        return ["rules@1", "known@1"] + [getattr(d, "name", type(d).__name__) for d in self.extra_detectors]

    def _known_detector(self) -> KnownDetector:
        if self._known_cache and self._known_cache[0] == self.vault.version:
            return self._known_cache[1]
        forms = []
        stop_words = stopwords() | ambiguous_names()  # parts that are also words are never searched for alone
        for t, values in self.known.items():
            for v in values:
                forms.append((t, v, known_mode(t, v)))
                if t == "PERSON" and len(v.split()) > 1:
                    # the app vouched for this person, so "Dana called" and "Reyes, Dana" are them too
                    forms.extend(("PERSON", w, "case") for w in v.split() if len(w) >= 2 and w.lower() not in stop_words)
        for e in self.vault.entries:
            if e.type in ("DATE", "MONEY"):
                continue  # the patterns find these again, and their stand-ins depend on the format
            for real in set(e.surfaces.values()):
                if cue_only(e.type, real):
                    continue
                if e.type in DIGIT_TYPES and len(digits_of(real)) >= 6:
                    forms.append((e.type, digits_of(real), "digits"))
                else:
                    forms.append((e.type, real, known_mode(e.type, real)))
        for real_part in self.vault.parts_back.values():
            if len(real_part) >= 2 and real_part.lower() not in stop_words:
                forms.append(("PERSON", real_part, "case"))
        key = tuple(forms)
        if self._known_forms is not None and self._known_forms[0] == key:
            det = self._known_forms[1]  # the vault changed, but not in anything we search for
        else:
            det = KnownDetector(forms)
            self._known_forms = (key, det)
        self._known_cache = (self.vault.version, det)
        return det

    def restorer(self) -> Restorer:
        r = self._restorer_cache
        if r is None or r.version != self.vault.version:
            r = Restorer(self.vault, self._year(), self.dayfirst)
            self._restorer_cache = r
        return r

    # Detection

    def detect(self, text: str) -> list[Span]:
        spans = self._patterns.detect(text) + self._known_detector().detect(text)
        for d in self.extra_detectors:
            spans.extend(d.detect(text))
        chosen = grow_names(resolve_people(spans), text)
        return [s for s in chosen if s.text.lower() not in self.allow and not self._is_ours(s.text)]

    def _is_ours(self, text: str) -> bool:
        return self.masked_input and self.vault.is_stand_in(text)

    # Masking

    def mask(self, text: str, source: Source | None = None) -> Masked:
        spans = self.detect(text)
        stand: dict[Span, tuple[str, Entry] | None] = {}
        todo = spans
        for _ in range(3):
            # people first, so an email like dana.reyes@... can reuse the fake name chosen for "Dana Reyes"
            for span in sorted(todo, key=lambda sp: (sp.type != "PERSON", sp.start)):
                stand[span] = self._stand_in(span, text, source)
            # what we just learned (a name, its parts) may appear elsewhere in this same text without a cue,
            # like a sign-off "Dana" under "From: Dana Reyes"; look once more for known values only
            todo = [sp for sp in grow_names(resolve(self._known_detector().detect(text)), text)
                    if not any(sp.start < o.end and o.start < sp.end for o in spans)
                    and sp.text.lower() not in self.allow and not self._is_ours(sp.text)]
            if not todo:
                break
            spans = sorted(spans + todo, key=lambda sp: sp.start)
        else:
            # three rounds is plenty in practice; whatever the last one found still gets a stand-in
            for span in sorted(todo, key=lambda sp: (sp.type != "PERSON", sp.start)):
                stand[span] = self._stand_in(span, text, source)
        out, last, reps, notes = [], 0, [], []
        pos = 0
        for span in spans:
            if stand.get(span) is None:
                continue
            value, entry = stand[span]
            out.append(text[last:span.start])
            pos += span.start - last
            reps.append(Replacement(pos, pos + len(value), span.type, entry.action, value, entry.id))
            out.append(value)
            pos += len(value)
            last = span.end
            if entry.action == "handle":
                n = handles.note(entry.stand_in, entry.meta)
                if n not in notes:
                    notes.append(n)
        out.append(text[last:])
        return Masked("".join(out), reps, notes)

    def _kept(self, span: Span, text: str) -> bool:
        """True when this mention stays as written. The masking and the egress check both ask here, so a value we
        chose to keep is never reported as a leak."""
        action = self.policy.rule_for(span.type).action
        if action == "keep":
            return True
        if span.type == "DATE" and action in ("shift", "fake") and dates.near_holiday(text, span.start, span.end):
            # "Christmas Day, December 25": the words already give the date away, and a shifted day would contradict
            # them
            return dates.parse(span.text, self._year(), self.dayfirst) is not None
        if span.type == "LOCATION" and action == "generalize" and fakes.coarse_place(span.text):
            return True  # a country or a state is already general
        return False

    def _stand_in(self, span: Span, text: str, source: Source | None) -> tuple[str, Entry] | None:
        rule = self.policy.rule_for(span.type)
        action, type_ = rule.action, span.type
        if self._kept(span, text):
            return None
        if action == "refuse":
            raise RefusedData(type_)
        parsed = None
        if type_ == "DATE":
            parsed = dates.parse(span.text, self._year(), self.dayfirst)
            if action == "fake":
                action = "shift"
            if parsed is None and action == "shift":
                action = "tag"
            norm = parsed.day.isoformat() if parsed else normalize(type_, span.text)
        else:
            if action == "shift":
                action = "fake"
            norm = normalize(type_, span.text)
        if action == "fpe" and (type_ not in DIGIT_TYPES or len(digits_of(span.text)) < 6):
            action = "fake"
        entry = self.vault.find(type_, norm, action)
        if entry is not None:
            return self._reuse(entry, span, parsed, text), entry
        return self._create(type_, span, norm, action, rule, parsed, text, source)

    def _reuse(self, entry: Entry, span: Span, parsed, text: str) -> str:
        for fake, real in entry.surfaces.items():
            if real == span.text:
                return fake
        a, t = entry.action, entry.type
        if a == "shift" and parsed is not None:
            value = dates.render(dt.date.fromisoformat(entry.meta["shifted"]), parsed)
        elif a == "fake" and t == "PERSON":
            value = fakes.person(Ctx(self.vault, text, self.policy.rule_for(t).options), span.text)
        elif a in ("fake", "fpe") and t in DIGIT_TYPES:
            value = fill_template(span.text, digits_of(entry.stand_in))
        elif a == "fake" and t == "MONEY":
            value = self._money_scaled(span.text)
        elif a == "generalize":
            value = self._generalize(t, span.text, parsed, text[span.end:span.end + 40])
        else:
            value = entry.stand_in
        self.vault.add_surface(entry, value, span.text)
        return value

    def _create(self, type_, span, norm, action, rule: Rule, parsed, text, source) -> tuple[str, Entry]:
        real = span.text
        meta: dict = {}
        restorable = action not in ("generalize", "drop")
        ctx = Ctx(self.vault, text, rule.options)
        if action == "fake":
            if type_ == "MONEY":
                value = self._money_scaled(real)
            elif type_ == "EMAIL":
                value = fakes.email(ctx, real, on_person=lambda full: self._person_from_email(full, text))
            elif type_ == "ORG":
                value, core = fakes.org_parts(ctx, real)
                meta = {"core": core}
            else:
                value = fakes.make(type_, ctx, real)
        elif action == "shift":
            offset = self.vault.get_date_offset()
            if parsed.has_year and dates.near_birth(text, span.start):
                # a birth date moves the other way if the usual shift would change the person's age today
                today = dt.datetime.fromtimestamp(self.now(), dt.timezone.utc).date()
                if dates.age(parsed.day, today) != dates.age(parsed.day + dt.timedelta(days=offset), today):
                    offset = -offset
            shifted = parsed.day + dt.timedelta(days=offset)
            value = dates.render(shifted, parsed)
            meta = {"day": parsed.day.isoformat(), "shifted": shifted.isoformat()}
        elif action == "tag":
            value = f"[{type_}_{self.vault.next_number(type_)}]"
        elif action == "token":
            mac = hmac.new(self.vault.get_token_key(), f"{type_}:{norm}".encode("utf-8"), hashlib.sha256)
            value = f"{type_.lower()}_{mac.hexdigest()[:8]}"
        elif action == "fpe":
            value = self._fpe(type_, real)
        elif action == "generalize":
            value = self._generalize(type_, real, parsed, text[span.end:span.end + 40])
        elif action == "drop":
            value = f"[{type_} removed]"
        elif action == "handle":
            value = "{{" + f"{type_}_{self.vault.next_number(type_)}" + "}}"
            meta = self._handle_meta(type_, real, rule, text, source)
        else:  # pragma: no cover - policy validation keeps us out of here
            raise ValueError(f"unknown action {action!r}")
        entry = self.vault.add(type_, real, norm, action, value, restorable, meta)
        if type_ == "ORG" and action == "fake":
            real_core = fakes.org_core(real)
            if real_core != real and fakes.org_core_usable(real_core):
                # the bare name is known from now on, so "work at Acme" is hidden like "Acme Corp" was
                self.vault.add_surface(entry, meta["core"], real_core)
        return value, entry

    def _person_from_email(self, full_name: str, text: str) -> None:
        """An address like dana.reyes@ names a person; give them the same fake name everywhere."""
        rule = self.policy.rule_for("PERSON")
        if rule.action == "keep":
            # names stay visible under this policy, so the address gets plain fake words; registering the name's
            # parts would make the egress check treat the visible name as a leak
            return
        norm = normalize("PERSON", full_name)
        if rule.action == "fake" and self.vault.find("PERSON", norm, "fake") is None:
            value = fakes.person(Ctx(self.vault, text, rule.options), full_name)
            self.vault.add("PERSON", full_name, norm, "fake", value, True)
        else:
            fakes.person(Ctx(self.vault, text, {"keep_gender": True}), full_name)

    def _handle_meta(self, type_: str, real: str, rule: Rule, text: str, source: Source | None) -> dict:
        sites = list(rule.options.get("sites") or [])
        if not sites and source is not None and source.bound_site():
            sites = [source.bound_site()]
        # text is untrusted: a phrase like "valid for 999 hours" may only shorten the policy's limit, never extend it
        text_ttl = handles.ttl_from_text(text) if type_ == "OTP" else None
        policy_ttl = rule.options.get("ttl_s")
        limits = [x for x in (text_ttl, policy_ttl) if x is not None]
        if text_ttl is not None and policy_ttl is None:
            limits.append(MAX_TEXT_TTL)
        ttl = min(limits) if limits else None
        expires = self.now() + int(ttl) if ttl is not None else None  # 0 means already expired, not never
        return {
            "sites": sites,
            "tools": rule.options.get("tools"),
            "uses_left": rule.options.get("uses"),
            "expires_at": expires,
            "ask": bool(rule.options.get("ask", False)),
            "description": handles.describe(type_, real, sites[0] if sites else None, expires),
            "sinks": [],
        }

    def _fpe(self, type_: str, real: str) -> str:
        ff1 = FF1(self.vault.get_fpe_key())
        tweak = type_.encode("ascii")
        d = digits_of(real)
        if type_ == "CARD":
            head, mid, tail = d[0], d[1:-4], d[-4:]
            while True:  # cycle-walk until the Luhn digit works out, so the fake is still a well-formed card
                mid = ff1.encrypt_digits(mid, tweak)
                if luhn_ok(head + mid + tail):
                    return fill_template(real, head + mid + tail)
        if type_ == "ROUTING":
            x = d
            while True:
                x = ff1.encrypt_digits(x, tweak)
                if aba_ok(x):
                    return fill_template(real, x)
        if type_ == "PHONE" and (len(d) == 10 or len(d) == 11):
            keep = len(d) - 7  # country code and area code stay
            return fill_template(real, d[:keep] + ff1.encrypt_digits(d[keep:], tweak))
        if type_ == "SSN":
            x = d
            while True:
                x = ff1.encrypt_digits(x, tweak)
                if ssn_ok(x):
                    return fill_template(real, x)
        return fill_template(real, ff1.encrypt_digits(d, tweak))

    def fpe_decrypt(self, type_: str, value: str) -> str:
        """Undo `fpe` with the key alone, for systems that have the key but not the vault."""
        ff1 = FF1(self.vault.get_fpe_key())
        tweak = type_.encode("ascii")
        d = digits_of(value)
        if type_ == "CARD":
            head, mid, tail = d[0], d[1:-4], d[-4:]
            while True:
                mid = ff1.decrypt_digits(mid, tweak)
                if luhn_ok(head + mid + tail):
                    return fill_template(value, head + mid + tail)
        if type_ in ("ROUTING", "SSN"):
            ok = aba_ok if type_ == "ROUTING" else ssn_ok
            x = d
            while True:
                x = ff1.decrypt_digits(x, tweak)
                if ok(x):
                    return fill_template(value, x)
        if type_ == "PHONE" and (len(d) == 10 or len(d) == 11):
            keep = len(d) - 7
            return fill_template(value, d[:keep] + ff1.decrypt_digits(d[keep:], tweak))
        return fill_template(value, ff1.decrypt_digits(d, tweak))

    def _money_scaled(self, real: str) -> str:
        cents, fmt = _parse_money(real)
        if cents is None:
            return real
        return _format_money(cents * self.vault.get_money_factor(), fmt)

    def _generalize(self, type_: str, real: str, parsed, after: str = "") -> str:
        if type_ == "DATE":
            if parsed is None:
                return "a date"
            month = dates.MONTHS[parsed.day.month - 1]
            return f"{month} {parsed.day.year}" if parsed.has_year else month
        if type_ == "MONEY":
            cents, fmt = _parse_money(real)
            if cents is None:
                return "an amount"
            dollars = (cents + 50) // 100
            if dollars >= 100:
                step = 10 ** (len(str(dollars)) - 2)
                dollars = (dollars + step // 2) // step * step
            return "about " + _format_money(dollars * 100, {**fmt, "decimals": False})
        if type_ == "LOCATION":
            return fakes.general_place(real, after)
        if type_ == "ADDRESS":
            area = fakes.postcode_area(real)
            if area is not None:
                return area
        return GENERAL.get(type_, f"[{type_}]")

    # JSON and chat messages

    def mask_json(self, value: Any, source: Source | None = None) -> tuple[Any, list[str]]:
        """Mask a JSON value that is data (a tool result): every string, and the keys too, since a result keyed by
        email address is as personal as one with emails in it."""
        notes: list[str] = []
        return self._mask_tree(self._mask_keys(value, source, notes), source, notes, skip_keys=frozenset()), notes

    def _mask_keys(self, v: Any, source, notes: list[str]) -> Any:
        if isinstance(v, dict):
            out = {}
            for k, x in v.items():
                m = self.mask(k, source) if isinstance(k, str) else None
                if m is not None:
                    notes.extend(n for n in m.notes if n not in notes)
                out[m.text if m is not None else k] = self._mask_keys(x, source, notes)
            return out
        if isinstance(v, list):
            return [self._mask_keys(x, source, notes) for x in v]
        return v

    def _mask_tree(self, v: Any, source, notes: list[str], skip_keys: frozenset, key: str | None = None,
                   parent: dict | None = None) -> Any:
        if isinstance(v, str):
            if key in skip_keys or is_signed_thinking(key, parent):
                return v
            decoded = text_base64(key, v, parent)
            if decoded is not None:  # text sent as base64: mask the text, send it back as base64
                prefix, _, text = decoded
                m = self.mask(text, source)
                notes.extend(n for n in m.notes if n not in notes)
                return prefix + base64.b64encode(m.text.encode("utf-8")).decode("ascii")
            if is_binary(key, v, parent):
                return v
            if key == "arguments" and v.strip().startswith(("{", "[")):
                try:
                    inner = json.loads(v)
                except ValueError:
                    pass
                else:
                    masked = self._mask_tree(inner, source, notes, frozenset())
                    return json.dumps(masked, ensure_ascii=False, separators=(",", ":"))
            m = self.mask(v, source)
            for n in m.notes:
                if n not in notes:
                    notes.append(n)
            return m.text
        if isinstance(v, dict):
            return {k: self._mask_tree(x, source, notes, skip_keys, k, v) for k, x in v.items()}
        if isinstance(v, list):
            return [self._mask_tree(x, source, notes, skip_keys, key, parent) for x in v]
        return v

    def mask_messages(self, messages: list, source: Source | None = None) -> tuple[list, list[str]]:
        """Mask a chat history in OpenAI or Anthropic shape. Handle notes go at the end of the message that
        mentions the handle, so the model learns what {{OTP_1}} is right where it first sees it."""
        all_notes: list[str] = []
        out = []
        for msg in messages:
            notes: list[str] = []
            masked = self._mask_tree(copy.deepcopy(msg), source, notes, SKIP_KEYS)
            fresh = [n for n in notes if not _already_noted(masked, n)]
            if fresh and isinstance(masked, dict):
                _append_notes(masked, fresh)
            out.append(masked)
            all_notes.extend(n for n in notes if n not in all_notes)
        return out, all_notes

    def mask_value(self, value: Any, source: Source | None = None) -> tuple[Any, list[str]]:
        """Mask any request body part (a system prompt string or block list, tool results...)."""
        notes: list[str] = []
        return self._mask_tree(copy.deepcopy(value), source, notes, SKIP_KEYS), notes

    # Restoring

    def _reveal(self, entry_id: str) -> str:
        e = self.vault.by_id(entry_id)
        return e.real if e else ""

    def restore(self, text: str, reveal_handles: bool = False) -> str:
        """Put the real values back for the person to read. Handles become a short label unless revealed."""
        return self.restorer().restore(text, self._reveal if reveal_handles else None)

    def unknown_stand_ins(self, text: str) -> list[str]:
        return self.restorer().unknown(text)

    def stream(self, reveal_handles: bool = False) -> StreamRestorer:
        return StreamRestorer(self.restorer, self._reveal if reveal_handles else None)

    def restore_json(self, value: Any) -> Any:
        """Restore every string in a JSON value for display (handles stay as labels)."""
        if isinstance(value, str):
            return self.restore(value)
        if isinstance(value, dict):
            return {k: self.restore_json(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.restore_json(v) for v in value]
        return value

    def restore_keep_handles(self, value: Any) -> Any:
        """Restore fakes and tags in a value but leave {{handles}} exactly as they are.

        For handing a tool call back to an app that resolves handles itself, later, with a sink it trusts.
        """
        keep = lambda eid: self.vault.by_id(eid).stand_in  # noqa: E731
        if isinstance(value, str):
            return self.restorer().restore(value, keep)
        if isinstance(value, dict):
            return {k: self.restore_keep_handles(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.restore_keep_handles(v) for v in value]
        return value

    def resolve_args(self, args: Any, sink: Sink) -> Resolved:
        """Restore a tool call's arguments right before the tool runs.

        Fakes and tags turn back into real values. Handles are filled in only if their binding allows this sink;
        otherwise HandleRefused is raised and nothing is filled. Strings that hold contact or payment details the
        vault never issued are flagged with origin "model": the model wrote them itself.
        """
        if isinstance(args, str) and args.strip().startswith(("{", "[")):
            try:
                parsed = json.loads(args)
            except ValueError:
                parsed = None
            if parsed is not None:
                res = self.resolve_args(parsed, sink)
                return Resolved(json.dumps(res.args, ensure_ascii=False, separators=(",", ":")), res.report)
        restorer = self.restorer()
        now = self.now()
        wanted: dict[str, Entry] = {}
        for text in _strings(args):
            for m in HANDLE.finditer(text):
                eid = restorer.handles.get(m[0])
                if eid is None:
                    raise HandleRefused(m[0], "unknown handle")
                wanted[m[0]] = self.vault.by_id(eid)
        for handle, entry in wanted.items():
            handles.check(handle, entry.meta, sink, now)
            place = [sink.tool, handles.host_of(sink.site) if sink.site else None]
            first_time_here = place not in entry.meta.get("sinks", [])
            if entry.meta.get("ask") or (first_time_here and self.approve is not None):
                if self.approve is None:
                    raise HandleRefused(handle, "needs the person's approval")
                if not self.approve(handle, entry.meta["description"], sink):
                    raise HandleRefused(handle, "not approved")
        report: list[dict] = []

        def walk(v, path):
            if isinstance(v, str):
                found = restorer.matches(v, 0, self._reveal)
                if found:
                    report.append({"path": path, "restored": len(found),
                                   "handles": [m.entry_id for m in found if m.kind == "handle"]})
                    from .restore import apply

                    return apply(v, found)
                kinds = sorted({s.type for s in self._patterns.detect(v)
                                if s.type in ("EMAIL", "PHONE", "CARD", "IBAN", "BANK_ACCOUNT", "URL")})
                if kinds:
                    report.append({"path": path, "origin": "model", "types": kinds})
                return v
            if isinstance(v, dict):
                return {k: walk(x, f"{path}.{k}" if path else k) for k, x in v.items()}
            if isinstance(v, list):
                return [walk(x, f"{path}[{i}]") for i, x in enumerate(v)]
            return v

        result = walk(args, "")
        for handle, entry in wanted.items():
            if entry.meta.get("uses_left") is not None:
                entry.meta["uses_left"] -= 1
            place = [sink.tool, handles.host_of(sink.site) if sink.site else None]
            if place not in entry.meta["sinks"]:
                entry.meta["sinks"].append(place)
            self.vault.touch()
        return Resolved(result, report)

    # Egress

    def check_egress(self, payload: bytes | str) -> list[Leak]:
        """Two checks on the exact bytes about to leave: every real value the vault knows, and a fresh detection pass
        over the content fields, so a field that was never masked (a document, a metadata note) is caught too."""
        restorer = self.restorer()
        leaks = egress_check(self.vault, payload, restorer)
        seen = {(lk.type, lk.entry_id) for lk in leaks}
        text = content_text(payload)
        # our own stand-ins are blanked first, so a slice of a fake ("Rowan Whitlock" inside "Taylor Rowan Whitlock")
        # is not taken for a new name
        for span in self.detect(blank_stand_ins(text, restorer)):
            if not self._kept(span, text) and not self.vault.is_stand_in(span.text):
                if (span.type, "detected") not in seen:
                    seen.add((span.type, "detected"))
                    leaks.append(Leak(span.type, "detected"))
        return leaks

    def record_egress(self, log: EgressLog, payload: bytes, dest: str) -> str:
        """Check the exact bytes about to be sent and sign a receipt. Raises EgressLeak instead of sending a leak."""
        leaks = self.check_egress(payload)
        if leaks:
            raise EgressLeak(leaks)
        return log.record(self.vault, payload, session=self.id, policy_digest=self.policy.digest, dest=dest,
                          now=self.now(), detectors=self.detector_names(), restorer=self.restorer())


def content_text(payload: bytes | str) -> str:
    """Everything in a payload a person could have written, as text, for the detection pass: for JSON every key and
    every string except the top-level model name, signed or encrypted reasoning and real binary base64 (text sent as
    base64 is decoded and read). Plain text is used as is."""
    raw = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError):
        return raw
    out: list[str] = []
    stack = [(doc, None, None)]
    while stack:  # a loop, not recursion, so deeply nested JSON cannot crash the check
        v, key, parent = stack.pop()
        if isinstance(v, str):
            if (key in TOP_KEYS and parent is doc) or is_signed_thinking(key, parent):
                continue
            decoded = text_base64(key, v, parent)
            if decoded is not None:
                out.append(decoded[2])
            elif not is_binary(key, v, parent):
                out.append(v)
        elif isinstance(v, dict):
            for k, x in v.items():
                out.append(str(k))
                stack.append((x, k, v))
        elif isinstance(v, list):
            stack.extend((x, key, parent) for x in v)
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            out.append(str(v))
    return "\n".join(out)


def _strings(v: Any):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for x in v.values():
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


def _already_noted(msg: Any, note: str) -> bool:
    return note in json.dumps(msg, ensure_ascii=False)


def _append_notes(msg: dict, notes: list[str]) -> None:
    text = "\n".join(f"Note: {n}" for n in notes)
    content = msg.get("content")
    if isinstance(content, str):
        msg["content"] = content + "\n\n" + text
    elif isinstance(content, list):
        msg["content"] = content + [{"type": "text", "text": text}]
    else:
        msg["content"] = text


def _parse_money(real: str):
    m = MONEY_PREFIX.match(real)
    if m:
        whole, dec = m[3], m[4]
        fmt = {"symbol": m[1], "space": m[2], "suffix": None, "commas": "," in whole, "decimals": bool(dec)}
    else:
        m = MONEY_SUFFIX.match(real)
        if not m:
            return None, None
        whole, dec = m[1], m[2]
        fmt = {"symbol": None, "space": m[3], "suffix": m[4], "commas": "," in whole, "decimals": bool(dec)}
    cents = int(whole.replace(",", "")) * 100 + (int(dec[1:]) if dec else 0)
    return cents, fmt


def _format_money(cents: int, fmt: dict) -> str:
    whole, rest = divmod(cents, 100)
    number = f"{whole:,}" if fmt["commas"] else str(whole)
    if fmt["decimals"]:
        number += f".{rest:02d}"
    if fmt["symbol"]:
        return f"{fmt['symbol']}{fmt['space']}{number}"
    return f"{number}{fmt['space']}{fmt['suffix']}"
