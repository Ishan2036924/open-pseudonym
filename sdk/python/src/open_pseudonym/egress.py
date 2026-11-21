"""Proving what left: the egress check and signed, chained receipts.

The check runs on the exact bytes about to be sent. It first blanks out every stand-in we issued, then looks for any
real value the vault holds (names, their parts, emails in any case, numbers with any formatting). If it finds one, the
request is not sent. This proves something narrow and useful: no value we know about left. It cannot prove that a
value the detectors never saw did not leave, and the receipts say so by counting only what the vault knows.

Each sent request gets a receipt, an Ed25519-signed JWS that names the payload's digest, the policy, how many
stand-ins of each type were in it, and the previous receipt's digest. `verify_log` re-checks all of it later.

The same log can also hold release records: one signed line for each decision to fill, or to refuse to fill, a secret
handle, with who allowed it (spec 10.4). A checkpoint is a head of the chain signed by a key the writer does not
hold; given to `verify_log` it proves the log was not cut off before that point (spec 11.3).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .checks import ambiguous_names, cue_only, stopwords
from .detect import KnownDetector
from .handles import CODES, DIGEST, HANDLE
from .jcs import b64url_decode, canonical, digest
from .jws import SignatureError, Signer, key_id, verify
from .restore import Restorer
from .types import CASELESS_TYPES, DIGIT_TYPES, digits_of
from .vault import Vault

RECEIPT_TYP = "opn-egress+jws"
RELEASE_TYP = "opn-release+jws"
CHECKPOINT_TYP = "opn-checkpoint+jws"
AUTHORITY_KINDS = ("binding", "person", "consent", "policy")


class EgressLeak(Exception):
    def __init__(self, leaks):
        types = sorted({lk.type for lk in leaks})
        super().__init__(f"refused to send: {len(leaks)} known value(s) of type {', '.join(types)} still present")
        self.leaks = leaks


@dataclass(frozen=True)
class Leak:
    type: str
    entry_id: str


def payload_text(payload: bytes | str) -> str:
    """The text the check reads: the raw text, plus, for JSON, every decoded key and string, so '\\u00e9' escapes
    cannot hide a name. The raw text is always included, so a bare JSON number or literal is read as written."""
    raw = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError):
        return raw
    out: list[str] = [raw]
    stack = [doc]
    while stack:  # a loop, not recursion, so deeply nested JSON cannot crash the check
        v = stack.pop()
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            for k, x in v.items():
                out.append(str(k))
                stack.append(x)
        elif isinstance(v, list):
            stack.extend(v)
    return "\n".join(out)


def known_mode(type_: str, value: str) -> str:
    """Matches session.known_mode: multi-word names in any case, single words as written."""
    if type_ in CASELESS_TYPES or (type_ in ("PERSON", "ORG", "LOCATION", "ADDRESS") and len(value.split()) > 1):
        return "nocase"
    return "case"


def real_forms(vault: Vault) -> list[tuple[str, str, str]]:
    """Every real value that must never leave, as (type, text, mode) for KnownDetector."""
    forms = []
    for e in vault.entries:
        if e.action == "keep":
            continue
        for real in set(e.surfaces.values()) | {e.real}:
            if cue_only(e.type, real):
                continue
            if e.type == "IBAN":
                forms.append((e.type, real, "nocase"))
                forms.append((e.type, "".join(real.split()), "nocase"))
            elif e.type in DIGIT_TYPES:
                d = digits_of(real)
                # long numbers match with any formatting; a short code must match as written
                forms.append((e.type, d, "digits") if len(d) >= 6 else (e.type, real, "case"))
            elif len(real) >= 2:
                forms.append((e.type, real, known_mode(e.type, real)))
    stop = stopwords() | ambiguous_names()
    for real_part in vault.parts_back.values():
        # stopword parts ("May") are never masked on their own, so searching for them would only raise false alarms
        if len(real_part) >= 3 and real_part.lower() not in stop:
            forms.append(("PERSON", real_part, "case"))
    return forms


def blank_stand_ins(text: str, restorer: Restorer) -> str:
    """The text with our own stand-ins replaced by spaces (same length, so positions still line up)."""
    chars = list(text)
    for m in restorer.matches(text):
        for i in range(m.start, m.end):
            chars[i] = " "
    return "".join(chars)


def check(vault: Vault, payload: bytes | str, restorer: Restorer | None = None) -> list[Leak]:
    text = payload_text(payload)
    restorer = restorer or Restorer(vault)
    # blank out our own stand-ins first, so a fake that happens to equal a real value elsewhere is not a false alarm
    blanked = blank_stand_ins(text, restorer)
    leaks = []
    seen = set()
    for span in KnownDetector(real_forms(vault)).detect(blanked):
        entry = _entry_for(vault, span.type, span.text)
        key = (span.type, entry)
        if key not in seen:
            seen.add(key)
            leaks.append(Leak(span.type, entry))
    return leaks


def _entry_for(vault: Vault, type_: str, text: str) -> str:
    low = text.lower()
    d = digits_of(text)
    for e in vault.entries:
        if e.type != type_:
            continue
        reals = set(e.surfaces.values()) | {e.real}
        if any(r.lower() == low or (d and digits_of(r) == d) for r in reals):
            return e.id
    return "part"


def stand_in_counts(vault: Vault, payload: bytes | str, restorer: Restorer | None = None) -> dict[str, int]:
    """How many distinct stand-ins of each type the payload carries."""
    restorer = restorer or Restorer(vault)
    ids = {m.entry_id for m in restorer.matches(payload_text(payload)) if m.entry_id}
    counts: dict[str, int] = {}
    for eid in ids:
        e = vault.by_id(eid)
        t = e.type if e else "PERSON"
        counts[t] = counts.get(t, 0) + 1
    return dict(sorted(counts.items()))


class EgressLog:
    """An append-only folder: receipts.jsonl (one JWS per line) and, optionally, the payloads themselves.

    Payloads are what the model provider received, so they hold stand-ins, not real values. Keeping them lets anyone
    with the vault re-run the check later; without them a verifier can still check signatures and the chain.
    """

    def __init__(self, folder, signer: Signer, store_payloads: bool = True):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.signer = signer
        self.store_payloads = store_payloads
        self._receipts = self.folder / "receipts.jsonl"
        self.seq, self.prev = 0, None
        if self._receipts.exists():
            lines = [ln for ln in self._receipts.read_text().splitlines() if ln.strip()]
            if lines:
                self.seq = len(lines)
                self.prev = digest(lines[-1].encode("ascii"))

    def record(self, vault: Vault, payload: bytes, *, session: str, policy_digest: str, dest: str, now: int,
               detectors: list[str], restorer: Restorer | None = None, allow_leaks: bool = False) -> str:
        restorer = restorer or Restorer(vault)
        leaks = check(vault, payload, restorer)
        if leaks and not allow_leaks:
            raise EgressLeak(leaks)
        known = sum(1 for e in vault.entries if e.action != "keep")
        body = {
            "opn": "0.1",
            "type": "egress",
            "session": session,
            "seq": self.seq + 1,
            "iat": now,
            "prev": self.prev,
            "dest": dest,
            "payload": digest(payload),
            "policy": policy_digest,
            "stand_ins": stand_in_counts(vault, payload, restorer),
            "check": {"known_values": known, "found": len(leaks)},
            "detectors": detectors,
        }
        token = self.signer.sign(body, RECEIPT_TYP)
        if self.store_payloads:
            pdir = self.folder / "payloads"
            pdir.mkdir(exist_ok=True)
            (pdir / f"{self.seq + 1:06d}.bin").write_bytes(payload)
        self._append([token])
        return token

    def record_release(self, **fields) -> str:
        """Sign and append one release record (spec 10.4). See `record_releases` for the fields."""
        return self.record_releases([fields])[0]

    def record_releases(self, entries: list[dict]) -> list[str]:
        """Sign and append release records, all in one write, so a call that fills several handles is recorded whole
        or not at all. Each entry takes: session, now, handle, data, source, sink ({tool, site}), call, decision
        ("allow" or "deny"), authority ({kind, ref?, digest?, by?, channel?, shown?}) and, as they apply, code
        (a deny), reason (a deny) and uses_left. There is no field for a value, and none may be added."""
        seq, prev, tokens = self.seq, self.prev, []
        for e in entries:
            body = release_body(e, seq + 1, prev)
            token = self.signer.sign(body, RELEASE_TYP)
            tokens.append(token)
            seq, prev = seq + 1, digest(token.encode("ascii"))
        self._append(tokens)
        return tokens

    def _append(self, tokens: list[str]) -> None:
        try:
            with open(self._receipts, "a", encoding="ascii") as fh:
                fh.write("".join(t + "\n" for t in tokens))
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            self._reload()  # a failed write may have left part of a line; take the state from the file again
            raise
        self.seq += len(tokens)
        self.prev = digest(tokens[-1].encode("ascii"))

    def _reload(self) -> None:
        try:
            lines = [ln for ln in self._receipts.read_text().splitlines() if ln.strip()]
        except OSError:
            return  # the file cannot be read; keep what we knew
        self.seq = len(lines)
        self.prev = digest(lines[-1].encode("ascii")) if lines else None

    def head(self) -> tuple[int, str | None]:
        """The last sequence number and the digest of that record: what a checkpoint signs."""
        return self.seq, self.prev

    def checkpoint(self, anchor: Signer, *, session: str, now: int) -> str:
        """A checkpoint of this log's head, signed by `anchor`, which must not be the key that signs the log."""
        if anchor.kid == self.signer.kid:
            raise ValueError("a checkpoint must be signed by a key the log writer does not hold")
        if self.seq == 0:
            raise ValueError("the log is empty")
        return make_checkpoint(anchor, session=session, seq=self.seq, head=self.prev, now=now)


def release_body(e: dict, seq: int, prev: str | None) -> dict:
    """The signed body of a release record. Refuses anything that does not fit the schema, so a bug cannot put a
    value in a record."""
    decision = e["decision"]
    if decision not in ("allow", "deny"):
        raise ValueError("decision is allow or deny")
    authority = {k: v for k, v in e["authority"].items() if v is not None}
    if authority.get("kind") not in AUTHORITY_KINDS or not set(authority) <= {"kind", "ref", "digest", "by", "channel", "shown"}:
        raise ValueError("authority is {kind, ref?, digest?, by?, channel?, shown?}")
    body = {
        "opn": "0.1", "type": "release", "session": e["session"], "seq": seq, "prev": prev, "iat": e["now"],
        "handle": e["handle"], "data": e.get("data"), "source": e.get("source"),
        "sink": {"tool": e["sink"].get("tool"), "site": e["sink"].get("site")},
        "call": e["call"], "outcome": "released" if decision == "allow" else "refused", "decision": decision,
        "authority": authority,
    }
    if decision == "deny":
        if e.get("code") not in CODES or e["code"] == "not_recorded":
            raise ValueError("a recorded denial carries one of the stable codes, except not_recorded")
        body["code"] = e["code"]
        body["reason"] = e["reason"]
    if e.get("uses_left") is not None:
        body["uses_left"] = e["uses_left"]
    return body


def make_checkpoint(signer: Signer, *, session: str, seq: int, head: str, now: int) -> str:
    """Sign a checkpoint: the head (the digest of record `seq`) of a log, by a key that is not the log writer's."""
    return signer.sign({"opn": "0.1", "type": "checkpoint", "session": session, "seq": seq, "head": head, "iat": now},
                       CHECKPOINT_TYP)


def verify_log(folder, public_key, vault: Vault | None = None, *, expect_count: int | None = None,
               expect_last: str | None = None, expect_session: str | None = None, anchors=(),
               anchor_key=None) -> dict:
    """Check every record: signature, chain, payload digest and (with the vault) the egress check again.

    A chain proves that nothing in the middle was changed, but not that nothing was cut off the end. Two ways to catch
    that. Pass what you recorded elsewhere: the number of requests sent (`expect_count`) or the digest of the last
    receipt (`expect_last`, from the x-opn-receipt header the app kept). Or pass checkpoints (`anchors`, compact JWS
    strings) made by a key the log writer does not hold (`anchor_key`, its public key): the report then says how far the
    log is proven complete.

    Release records (spec 10.4) are checked for their fields, and, given the vault, for any real value in them.

    Returns counts, a list of problems (an empty list means the log holds up), and `proven_to` (the highest sequence
    number a valid checkpoint vouches for, or None), `status` ("complete": the last record is vouched for; "prefix":
    the records are valid as far as they go, but the end is not proven) and `reason` (why not complete: "no_anchor" or
    "unanchored_tail"). "complete" says nothing about whether the records are valid: read `problems` too.
    """
    folder = Path(folder)
    problems: list[str] = []
    log_file = folder / "receipts.jsonl"
    lines = [ln for ln in log_file.read_text(errors="replace").splitlines() if ln.strip()] if log_file.exists() else []
    if not log_file.exists():
        problems.append("there is no receipts.jsonl in this folder")
    stored = (folder / "payloads").is_dir()
    extra = sorted(p.name for p in (folder / "payloads").glob("*.bin")
                   if not p.stem.isdigit() or int(p.stem) > len(lines)) if stored else []
    if extra:
        problems.append(f"{len(extra)} stored payload(s) have no receipt: receipts were removed")
    prev = None
    leaks_total = 0
    rechecked = 0
    egress_lines = 0
    releases = 0
    session0 = None
    restorer = Restorer(vault) if vault is not None else None
    for i, token in enumerate(lines, start=1):
        typ = _line_typ(token)
        try:
            body = verify(token, public_key, typ)
        except SignatureError as exc:
            problems.append(f"receipt {i}: {exc}")
            prev = _safe_digest(token)
            egress_lines += 1
            continue
        except Exception as exc:  # a damaged line must never stop the rest of the check
            problems.append(f"receipt {i}: unreadable ({type(exc).__name__})")
            prev = _safe_digest(token)
            egress_lines += 1
            continue
        if session0 is None and isinstance(body.get("session"), str):
            session0 = body["session"]
        if expect_session is not None and body.get("session") != expect_session:
            problems.append(f"receipt {i}: belongs to another session")
        if body.get("seq") != i:
            problems.append(f"receipt {i}: sequence number is {body.get('seq')}")
        if body.get("prev") != prev:
            problems.append(f"receipt {i}: chain broken (prev does not match receipt {i - 1})")
        pfile = folder / "payloads" / f"{i:06d}.bin"
        if typ == RELEASE_TYP:
            releases += 1
            bad = release_problems(i, body)
            problems.extend(bad)
            if vault is not None and not bad:
                found = check(vault, canonical(body), restorer)
                leaks_total += len(found)
                if found:
                    problems.append(f"release {i}: {len(found)} known value(s) found in the record")
            if pfile.exists():
                problems.append(f"release {i}: a release record has a stored payload")
            prev = _safe_digest(token)
            continue
        egress_lines += 1
        if body.get("check", {}).get("found"):
            problems.append(f"receipt {i}: was sent with {body['check']['found']} known value(s) present")
        if pfile.exists():
            data = pfile.read_bytes()
            if digest(data) != body.get("payload"):
                problems.append(f"receipt {i}: stored payload does not match its digest")
            elif vault is not None:
                rechecked += 1
                found = check(vault, data, restorer)
                leaks_total += len(found)
                if found:
                    problems.append(f"receipt {i}: {len(found)} known value(s) found on re-check")
        elif stored:
            problems.append(f"receipt {i}: its stored payload is missing")
        prev = _safe_digest(token)
    if not lines and log_file.exists():
        problems.append("the log holds no receipts")
    if vault is not None and egress_lines and rechecked == 0:
        problems.append("no stored payloads to re-check: they were never kept, or they were removed")
    if expect_count is not None and expect_count != len(lines):
        problems.append(f"expected {expect_count} receipt(s), found {len(lines)}: the log was cut or added to")
    if expect_last is not None and expect_last != prev:
        problems.append("the last receipt is not the one you recorded: the log was cut or replaced")
    proven = _proven_to(lines, public_key, anchors, anchor_key, expect_session or session0, problems)
    complete = proven is not None and proven == len(lines)
    return {"receipts": len(lines), "releases": releases, "rechecked": rechecked, "leaks": leaks_total,
            "problems": problems, "last": prev, "proven_to": proven,
            "status": "complete" if complete else "prefix",
            "reason": None if complete else ("no_anchor" if proven is None else "unanchored_tail")}


def _line_typ(token: str) -> str:
    """The type a line says it is. Anything that is not a release record is read as an egress receipt, so a damaged
    or foreign line gets the same errors it always did."""
    try:
        header = json.loads(b64url_decode(token.split(".")[0]))
    except Exception:
        return RECEIPT_TYP
    return RELEASE_TYP if isinstance(header, dict) and header.get("typ") == RELEASE_TYP else RECEIPT_TYP


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_digest(v) -> bool:
    return isinstance(v, str) and DIGEST.match(v) is not None


def release_problems(i: int, body: dict) -> list[str]:
    """Everything wrong with the shape of a release record (spec 10.4), one short line each."""
    out: list[str] = []

    def bad(field: str) -> None:
        out.append(f"release {i}: {field} is not valid")

    required = {"opn", "type", "session", "seq", "prev", "iat", "handle", "data", "source", "sink", "call", "outcome",
                "decision", "authority"}
    if not required <= set(body) or not set(body) <= required | {"reason", "code", "uses_left"}:
        bad("the field list")
    if body.get("opn") != "0.1" or body.get("type") != "release":
        bad("opn or type")
    if not isinstance(body.get("session"), str):
        bad("session")
    if not _is_int(body.get("seq")) or not _is_int(body.get("iat")):
        bad("seq or iat")
    if body.get("prev") is not None and not _is_digest(body.get("prev")):
        bad("prev")
    h = body.get("handle")
    if not (isinstance(h, str) and HANDLE.fullmatch(h)):
        bad("handle")
    d = body.get("data")
    if d is not None and not (isinstance(d, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{1,31}", d)):
        bad("data")
    if body.get("source") is not None and not isinstance(body.get("source"), str):
        bad("source")
    sink = body.get("sink")
    if not (isinstance(sink, dict) and set(sink) == {"tool", "site"}
            and all(v is None or isinstance(v, str) for v in sink.values())):
        bad("sink")
    if not _is_digest(body.get("call")):
        bad("call")
    pair = (body.get("outcome"), body.get("decision"))
    if pair not in (("released", "allow"), ("refused", "deny")):
        bad("outcome and decision")
    auth = body.get("authority")
    if not (isinstance(auth, dict) and auth.get("kind") in AUTHORITY_KINDS
            and set(auth) <= {"kind", "ref", "digest", "by", "channel", "shown"}
            and all(isinstance(v, str) and v for v in auth.values())
            and all(_is_digest(auth[k]) for k in ("digest", "shown") if k in auth)):
        bad("authority")
    if body.get("decision") == "deny":
        if body.get("code") not in CODES or body.get("code") == "not_recorded":
            bad("code")
        if not (isinstance(body.get("reason"), str) and body["reason"]):
            bad("reason")
    elif "code" in body or "reason" in body:
        bad("code or reason on an allow")
    if "uses_left" in body and not (_is_int(body["uses_left"]) and body["uses_left"] >= 0):
        bad("uses_left")
    return out


def _proven_to(lines, public_key, anchors, anchor_key, session, problems) -> int | None:
    """The highest sequence number a valid checkpoint vouches for. Problems are appended for every checkpoint that does
    not hold up, in particular one past the end of the log (the end was cut off) and one made by the writer's own key."""
    anchors = list(anchors or ())
    if not anchors:
        return None
    if anchor_key is None:
        problems.append("anchors were given without an anchor_key to check them with")
        return None
    if key_id(anchor_key) == key_id(public_key):
        problems.append("the anchor key is the key that signs the log: a checkpoint must come from a key the writer "
                        "does not hold")
        return None
    proven = None
    for n, token in enumerate(anchors, start=1):
        try:
            body = verify(token, anchor_key, CHECKPOINT_TYP)
        except SignatureError as exc:
            problems.append(f"anchor {n}: {exc}")
            continue
        except Exception as exc:
            problems.append(f"anchor {n}: unreadable ({type(exc).__name__})")
            continue
        if not (set(body) == {"opn", "type", "session", "seq", "head", "iat"} and body["opn"] == "0.1"
                and body["type"] == "checkpoint" and isinstance(body["session"], str) and _is_int(body["seq"])
                and body["seq"] >= 1 and _is_digest(body["head"]) and _is_int(body["iat"])):
            problems.append(f"anchor {n}: not a checkpoint")
            continue
        if session is not None and body["session"] != session:
            problems.append(f"anchor {n}: belongs to another session")
            continue
        seq = body["seq"]
        if seq > len(lines):
            problems.append(f"anchor at seq {seq}: the log was cut off after seq {len(lines)}")
        elif body["head"] != _safe_digest(lines[seq - 1]):
            problems.append(f"anchor at seq {seq}: head does not match receipt {seq}: the log was changed or replaced")
        else:
            proven = seq if proven is None else max(proven, seq)
    return proven


def _safe_digest(token: str) -> str:
    return digest(token.encode("utf-8", errors="replace"))
