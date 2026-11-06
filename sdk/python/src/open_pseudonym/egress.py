"""Proving what left: the egress check and signed, chained receipts.

The check runs on the exact bytes about to be sent. It first blanks out every stand-in we issued, then looks for any
real value the vault holds (names, their parts, emails in any case, numbers with any formatting). If it finds one, the
request is not sent. This proves something narrow and useful: no value we know about left. It cannot prove that a
value the detectors never saw did not leave, and the receipts say so by counting only what the vault knows.

Each sent request gets a receipt, an Ed25519-signed JWS that names the payload's digest, the policy, how many
stand-ins of each type were in it, and the previous receipt's digest. `verify_log` re-checks all of it later.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from ._data import pools
from .detect import KnownDetector
from .jcs import digest
from .jws import SignatureError, Signer, verify
from .restore import Restorer
from .types import CASELESS_TYPES, DIGIT_TYPES, digits_of
from .vault import Vault

RECEIPT_TYP = "opn-egress+jws"


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
            if e.type == "IBAN":
                forms.append((e.type, real, "nocase"))
                forms.append((e.type, "".join(real.split()), "nocase"))
            elif e.type in DIGIT_TYPES:
                d = digits_of(real)
                # long numbers match with any formatting; a short code must match as written
                forms.append((e.type, d, "digits") if len(d) >= 6 else (e.type, real, "case"))
            elif len(real) >= 2:
                forms.append((e.type, real, known_mode(e.type, real)))
    stop = {w.lower() for w in pools()["name_stopwords"]}
    for real_part in vault.parts_back.values():
        # stopword parts ("May") are never masked on their own, so searching for them would only raise false alarms
        if len(real_part) >= 3 and real_part.lower() not in stop:
            forms.append(("PERSON", real_part, "case"))
    return forms


def check(vault: Vault, payload: bytes | str, restorer: Restorer | None = None) -> list[Leak]:
    text = payload_text(payload)
    restorer = restorer or Restorer(vault)
    # blank out our own stand-ins first, so a fake that happens to equal a real value elsewhere is not a false alarm
    chars = list(text)
    for m in restorer.matches(text):
        for i in range(m.start, m.end):
            chars[i] = " "
    blanked = "".join(chars)
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
        with open(self._receipts, "a", encoding="ascii") as fh:
            fh.write(token + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self.seq += 1
        self.prev = digest(token.encode("ascii"))
        return token


def verify_log(folder, public_key, vault: Vault | None = None, *, expect_count: int | None = None,
               expect_last: str | None = None, expect_session: str | None = None) -> dict:
    """Check every receipt: signature, chain, payload digest and (with the vault) the egress check again.

    A chain proves that nothing in the middle was changed, but not that nothing was cut off the end. To catch that,
    pass what you recorded elsewhere: the number of requests sent (`expect_count`) or the digest of the last
    receipt (`expect_last`, from the x-opn-receipt header the app kept). Returns counts and a list of problems; an
    empty list means the log holds up.
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
    restorer = Restorer(vault) if vault is not None else None
    for i, token in enumerate(lines, start=1):
        try:
            body = verify(token, public_key, RECEIPT_TYP)
        except SignatureError as exc:
            problems.append(f"receipt {i}: {exc}")
            prev = _safe_digest(token)
            continue
        except Exception as exc:  # a damaged line must never stop the rest of the check
            problems.append(f"receipt {i}: unreadable ({type(exc).__name__})")
            prev = _safe_digest(token)
            continue
        if expect_session is not None and body.get("session") != expect_session:
            problems.append(f"receipt {i}: belongs to another session")
        if body.get("seq") != i:
            problems.append(f"receipt {i}: sequence number is {body.get('seq')}")
        if body.get("prev") != prev:
            problems.append(f"receipt {i}: chain broken (prev does not match receipt {i - 1})")
        if body.get("check", {}).get("found"):
            problems.append(f"receipt {i}: was sent with {body['check']['found']} known value(s) present")
        pfile = folder / "payloads" / f"{i:06d}.bin"
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
    if vault is not None and lines and rechecked == 0:
        problems.append("no stored payloads to re-check: they were never kept, or they were removed")
    if expect_count is not None and expect_count != len(lines):
        problems.append(f"expected {expect_count} receipt(s), found {len(lines)}: the log was cut or added to")
    if expect_last is not None and expect_last != prev:
        problems.append("the last receipt is not the one you recorded: the log was cut or replaced")
    return {"receipts": len(lines), "rechecked": rechecked, "leaks": leaks_total, "problems": problems,
            "last": prev}


def _safe_digest(token: str) -> str:
    return digest(token.encode("utf-8", errors="replace"))
