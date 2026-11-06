"""The vault: the only place where real values and their stand-ins sit side by side.

It never leaves the device (or the app's own server). When saved, it is encrypted with AES-256-GCM under a key the app
keeps; the EDPB treats this table as personal data in its own right, so we treat it like one.

An entry is one real value under one action. Each entry remembers every surface form it was shown as
(`surfaces`: stand-in text -> the real text it replaced), so restoring puts back exactly what the person wrote.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .drbg import Drbg
from .jcs import b64url, b64url_decode

_AAD = b"opn-vault-v1"


class VaultError(Exception):
    pass


@dataclass
class Entry:
    id: str
    type: str
    real: str
    norm: str
    action: str
    stand_in: str
    restorable: bool
    surfaces: dict = field(default_factory=dict)  # stand-in surface -> real surface
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "type": self.type, "real": self.real, "norm": self.norm, "action": self.action,
            "stand_in": self.stand_in, "restorable": self.restorable, "surfaces": self.surfaces, "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        return cls(d["id"], d["type"], d["real"], d["norm"], d["action"], d["stand_in"], d["restorable"],
                   dict(d.get("surfaces") or {}), dict(d.get("meta") or {}))


class Vault:
    def __init__(self, seed: bytes | None = None, created: int | None = None):
        self.seed = seed if seed is not None else os.urandom(32)
        self.drbg = Drbg(self.seed)
        self.created = int(time.time()) if created is None else created
        self.entries: list[Entry] = []
        self._index: dict[tuple[str, str, str], Entry] = {}
        self.used: set[str] = set()  # every stand-in we ever issued, lower case
        self.real_seen: set[str] = set()  # real values and real name parts, lower case
        self.parts: dict[str, str] = {}  # real name part (lower) -> fake part
        self.parts_back: dict[str, str] = {}  # fake name part (lower) -> real part as first written
        self.domains: dict[str, str] = {}  # real registrable domain (lower) -> fake domain
        self.numbers: dict[str, int] = {}  # per type counter for [TYPE_n] and {{TYPE_n}}
        self.date_offset: int | None = None  # days, a non-zero multiple of 7
        self.money_factor: int | None = None
        self.token_key: bytes | None = None  # set it to keep tokens stable across vaults
        self.fpe_key: bytes | None = None
        self.version = 0  # bumps on every change, so caches know when to rebuild

    # Lookups

    def find(self, type_: str, norm: str, action: str) -> Entry | None:
        return self._index.get((type_, norm, action))

    def by_id(self, entry_id: str) -> Entry | None:
        for e in self.entries:
            if e.id == entry_id:
                return e
        return None

    def is_stand_in(self, text: str) -> bool:
        return text.lower() in self.used

    # Changes

    def add(self, type_: str, real: str, norm: str, action: str, stand_in: str, restorable: bool,
            meta: dict | None = None) -> Entry:
        entry = Entry(f"e{len(self.entries) + 1}", type_, real, norm, action, stand_in, restorable,
                      {stand_in: real}, meta or {})
        self.entries.append(entry)
        self._index[(type_, norm, action)] = entry
        self.used.add(stand_in.lower())
        self.real_seen.add(real.lower())
        self.version += 1
        return entry

    def add_surface(self, entry: Entry, stand_in: str, real: str) -> None:
        if entry.surfaces.get(stand_in) != real:
            entry.surfaces.setdefault(stand_in, real)
            self.used.add(stand_in.lower())
            self.version += 1

    def add_part(self, real_part: str, fake_part: str) -> None:
        key = real_part.lower()
        if key not in self.parts:
            self.parts[key] = fake_part
            self.parts_back.setdefault(fake_part.lower(), real_part)
            self.used.add(fake_part.lower())
            self.real_seen.add(key)
            self.version += 1

    def next_number(self, type_: str) -> int:
        n = self.numbers.get(type_, 0) + 1
        self.numbers[type_] = n
        return n

    def touch(self) -> None:
        self.version += 1

    # Values drawn once per vault

    def get_date_offset(self) -> int:
        if self.date_offset is None:
            weeks = self.drbg.below("date.offset", 52) - 26  # -26 .. 25
            if weeks >= 0:
                weeks += 1  # never zero: -26..-1 and 1..26, so the season mostly stays
            self.date_offset = 7 * weeks  # whole weeks keep the weekday
            self.version += 1
        return self.date_offset

    def get_money_factor(self) -> int:
        if self.money_factor is None:
            self.money_factor = 2 + self.drbg.below("money.factor", 3)  # 2, 3 or 4: whole cents stay whole
            self.version += 1
        return self.money_factor

    def get_token_key(self) -> bytes:
        return self.token_key if self.token_key is not None else self.drbg.derive("token")

    def get_fpe_key(self) -> bytes:
        return self.fpe_key if self.fpe_key is not None else self.drbg.derive("fpe")

    # Saving

    def to_dict(self) -> dict:
        return {
            "opn": "0.1",
            "type": "vault-state",
            "seed": b64url(self.seed),
            "created": self.created,
            "counters": self.drbg.counters,
            "entries": [e.to_dict() for e in self.entries],
            "used": sorted(self.used),
            "real_seen": sorted(self.real_seen),
            "parts": self.parts,
            "parts_back": self.parts_back,
            "domains": self.domains,
            "numbers": self.numbers,
            "date_offset": self.date_offset,
            "money_factor": self.money_factor,
            "token_key": b64url(self.token_key) if self.token_key else None,
            "fpe_key": b64url(self.fpe_key) if self.fpe_key else None,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Vault":
        if d.get("type") != "vault-state":
            raise VaultError("not a vault state document")
        v = cls(b64url_decode(d["seed"]), d.get("created"))
        v.drbg = Drbg(v.seed, d.get("counters"))
        for raw in d.get("entries", []):
            e = Entry.from_dict(raw)
            v.entries.append(e)
            v._index[(e.type, e.norm, e.action)] = e
        v.used = set(d.get("used", []))
        v.real_seen = set(d.get("real_seen", []))
        v.parts = dict(d.get("parts", {}))
        v.parts_back = dict(d.get("parts_back", {}))
        v.domains = dict(d.get("domains", {}))
        v.numbers = dict(d.get("numbers", {}))
        v.date_offset = d.get("date_offset")
        v.money_factor = d.get("money_factor")
        v.token_key = b64url_decode(d["token_key"]) if d.get("token_key") else None
        v.fpe_key = b64url_decode(d["fpe_key"]) if d.get("fpe_key") else None
        return v

    def encrypt(self, key: bytes) -> bytes:
        if len(key) != 32:
            raise VaultError("the vault key must be 32 bytes")
        nonce = os.urandom(12)
        body = json.dumps(self.to_dict(), ensure_ascii=False).encode("utf-8")
        ct = AESGCM(key).encrypt(nonce, body, _AAD)
        doc = {"opn": "0.1", "type": "vault", "alg": "A256GCM", "nonce": b64url(nonce), "ciphertext": b64url(ct)}
        return json.dumps(doc).encode("utf-8")

    @classmethod
    def decrypt(cls, blob: bytes, key: bytes) -> "Vault":
        try:
            doc = json.loads(blob)
            if doc.get("type") != "vault" or doc.get("alg") != "A256GCM":
                raise VaultError("not an encrypted vault")
            body = AESGCM(key).decrypt(b64url_decode(doc["nonce"]), b64url_decode(doc["ciphertext"]), _AAD)
        except VaultError:
            raise
        except Exception as exc:  # wrong key, damaged file
            raise VaultError("could not open the vault (wrong key or damaged file)") from exc
        return cls.from_dict(json.loads(body))

    def save(self, path, key: bytes) -> None:
        """Write atomically with owner-only permissions."""
        path = os.fspath(path)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(self.encrypt(key))
        os.replace(tmp, path)

    @classmethod
    def load(cls, path, key: bytes) -> "Vault":
        with open(path, "rb") as fh:
            return cls.decrypt(fh.read(), key)
