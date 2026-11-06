"""Runs the shared vectors against this SDK: python -m open_pseudonym.conformance path/to/vectors

Exit code 0 means every vector passed. Each failure prints the file, the case and what differed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from . import checks
from .drbg import Drbg
from .fpe import FF1
from .handles import HandleRefused, Sink, Source
from .jcs import canonical, digest
from .jws import Signer, verify
from .policy import PolicyError, load_profile
from .session import Session
from .vault import Vault

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


class Runner:
    def __init__(self, folder: Path):
        self.folder = folder
        self.passed = 0
        self.failed: list[str] = []

    def ok(self, cond: bool, where: str, detail: str = "") -> None:
        if cond:
            self.passed += 1
        else:
            self.failed.append(f"{where}: {detail}" if detail else where)

    def load(self, name: str) -> dict:
        return json.loads((self.folder / f"{name}.json").read_text(encoding="utf-8"))

    def run(self) -> int:
        for name in ("checks", "drbg", "ff1", "detect", "policy", "scenarios", "receipts"):
            getattr(self, name)(self.load(name))
        for f in self.failed:
            print("FAIL", f)
        print(f"{self.passed} passed, {len(self.failed)} failed")
        return 1 if self.failed else 0

    def checks(self, doc):
        fns = {"card": checks.card_ok, "iban": checks.iban_ok, "aba": checks.aba_ok, "ssn": checks.ssn_ok,
               "phone": checks.phone_ok, "name": checks.name_ok}
        for c in doc["cases"]:
            self.ok(fns[c["check"]](c["value"]) == c["ok"], f"checks {c['check']} {c['value']!r}")

    def drbg(self, doc):
        seed = bytes.fromhex(doc["seed"])
        fb = doc["first_block"]
        self.ok(Drbg(seed).block(fb["label"]).hex() == fb["hex"], "drbg first block")
        self.ok(Drbg(seed).derive(doc["derive"]["purpose"]).hex() == doc["derive"]["hex"], "drbg derive")
        d = Drbg(seed)
        for i, draw in enumerate(doc["draws"]):
            got = d.below(draw["label"], draw["n"])
            self.ok(got == draw["value"], f"drbg draw {i}", f"got {got}, want {draw['value']}")

    def ff1(self, doc):
        for i, c in enumerate(doc["cases"]):
            f = FF1(bytes.fromhex(c["key"]), c["radix"])
            pt = [ALPHABET.index(ch) for ch in c["pt"]]
            ct = "".join(ALPHABET[x] for x in f.encrypt(pt, bytes.fromhex(c["tweak"])))
            self.ok(ct == c["ct"], f"ff1 case {i}", f"got {ct}")
            back = "".join(ALPHABET[x] for x in f.decrypt([ALPHABET.index(ch) for ch in ct], bytes.fromhex(c["tweak"])))
            self.ok(back == c["pt"], f"ff1 case {i} decrypt")

    def detect(self, doc):
        for i, c in enumerate(doc["cases"]):
            s = Session(c["profile"], Vault(seed=bytes(32)), clock=lambda c=c: c["now"])
            got = [[sp.type, sp.text] for sp in s.detect(c["text"])]
            self.ok(got == c["spans"], f"detect case {i}", f"got {got}")

    def policy(self, doc):
        for i, c in enumerate(doc["cases"]):
            where = f"policy case {i} ({c['op']})"
            if c["op"] == "tighten":
                t = load_profile(c["a"]).tighten(load_profile(c["b"]))
                self.ok(all(t.rule_for(k).action == v for k, v in c["expect"].items()), where)
            elif c["op"] == "with_rules":
                try:
                    p = load_profile(c["base"]).with_rules(c["rules"])
                    self.ok("expect" in c and all(p.rule_for(k).action == v for k, v in c["expect"].items()), where)
                except PolicyError as exc:
                    self.ok(c.get("error") == str(exc), where, str(exc))
            elif c["op"] == "digest":
                self.ok(load_profile(c["profile"]).digest == c["expect"], where)

    def scenarios(self, doc):
        for sc in doc["scenarios"]:
            s = Session(sc["profile"], Vault(seed=bytes.fromhex(sc["seed"]), created=sc["now"]),
                        clock=lambda sc=sc: sc["now"], known=sc["known"])
            for j, st in enumerate(sc["steps"]):
                where = f"scenario {sc['name']!r} step {j} ({st['op']})"
                got = self._step(s, st)
                self.ok(got == st["expect"], where, f"got {json.dumps(got, ensure_ascii=False)[:300]}")

    @staticmethod
    def _step(s: Session, st: dict):
        op = st["op"]
        if op == "mask":
            src = st.get("source")
            m = s.mask(st["text"], Source(**src) if src else None)
            return {"text": m.text, "notes": m.notes}
        if op == "restore":
            return s.restore(st["text"], st.get("reveal", False))
        if op == "stream":
            sr = s.stream(st.get("reveal", False))
            out, i = [], 0
            for n in st["chunks"]:
                out.append(sr.feed(st["text"][i:i + n]))
                i += n
            out.append(sr.feed(st["text"][i:]))
            out.append(sr.flush())
            return "".join(out)
        if op == "resolve":
            try:
                return {"args": s.resolve_args(st["args"], Sink(**st["sink"])).args}
            except HandleRefused as exc:
                return {"refused": exc.reason}
        if op == "egress":
            return sorted({lk.type for lk in s.check_egress(st["payload"])})
        if op == "mask_messages":
            msgs, notes = s.mask_messages(st["messages"])
            return {"messages": msgs, "notes": notes}
        raise ValueError(op)

    def receipts(self, doc):
        signer = Signer.from_seed(bytes.fromhex(doc["private_key_seed"]))
        self.ok(signer.kid == doc["kid"], "receipts kid")
        self.ok(canonical(doc["body"]).decode() == doc["canonical_body"], "receipts canonical body")
        self.ok(signer.sign(doc["body"], "opn-egress+jws") == doc["token"], "receipts token")
        self.ok(verify(doc["token"], signer.public_key, "opn-egress+jws") == doc["body"], "receipts verify")
        self.ok(digest(b"hello") == doc["payload_digest_of_hello"], "receipts digest")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    folder = Path(argv[0] if argv else "vectors")
    return Runner(folder).run()


if __name__ == "__main__":
    sys.exit(main())
