"""Runs the shared vectors against this SDK: python -m open_pseudonym.conformance path/to/vectors

Exit code 0 means every vector passed. Each failure prints the file, the case and what differed.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from . import checks
from .drbg import Drbg
from .egress import EgressLog, make_checkpoint, release_body, verify_log
from .fpe import FF1
from .handles import Approval, HandleRefused, Sink, Source
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
        for name in ("checks", "drbg", "ff1", "detect", "policy", "scenarios", "receipts", "releases", "checkpoints"):
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
        if op == "resolve_report":
            return {"report": s.resolve_args(st["args"], Sink(**st["sink"])).report}
        if op == "egress":
            return sorted({lk.type for lk in s.check_egress(st["payload"])})
        if op == "mask_messages":
            msgs, notes = s.mask_messages(st["messages"])
            return {"messages": msgs, "notes": notes}
        raise ValueError(op)

    def releases(self, doc):
        writer = _signer("writer")
        self.ok(writer.kid == doc["kid"], "releases kid")
        for case in doc["cases"]:
            where = f"release case {case['name']!r}"
            with tempfile.TemporaryDirectory() as tmp:
                got = run_release_case(case, Path(tmp))
            self.ok(got["results"] == case["results"], where + " results", json.dumps(got["results"])[:300])
            self.ok(got["records"] == case["records"], where + " records", json.dumps(got["records"])[:300])
            self.ok(got["tokens"] == case["tokens"], where + " tokens")
            self.ok(got["report"]["problems"] == [], where + " verify", str(got["report"]["problems"]))
            text = "\n".join(canonical(r).decode() for r in got["records"])
            self.ok(not any(n in text for n in case["never_in_records"]), where + " holds no value or hash")
        for case in doc["shapes"]:
            with tempfile.TemporaryDirectory() as tmp:
                got = run_shape_case(case, Path(tmp))
            self.ok(got == case["problems"], f"release shape {case['name']!r}", json.dumps(got)[:300])

    def checkpoints(self, doc):
        for case in doc["cases"]:
            with tempfile.TemporaryDirectory() as tmp:
                got = run_checkpoint_case(doc, case, Path(tmp))
            where = f"checkpoint case {case['name']!r}"
            self.ok(got["full"] == doc["tokens"], where + " log tokens")
            self.ok(got["tokens"] == case["anchor_tokens"], where + " anchor tokens")
            self.ok(got["result"] == case["expect"], where, json.dumps(got["result"])[:300])

    def receipts(self, doc):
        signer = Signer.from_seed(bytes.fromhex(doc["private_key_seed"]))
        self.ok(signer.kid == doc["kid"], "receipts kid")
        self.ok(canonical(doc["body"]).decode() == doc["canonical_body"], "receipts canonical body")
        self.ok(signer.sign(doc["body"], "opn-egress+jws") == doc["token"], "receipts token")
        self.ok(verify(doc["token"], signer.public_key, "opn-egress+jws") == doc["body"], "receipts verify")
        self.ok(digest(b"hello") == doc["payload_digest_of_hello"], "receipts digest")


WRITER_SEED = bytes(range(32))
ANCHOR_SEED = bytes(range(32, 64))
OTHER_SEED = bytes([9] * 32)


def _signer(name: str) -> Signer:
    return Signer.from_seed({"writer": WRITER_SEED, "anchor": ANCHOR_SEED, "other": OTHER_SEED}[name])


def read_lines(folder: Path) -> list[str]:
    return [ln for ln in (folder / "receipts.jsonl").read_text().splitlines() if ln.strip()]


def run_release_case(case: dict, folder: Path) -> dict:
    """Plays one release case through the SDK: a session with a release log in `folder`, then each step. Returns what
    each step gave, the signed records read back from the log, their tokens and the verify_log report."""
    now = [case["now"]]
    spec = case.get("approve")
    approve = None if spec is None else (lambda *_: Approval(**spec) if isinstance(spec, dict) else spec)
    writer = _signer("writer")
    s = Session(case["profile"], Vault(seed=bytes.fromhex(case["seed"]), created=case["now"]), clock=lambda: now[0],
                approve=approve, session_id="s1", release_log=EgressLog(folder, writer, store_payloads=False))
    if case.get("mask"):
        src = case["mask"].get("source")
        s.mask(case["mask"]["text"], Source(**src) if src else None)
    results = []
    for st in case["steps"]:
        if "at" in st:
            now[0] = st["at"]
        if st.get("op") == "break_log":
            os.mkdir(folder / "receipts.jsonl")  # appending to a folder fails
            continue
        if st.get("op") == "fix_log":
            os.rmdir(folder / "receipts.jsonl")
            continue
        try:
            results.append({"args": s.resolve_args(st["args"], Sink(**st["sink"])).args})
        except HandleRefused as exc:
            results.append({"refused": exc.reason, "code": exc.code})
    tokens = read_lines(folder)
    records = [verify(t, writer.public_key, "opn-release+jws") for t in tokens]
    return {"results": results, "records": records, "tokens": tokens,
            "report": verify_log(folder, writer.public_key, s.vault)}


def run_shape_case(case: dict, folder: Path) -> list[str]:
    """Signs a release record changed the way `case` says and returns what verify_log reports about it."""
    writer = _signer("writer")
    body = release_body(case["entry"], 1, None)
    for k, v in case.get("set", {}).items():
        body[k] = v
    for k in case.get("delete", []):
        del body[k]
    (folder / "receipts.jsonl").write_text(writer.sign(body, "opn-release+jws") + "\n")
    vault = None
    if case.get("mask"):
        s = Session(case["profile"], Vault(seed=bytes.fromhex(case["seed"]), created=case["now"]),
                    clock=lambda: case["now"])
        s.mask(case["mask"])
        vault = s.vault
    return verify_log(folder, writer.public_key, vault)["problems"]


def run_checkpoint_case(doc: dict, case: dict, folder: Path) -> dict:
    """Writes the log in `doc`, cuts it to `keep` records, signs the case's checkpoints and verifies the log."""
    writer = _signer("writer")
    log = EgressLog(folder, writer, store_payloads=False)
    for e in doc["entries"]:
        log.record_release(**e)
    full = read_lines(folder)
    (folder / "receipts.jsonl").write_text("".join(ln + "\n" for ln in full[:case["keep"]]))
    tokens = []
    for a in case["anchors"]:
        head = digest(b"another log") if a.get("head") == "other" else digest(full[a["seq"] - 1].encode("ascii"))
        tokens.append(make_checkpoint(_signer(a.get("signer", "anchor")), session=a.get("session", "s1"),
                                      seq=a["seq"], head=head, now=doc["now"]))
    key = case.get("anchor_key", "anchor")
    report = verify_log(folder, writer.public_key, anchors=tokens, anchor_key=_signer(key).public_key if key else None,
                        expect_count=case.get("expect_count"))
    return {"full": full, "tokens": tokens,
            "result": {k: report[k] for k in ("receipts", "problems", "proven_to", "status", "reason")}}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    folder = Path(argv[0] if argv else "vectors")
    return Runner(folder).run()


if __name__ == "__main__":
    sys.exit(main())
