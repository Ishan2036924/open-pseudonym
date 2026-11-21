"""Validates the shipped data against the JSON schemas: every profile, the patterns file, the receipt vector, the
release records and checkpoints in the vectors, and an encrypted vault made on the spot."""

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sdk/python/src"))

from open_pseudonym import Session, Vault  # noqa: E402


def schema(name):
    doc = json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text())
    Draft202012Validator.check_schema(doc)
    return Draft202012Validator(doc)


def main() -> int:
    errors = []
    pol = schema("policy")
    for f in sorted((ROOT / "data/profiles").glob("*.json")):
        errors += [f"{f.name}: {e.message}" for e in pol.iter_errors(json.loads(f.read_text()))]
    errors += [f"patterns.json: {e.message}" for e in
               schema("patterns").iter_errors(json.loads((ROOT / "data/patterns.json").read_text()))]
    body = json.loads((ROOT / "vectors/receipts.json").read_text())["body"]
    errors += [f"receipt vector: {e.message}" for e in schema("egress-receipt").iter_errors(body)]
    rel, cp = schema("release-record"), schema("checkpoint")
    releases = json.loads((ROOT / "vectors/releases.json").read_text())
    for case in releases["cases"]:
        for i, rec in enumerate(case["records"], start=1):
            errors += [f"release vector {case['name']!r} record {i}: {e.message}" for e in rel.iter_errors(rec)]
    # the schema must also refuse what verify_log refuses: a value-shaped field, a code on an allow
    allow = releases["cases"][0]["records"][1]
    std = {"rule": "/rules/OTP", "policy": allow["authority"]["policy"]}
    for name, bad in {"an extra field": {**allow, "value": "482913"}, "a code on an allow": {**allow, "code": "used_up"},
                      "no authority": {k: v for k, v in allow.items() if k != "authority"},
                      "a rule without its policy": {**allow, "authority": {"kind": "binding", "rule": "/rules/OTP"}},
                      "a policy without its rule": {**allow, "authority": {"kind": "binding", "policy": std["policy"]}},
                      "a standing on a person's answer": {**allow, "authority": {"kind": "person", **std}},
                      "a rule that is not a pointer": {**allow, "authority": {"kind": "binding", **std, "rule": "OTP"}},
                      "an empty audit id": {**allow, "audit_id": ""},
                      "an audit id of 129 characters": {**allow, "audit_id": "e" * 129},
                      "an audit id with a slash": {**allow, "audit_id": "evt/1"}}.items():
        if not list(rel.iter_errors(bad)):
            errors.append(f"release schema accepts {name}")
    sec = ROOT / "vectors/checkpoints.json"
    doc = json.loads(sec.read_text())
    from open_pseudonym.jws import verify as _verify, Signer as _Signer  # noqa: E402
    anchor = _Signer.from_seed(bytes.fromhex(doc["anchor_key_seed"]))
    for case in doc["cases"]:
        for tok in case["anchor_tokens"]:
            try:
                body = _verify(tok, anchor.public_key, "opn-checkpoint+jws")
            except Exception:  # signed by another key on purpose, or by the writer; the shape is what we check
                import base64
                body = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
            errors += [f"checkpoint vector {case['name']!r}: {e.message}" for e in cp.iter_errors(body)]
    s = Session("strict", Vault(seed=bytes(32)))
    s.mask("Hi Dana,\nok")
    blob = json.loads(s.vault.encrypt(bytes(32)))
    errors += [f"vault: {e.message}" for e in schema("vault").iter_errors(blob)]
    for e in errors:
        print("FAIL", e)
    print("schemas: ok" if not errors else f"schemas: {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
