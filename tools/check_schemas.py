"""Validates the shipped data against the JSON schemas: every profile, the patterns file, the receipt vector, and
an encrypted vault made on the spot."""

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
