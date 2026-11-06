"""Copies the canonical data/ folder into each SDK. Run with --check in CI to fail on drift."""

import filecmp
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = [ROOT / "sdk/python/src/open_pseudonym/data", ROOT / "sdk/typescript/data"]


def files(base: Path):
    return sorted(p.relative_to(base) for p in base.rglob("*.json"))


def main() -> int:
    check = "--check" in sys.argv
    src = ROOT / "data"
    drift = []
    for target in TARGETS:
        for rel in files(src):
            dest = target / rel
            if check:
                if not dest.exists() or not filecmp.cmp(src / rel, dest, shallow=False):
                    drift.append(str(dest.relative_to(ROOT)))
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src / rel, dest)
        if target.exists():
            for rel in files(target):
                if not (src / rel).exists():
                    if check:
                        drift.append(str((target / rel).relative_to(ROOT)) + " (not in data/)")
                    else:
                        (target / rel).unlink()
    if drift:
        print("data copies are out of date; run python tools/sync_data.py:\n  " + "\n  ".join(drift))
        return 1
    print("data copies match" if check else "data copied into both SDKs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
