"""Check the hash-locked CI requirements: python tools/check_ci_locks.py

1. Every ci/*.in names the SDK's own dependencies plus the extras on its "# extras:" line (sdk/python/pyproject.toml),
   so a new dependency cannot make a CI job skip tests silently.
2. Every ci/*.txt is a universal, hash-locked compile of its .in: each pin carries a sha256 hash and each .in name is pinned.
3. Every `pip install` in .github/workflows installs either from a lock with --require-hashes, or a local wheel with
   --no-deps (the two forms OpenSSF Scorecard's Pinned-Dependencies check counts as pinned).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def req_name(line: str) -> str | None:
    line = line.split("#", 1)[0].strip()
    m = NAME.match(line)
    return norm(m.group(1)) if m else None


def sdk_requirements(pyproject_text: str) -> tuple[set[str], dict[str, set[str]]]:
    import tomllib  # Python 3.11+

    project = tomllib.loads(pyproject_text)["project"]
    base = {n for n in map(req_name, project.get("dependencies", [])) if n}
    extras = {k: {n for n in map(req_name, v) if n} for k, v in project.get("optional-dependencies", {}).items()}
    return base, extras


def check_in(text: str, base: set[str], extras: dict[str, set[str]]) -> list[str]:
    names = {n for n in map(req_name, text.splitlines()) if n}
    m = re.search(r"^# extras:(.*)$", text, re.M)
    if not m:
        return []
    errors, wanted = [], set(base)
    for extra in (e.strip() for e in m.group(1).split(",") if e.strip()):
        if extra not in extras:
            errors.append(f"unknown extra {extra!r}")
        wanted |= extras.get(extra, set())
    errors += [f"missing {n} (SDK dependency or extra)" for n in sorted(wanted - names)]
    return errors


def check_txt(txt: str, in_text: str) -> list[str]:
    errors = []
    header = "\n".join(txt.splitlines()[:3])
    for flag in ("uv pip compile", "--universal", "--generate-hashes"):
        if flag not in header:
            errors.append(f"header lacks {flag!r} (relock with the command in the .in file)")
    lines = txt.splitlines()
    pinned = set()
    for i, line in enumerate(lines):
        if not line or line[0] in " #":
            continue
        if "==" not in line or line.startswith("-e") or "@" in line.split("==", 1)[0]:
            errors.append(f"not an exact pin: {line.strip()}")
            continue
        if i + 1 >= len(lines) or "--hash=sha256:" not in lines[i + 1]:
            errors.append(f"no sha256 hash for {line.strip()}")
        pinned.add(req_name(line))
    in_names = {n for n in map(req_name, in_text.splitlines()) if n}
    errors += [f"{n} is in the .in file but not pinned (relock)" for n in sorted(in_names - pinned)]
    return errors


PIP = re.compile(r"\bpip3?\s+install\b(?P<args>[^&;|\n]*)")


def check_workflow(text: str) -> list[str]:
    errors = []
    for m in PIP.finditer(text):
        args = m.group("args").split()
        hashed = "--require-hashes" in args and any(a == "-r" or a.startswith("--requirement") for a in args)
        wheel = "--no-deps" in args and all(a.startswith("-") or a.strip("\"'").endswith(".whl") for a in args)
        if not (hashed or wheel):
            errors.append(f"unpinned: {m.group(0).strip()}")
    return errors


def main() -> int:
    errors: list[str] = []
    base, extras = sdk_requirements((ROOT / "sdk/python/pyproject.toml").read_text(encoding="utf-8"))
    ins = sorted((ROOT / "ci").glob("*.in"))
    if not ins:
        errors.append("ci/: no .in files")
    for src in ins:
        in_text = src.read_text(encoding="utf-8")
        lock = src.with_suffix(".txt")
        errors += [f"{src.relative_to(ROOT)}: {e}" for e in check_in(in_text, base, extras)]
        if not lock.exists():
            errors.append(f"{lock.relative_to(ROOT)}: missing")
            continue
        errors += [f"{lock.relative_to(ROOT)}: {e}" for e in check_txt(lock.read_text(encoding="utf-8"), in_text)]
    for wf in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
        errors += [f"{wf.relative_to(ROOT)}: {e}" for e in check_workflow(wf.read_text(encoding="utf-8"))]
    for e in errors:
        print(e, file=sys.stderr)
    print("ci locks: ok" if not errors else f"ci locks: {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
