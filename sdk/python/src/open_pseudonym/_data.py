"""Loads the shared data files (fake-value pools, detection patterns, starter profiles).

The canonical copies live in the repository's top-level `data/` folder. `tools/sync_data.py` copies them into each
SDK so the installed packages carry them too; CI fails if the copies drift.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"


@lru_cache(maxsize=None)
def pools() -> dict:
    return json.loads((DATA_DIR / "pools.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def patterns() -> list[dict]:
    return json.loads((DATA_DIR / "patterns.json").read_text(encoding="utf-8"))["patterns"]


def profile_names() -> list[str]:
    return sorted(p.stem for p in (DATA_DIR / "profiles").glob("*.json"))


def profile_doc(name: str) -> dict:
    path = DATA_DIR / "profiles" / f"{name}.json"
    if not path.is_file():
        raise KeyError(f"no built-in profile called {name!r}; try one of {profile_names()}")
    return json.loads(path.read_text(encoding="utf-8"))
