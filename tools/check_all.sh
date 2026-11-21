#!/usr/bin/env bash
# Every check, in the order CI runs them. PYTHON=/path/to/python picks the interpreter.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
"$PY" tools/sync_data.py --check
PYTHONPATH=sdk/python/src "$PY" -m open_pseudonym.conformance vectors
(cd sdk/python && "$PY" -m pytest -q)  # parts whose extras are missing are skipped
if "$PY" -c "import jsonschema" 2>/dev/null; then "$PY" tools/check_schemas.py; else echo "skip: schemas (pip install jsonschema)"; fi
"$PY" tools/test_fetch_published.py 2>&1 | tail -1  # release signing takes only bytes matching the registries' digests
if "$PY" -c "import tomllib" 2>/dev/null; then "$PY" tools/check_ci_locks.py && "$PY" tools/test_check_ci_locks.py 2>&1 | tail -1; else echo "skip: CI lock check (Python 3.11+)"; fi
"$PY" bench/run.py offline --out /tmp/opn-offline.md > /dev/null && echo "bench offline: ok"
if [ -d sdk/typescript/node_modules/typescript ]; then
  (cd sdk/typescript && npm run build --silent && node src/conformance.ts ../../vectors && node dist/conformance.js ../../vectors && npm test --silent)
else
  echo "skip: TypeScript (run npm ci in sdk/typescript)"
fi
PYTHONPATH=sdk/python/src "$PY" -m open_pseudonym demo > /dev/null && echo "demo: ok"
if command -v gitleaks > /dev/null; then gitleaks dir . --no-banner --redact -c .gitleaks.toml; else echo "skip: gitleaks"; fi
if "$PY" -m ruff --version > /dev/null 2>&1; then "$PY" -m ruff check . && echo "ruff: ok"; else echo "skip: ruff (pip install --require-hashes -r ci/test.txt)"; fi
