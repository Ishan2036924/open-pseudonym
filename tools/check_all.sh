#!/usr/bin/env bash
# Every check, in the order CI runs them. PYTHON=/path/to/python picks the interpreter.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
"$PY" tools/sync_data.py --check
PYTHONPATH=sdk/python/src "$PY" -m open_pseudonym.conformance vectors
(cd sdk/python && "$PY" -m pytest -q)  # parts whose extras are missing are skipped
if "$PY" -c "import jsonschema" 2>/dev/null; then "$PY" tools/check_schemas.py; else echo "skip: schemas (pip install jsonschema)"; fi
"$PY" bench/run.py offline --out /tmp/opn-offline.md > /dev/null && echo "bench offline: ok"
if [ -d sdk/typescript/node_modules/typescript ]; then
  (cd sdk/typescript && npm run build --silent && node src/conformance.ts ../../vectors && node dist/conformance.js ../../vectors && npm test --silent)
else
  echo "skip: TypeScript (run npm ci in sdk/typescript)"
fi
PYTHONPATH=sdk/python/src "$PY" -m open_pseudonym demo > /dev/null && echo "demo: ok"
if command -v gitleaks > /dev/null; then gitleaks dir . --no-banner --redact -c .gitleaks.toml; else echo "skip: gitleaks"; fi
