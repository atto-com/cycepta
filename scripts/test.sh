#!/usr/bin/env bash
# Fast, hermetic checks. The long wall-clock replay is NOT part of this script;
# see TESTING.md for the re-baseline command.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> .NET build + tests"
dotnet test ThreatDetector/ThreatDetector.sln --nologo

echo "==> Python config contracts"
python3 -m unittest discover -s tests/python -v

echo "==> Dashboard URL sanitizer"
if command -v node >/dev/null 2>&1; then
    node --test tests/js/*.test.mjs
else
    echo "!! node not found; skipping JS tests"
fi

echo "==> Syntax checks"
python3 -m py_compile ncdbody/app/*.py benchmark/*.py
bash -n run.sh
bash -n scripts/test.sh

echo "All fast checks passed."
