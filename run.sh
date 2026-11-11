#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

NCD_PORT="${NCD_PORT:-5000}"
API_PORT="${API_PORT:-5001}"
# Safe default: local-only. Use BIND_HOST=0.0.0.0 only behind a proxy.
BIND_HOST="${BIND_HOST:-${NCD_BIND_HOST:-127.0.0.1}}"
# A wildcard bind is not a connectable address everywhere; probes and the
# server-to-server NCD URL use loopback in that case.
PROBE_HOST="$BIND_HOST"
case "$BIND_HOST" in
    0.0.0.0|::) PROBE_HOST=127.0.0.1 ;;
esac
export NcdService__Url="http://${PROBE_HOST}:${NCD_PORT}"

if ! command -v dotnet >/dev/null 2>&1; then
    echo "FATAL: dotnet not found. Install the .NET 10 SDK: https://dotnet.microsoft.com/download" >&2
    exit 1
fi

# The NCD engine imports more than the web stack; check the full set so a
# half-installed env fails here instead of after the API starts.
ncd_deps_ok() {
    "$1" -c 'import numpy, fastapi, uvicorn, sentence_transformers, skimage, umap' >/dev/null 2>&1
}

PY=""
for cand in "$ROOT/.venv/bin/python" "$ROOT/ncdbody/.venv/bin/python"; do
    if ncd_deps_ok "$cand"; then
        PY="$cand"
        break
    fi
    if [ -x "$cand" ]; then
        echo "==> $cand exists but is missing required packages; run 'bash setup.sh' or fix it." >&2
    fi
done

if [ -z "$PY" ]; then
    PY="${PYTHON:-python3}"
    if ! ncd_deps_ok "$PY"; then
        echo "FATAL: $PY lacks the NCD dependencies; run 'bash setup.sh' or set PYTHON to a prepared interpreter." >&2
        exit 1
    fi
    echo "==> Using $PY ($($PY --version))"
fi

cd ncdbody
NUMBA_NUM_THREADS="${NUMBA_NUM_THREADS:-1}" "$PY" -m uvicorn app.main:app --host "$BIND_HOST" --port "$NCD_PORT" &
NCD_PID=$!
trap 'kill "$NCD_PID" 2>/dev/null || true' EXIT

echo "==> Waiting for NCD on :$NCD_PORT (first start downloads the embedding model; up to 30 min)"
ready=0
for i in $(seq 1 900); do
  if curl -sf "http://${PROBE_HOST}:${NCD_PORT}/api/v1/health" >/dev/null 2>&1; then
    echo "==> NCD ready (after $((i * 2))s)"
    ready=1
    break
  fi
  if ! kill -0 "$NCD_PID" 2>/dev/null; then
    echo "!! NCD process died" >&2
    exit 1
  fi
  sleep 2
done

if [ "$ready" != "1" ]; then
  echo "!! NCD did not become healthy within 1800s" >&2
  exit 1
fi

cd "$ROOT/ThreatDetector/src/ThreatDetector.Api"
echo "==> Starting API on ${BIND_HOST}:${API_PORT} - dashboard at http://localhost:${API_PORT}/"
dotnet run --project . --urls "http://${BIND_HOST}:${API_PORT}"
