#!/usr/bin/env bash
set -euo pipefail

# NCD (Python) in the background
cd /app/ncdbody
uvicorn app.main:app --host 0.0.0.0 --port 8080 &
NCD_PID=$!

# wait for the NCD model to load (first start downloads the embedding model; up to 30 min)
ready=0
for i in $(seq 1 900); do
  if curl -sf http://127.0.0.1:8080/api/v1/health >/dev/null 2>&1; then
    echo "[entrypoint] NCD is ready (after $((i * 2))s)"
    ready=1
    break
  fi
  if ! kill -0 "$NCD_PID" 2>/dev/null; then
    echo "[entrypoint] FATAL: NCD process died" >&2
    exit 1
  fi
  sleep 2
done

if [ "$ready" != "1" ]; then
  echo "[entrypoint] FATAL: NCD did not become healthy within 1800s" >&2
  exit 1
fi

# API and NCD share the container, so supervise both: if either dies, stop
# the other and exit so Docker's restart policy restarts the pair.
cd /app/api
dotnet ThreatDetector.Api.dll --urls http://0.0.0.0:5001 &
API_PID=$!

trap 'kill "$NCD_PID" "$API_PID" 2>/dev/null || true; wait || true; exit 0' TERM INT

status=0
wait -n "$NCD_PID" "$API_PID" || status=$?
echo "[entrypoint] a service exited (status $status); shutting down the container" >&2
kill "$NCD_PID" "$API_PID" 2>/dev/null || true
wait || true
exit "$status"