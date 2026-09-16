#!/usr/bin/env bash
set -euo pipefail

# NCD (Python) в фоне
cd /app/ncdbody
uvicorn app.main:app --host 0.0.0.0 --port 8080 &
NCD_PID=$!

# дождаться загрузки модели NCD (первый старт ~1-2 мин, качает эмбеддер)
for i in $(seq 1 90); do
  if curl -sf http://localhost:8080/api/v1/health >/dev/null 2>&1; then
    echo "[entrypoint] NCD is ready (after ${i}0s)"
    break
  fi
  sleep 2
done

if ! kill -0 "$NCD_PID" 2>/dev/null; then
  echo "[entrypoint] FATAL: NCD process died" >&2
  exit 1
fi

# API (локальная точка входа, держит контейнер живым)
cd /app/api
exec dotnet ThreatDetector.Api.dll