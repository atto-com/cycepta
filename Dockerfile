# syntax=docker/dockerfile:1

# =============================================================
#  Cycepta — single image: Python NCD service + .NET ThreatDetector API
#  2 processes in one container (supervisor shell /entrypoint.sh)
# =============================================================

# ---- Stage 1: build the .NET API ----
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS api-build
WORKDIR /src

COPY ThreatDetector/src/ThreatDetector.Contracts/ThreatDetector.Contracts.csproj ThreatDetector/src/ThreatDetector.Contracts/
COPY ThreatDetector/src/ThreatDetector.Parsing/ThreatDetector.Parsing.csproj ThreatDetector/src/ThreatDetector.Parsing/
COPY ThreatDetector/src/ThreatDetector.Storage/ThreatDetector.Storage.csproj ThreatDetector/src/ThreatDetector.Storage/
COPY ThreatDetector/src/ThreatDetector.Api/ThreatDetector.Api.csproj ThreatDetector/src/ThreatDetector.Api/
COPY ncdbody/app/ncd.proto ncdbody/app/ncd.proto
RUN dotnet restore ThreatDetector/src/ThreatDetector.Api/ThreatDetector.Api.csproj

COPY ThreatDetector/src/ThreatDetector.Contracts/ ThreatDetector/src/ThreatDetector.Contracts/
COPY ThreatDetector/src/ThreatDetector.Parsing/ ThreatDetector/src/ThreatDetector.Parsing/
COPY ThreatDetector/src/ThreatDetector.Storage/ ThreatDetector/src/ThreatDetector.Storage/
COPY ThreatDetector/src/ThreatDetector.Api/ ThreatDetector/src/ThreatDetector.Api/

RUN dotnet publish ThreatDetector/src/ThreatDetector.Api/ThreatDetector.Api.csproj \
    -c Release -o /app/out

# ---- Stage 2: python + .NET runtime ----
FROM python:3.12-slim AS runtime
WORKDIR /app

# Tools + libicu (required by .NET) + ASP.NET Core 10 runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates libicu-dev \
 && rm -rf /var/lib/apt/lists/* \
 && curl -sSL https://dot.net/v1/dotnet-install.sh \
      | bash /dev/stdin --channel 10.0 --runtime aspnetcore \
        --install-dir /usr/share/dotnet
ENV PATH="/usr/share/dotnet:${PATH}"
ENV DOTNET_ROOT=/usr/share/dotnet

# CPU-only torch installed separately (PyPI would pull GBs of CUDA libs).
# Pinned so image builds stay reproducible; bump together with requirements.
RUN pip install --no-cache-dir torch==2.6.0 --index-url https://download.pytorch.org/whl/cpu

# NCD Python dependencies
COPY ncdbody/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# NCD code, built API and entrypoint
COPY ncdbody/app ./ncdbody/app
# Provider registry lives next to the app package (ncdbody/llm_providers.yaml);
# without it the container silently exposes only the default local model.
COPY ncdbody/llm_providers.yaml ./ncdbody/llm_providers.yaml
COPY --from=api-build /app/out ./api
COPY docker-entrypoint.sh /entrypoint.sh

# Run as an unprivileged user. /app must be writable for the HuggingFace cache
# and Python bytecode; /data is the persistent SQLite volume.
RUN groupadd --system app \
 && useradd --system --gid app --create-home app \
 && mkdir -p /data /home/app/.ncd/models \
 && chmod +x /entrypoint.sh \
 && chown -R app:app /app /data /home/app

# NCD
ENV NCD_DEVICE=cpu
ENV NUMBA_NUM_THREADS=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV NCD_MODEL_CACHE=/home/app/.ncd/models
# API
ENV NcdService__Url=http://127.0.0.1:8080
ENV THREAT_DB_PATH=/data/threats.db
ENV ASPNETCORE_HTTP_PORTS=5001
ENV HOME=/home/app

USER app

EXPOSE 8080 5001
ENTRYPOINT ["/entrypoint.sh"]
