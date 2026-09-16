# syntax=docker/dockerfile:1

# =============================================================
#  Concepta — единый образ: Python NCD + .NET ThreatDetector API
#  2 процесса в одном контейнере (supervisor-шелл /entrypoint.sh)
# =============================================================

# ---- Стадия 1: сборка .NET API ----
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

# ---- Стадия 2: runtime python + .NET runtime ----
FROM python:3.12-slim AS runtime
WORKDIR /app

# Инструменты + libicu (нужен .NET runtime) + ASP.NET Core 10 runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates libicu-dev \
 && rm -rf /var/lib/apt/lists/* \
 && curl -sSL https://dot.net/v1/dotnet-install.sh \
      | bash /dev/stdin --channel 10.0 --runtime aspnetcore \
        --install-dir /usr/share/dotnet
ENV PATH="/usr/share/dotnet:${PATH}"
ENV DOTNET_ROOT=/usr/share/dotnet

# CPU-only torch отдельно (иначе PyPI тянет ГБы CUDA-библиотек)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Python-зависимости NCD
COPY ncdbody/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Код NCD + собранный API + entrypoint
COPY ncdbody/app ./ncdbody/app
COPY --from=api-build /app/out ./api
COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /data

# NCD
ENV NCD_DEVICE=cpu
ENV NUMBA_NUM_THREADS=1
ENV PYTHONUNBUFFERED=1
# API
ENV NcdService__Url=http://localhost:8080
ENV THREAT_DB_PATH=/data/threats.db
ENV ASPNETCORE_HTTP_PORTS=5001

EXPOSE 8080 5001
ENTRYPOINT ["/entrypoint.sh"]