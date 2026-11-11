#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV="$ROOT/.venv"

if [ -n "${PYTHON:-}" ]; then
    PY="$PYTHON"
elif [ -x "$VENV/bin/python" ]; then
    # Reuse an existing compatible env even if python3.12 is not on PATH.
    PY="$VENV/bin/python"
else
    PY=""
    for cand in python3.12 python3.11 python3.10; do
        if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
    done
    [ -z "$PY" ] && PY="python3"
fi
echo "==> Using interpreter: $PY ($($PY --version))"
if ! "$PY" -c 'import sys; sys.exit(0 if (3,10) <= sys.version_info[:2] <= (3,12) else 1)'; then
    echo "!! Unsupported Python: $($PY --version). Required: 3.10-3.12 (>=3.13 has no wheels for pinned deps)."
    if command -v uv >/dev/null 2>&1; then
        echo "   Hint: PYTHON=\"\$(uv python find 3.12)\" bash setup.sh"
    else
        echo "   Install Python 3.12 (for example: brew install python@3.12) and rerun."
    fi
    exit 1
fi

if [ ! -x "$VENV/bin/python" ]; then
    echo "==> Creating venv at $VENV"
    "$PY" -m venv "$VENV"
fi
source "$VENV/bin/activate"
VENV_PY="$VENV/bin/python"

# uv-created venvs have no pip by default; install it into the venv. Never use
# a bare `pip` here: with an activated uv venv the shell may find a global pip
# and install Cycepta's pinned deps into the user's base interpreter.
if ! "$VENV_PY" -m pip --version >/dev/null 2>&1; then
    echo "==> Installing pip into $VENV"
    "$VENV_PY" -m ensurepip --upgrade
fi

echo "==> Installing Python dependencies"
"$VENV_PY" -m pip install --upgrade pip
"$VENV_PY" -m pip install -r ncdbody/requirements.txt

echo "==> Restoring .NET NuGet packages"
if ! command -v dotnet >/dev/null 2>&1; then
    for DOTNET_DIR in "$HOME/.dotnet" /usr/local/share/dotnet /usr/local/dotnet; do
        if [ -x "$DOTNET_DIR/dotnet" ]; then
            export PATH="$DOTNET_DIR:$PATH"
            break
        fi
    done
fi
if command -v dotnet >/dev/null 2>&1; then
    dotnet restore ThreatDetector/ThreatDetector.sln
else
    echo "!! dotnet not found. Install .NET 10 SDK: https://dotnet.microsoft.com/download"
fi

LLM_DIR="$ROOT/ncdbody/models/granite-4.0-1b"
if [ ! -f "$LLM_DIR/model.safetensors" ]; then
    echo "!! LLM weights not found at $LLM_DIR"
    echo "   The Granite 4.0 1B weights are not shipped in the repo. Download ibm-granite/granite-4.0-1b from HuggingFace (license gate)."
    echo "   Put it into 'ncdbody/models/granite-4.0-1b/' or set NCD_LLM_MODEL."
fi

echo "==> Pre-downloading embedding model (all-mpnet-base-v2)"
"$VENV_PY" - <<'PY'
from sentence_transformers import SentenceTransformer
SentenceTransformer("sentence-transformers/all-mpnet-base-v2")
print("Embedding model ready")
PY

echo "==> Done."
echo "Run: bash run.sh  (starts NCD on :5000 and the API dashboard on :5001)"