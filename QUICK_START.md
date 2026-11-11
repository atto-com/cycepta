# Cycepta — Quick Start

Emerging-threat detection on a live cyber-security stream. A **single Docker
image** runs both processes in one container:

| Process | Stack | Port | Role |
|---------|-------|------|------|
| `uvicorn` (NCD) | Python (FastAPI) | `5000 → 8080` | NCD engine: embeddings, UMAP, clustering, report summaries |
| `dotnet` (API) | .NET 10 (ASP.NET) | `5001` | HTTP API, RSS/NVD parsing, storage, SignalR |

## Running with Docker

Requires Docker + Docker Compose.

```bash
# from the repository root
docker compose up --build -d
```

Or without compose:

```bash
docker build -t cycepta .
docker run -d --name cycepta --restart unless-stopped \
       -p 127.0.0.1:5000:8080 -p 127.0.0.1:5001:5001 \
       -v cycepta-data:/data \
       -v cycepta-models:/home/app/.ncd/models cycepta
```

To use an API provider with plain `docker run`, pass its key with
`--env-file .env` (or `-e ANTHROPIC_API_KEY=...`). Compose forwards
`OPENAI_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY` and
`ANTHROPIC_API_KEY` from `.env` automatically.

The container runs as the unprivileged `app` user; ports are published on
localhost only. To expose it, put an authenticating reverse proxy in front
and bind `0.0.0.0` explicitly.

The first image build downloads the Python/.NET runtimes and dependencies;
the first container start downloads the `all-mpnet-base-v2` embedding model
(~420 MB). Expect roughly 3–15 minutes depending on network; subsequent
starts take seconds. The image does not bundle Granite — mount it separately
to enable local LLM summaries (see [Models](#models)).

Inside the container `docker-entrypoint.sh` starts uvicorn in the
background, waits for its health check and runs the API in the foreground.

### Verify

```bash
curl http://localhost:5000/api/v1/health   # NCD: {"status":"ok",...}
curl http://localhost:5001/health          # API: {"status":"ok",...}
```

Open http://localhost:5001/ for the web dashboard.

### Full analysis cycle

```bash
# Fetch RSS/NVD articles -> run through NCD -> persist concepts
curl -X POST "http://localhost:5001/api/v1/analyze/fetch-and-analyze?source=rss"

# Concepts
curl http://localhost:5001/api/v1/concepts?limit=50

# Markdown security report for the concepts
curl -X POST http://localhost:5001/api/v1/analyze/summarize \
     -H "Content-Type: application/json" \
     -d '{"concepts":[{"label":"Ransomware hits hospital","strength":0.9,"documentCount":3,"sentences":["Ransomware attack hits hospital network and exposes patient records.","The hospital said the ransomware attack disrupted care for several days."]}]}'
```

### Stop

```bash
docker compose down          # compose: stop, keep volumes
docker compose down -v       # compose: stop + wipe the DB (/data/threats.db)
docker stop cycepta && docker rm cycepta   # plain docker run
```

## Running without Docker (native)

The Python env is managed with `uv` (https://docs.astral.sh/uv). Models are
downloaded separately — see the next section.

### 0. Environment (uv)

```bash
# from the repository root; run.sh uses this .venv
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r ncdbody/requirements.txt

# LLM layer runs on HuggingFace Transformers (torch from requirements.txt).
# Optional alternative on Apple Silicon only: uv pip install mlx mlx-lm
```

Alternatively, `bash setup.sh` creates the same repo-root `.venv` (it needs
Python 3.10–3.12 on PATH) and restores the .NET packages.

### 1. Both services, one script

```bash
cp env.example .env      # ports, engine knobs, LLM keys - optional
bash run.sh              # starts NCD (:5000) and API (:5001); dashboard at http://localhost:5001/
```

The script sources `.env`, waits for the NCD health check and keeps the API
in the foreground; Ctrl+C stops both.

### 2. Manually (if you need the pieces separately)

```bash
# from the repository root
source .venv/bin/activate
cd ncdbody

# important: single numba thread (otherwise UMAP segfaults on arm64)
NUMBA_NUM_THREADS=1 NCD_DEVICE=cpu \
  python -m uvicorn app.main:app --host 127.0.0.1 --port 5000
```

```bash
cd ThreatDetector/src/ThreatDetector.Api
NcdService__Url=http://localhost:5000 \
  dotnet run --project . --urls http://127.0.0.1:5001
```

To serve the local network, switch `127.0.0.1` to `0.0.0.0` only together
with a reverse proxy / firewall: the dashboard has no built-in
authentication.

## Models

Two model sets are used. The embedder is required and downloads
automatically. The Granite 4.0 1B LLM is optional and is a separate
download; without it reports use the deterministic fallback.

The `hf` commands below come from the repository-root virtualenv. Run
`source .venv/bin/activate` from the repository root first, or call
`.venv/bin/hf` directly.

| Model | Role | Source | Location | Size |
|-------|------|--------|----------|------|
| `sentence-transformers/all-mpnet-base-v2` | text embeddings | HuggingFace (public) | `~/.ncd/models` - automatic | ~420 MB |
| `ibm-granite/granite-4.0-1b` | LLM: concise report item summaries | HuggingFace (gated, IBM license) | `ncdbody/models/granite-4.0-1b` | ~3.3 GB |

### 1. Embedder (automatic)

On first start NCD pulls the model from HuggingFace into the
`~/.ncd/models` cache (`NCD_MODEL_CACHE`). You can pre-fetch it:

```bash
cd ncdbody
../.venv/bin/python -c "
from app.config import NcdConfig
from sentence_transformers import SentenceTransformer
SentenceTransformer(NcdConfig.EMBEDDING_MODEL, cache_folder=NcdConfig.MODEL_CACHE_DIR)
print('OK ->', NcdConfig.MODEL_CACHE_DIR)
"
```

The native install also brings torch (~2 GB installed) through
`sentence-transformers` — expected, just wait for it.

### 2. Granite 4.0 1B LLM (HF Transformers)

`ibm-granite/granite-4.0-1b` is **gated**: first accept the IBM license on
the model page, then log in with a HuggingFace token:

```bash
cd ncdbody

# HF token (https://huggingface.co/settings/tokens)
hf auth login

# the model itself (~3.3 GB); generation loads via transformers (default backend)
hf download ibm-granite/granite-4.0-1b \
  --local-dir models/granite-4.0-1b
```

Expected files in `ncdbody/models/granite-4.0-1b/`:
`config.json`, `model.safetensors` (~3.3 GB), `tokenizer.json`,
`generation_config.json`.

The default folder matches `NCD_LLM_MODEL`
(`ncdbody/models/granite-4.0-1b`) and the default backend is
`NCD_LLM_BACKEND=transformers`. If you put the weights somewhere else, pass
the path explicitly:

```bash
export NCD_LLM_MODEL=/full/path/to/granite-4.0-1b
```

### 3. Adding a different local model

Any Hugging Face causal LM that fits the memory budget can be used instead of
Granite. Download the complete repository (weights **and** tokenizer) into a
folder, then register that folder in `ncdbody/llm_providers.yaml`.

```bash
cd ncdbody
hf download <org>/<model> --local-dir models/<model>
```

A model folder must contain:

- `config.json` with the architecture;
- one or more `*.safetensors` files (sharded models additionally need
  `model.safetensors.index.json`);
- tokenizer files (see below);
- optionally `generation_config.json`.

NCD treats a local entry as available only when it finds at least one
`*.safetensors` file. A folder with only `pytorch_model.bin` is reported as
"weights not found"; download the safetensors variant or convert the weights.

Register the folder under `local`:

```yaml
local:
  - name: Qwen2.5 1.5B Instruct
    path: models/qwen2.5-1.5b-instruct   # relative to ncdbody/, or absolute
    backend: transformers                # transformers | mlx | auto
    size_hint: "~3.1 GB"                 # used when weights are absent
```

`backend: transformers` works on CPU and CUDA. Use `mlx` on Apple Silicon only
when `mlx` and `mlx-lm` are installed. `auto` prefers CUDA or MLX when
available; on a plain CPU host it can resolve to `none`, so set the backend
explicitly there.

Before generating, confirm that the entry is registered and the weights are
visible: open Generate Summaries, or query the NCD endpoint directly:

```bash
curl -s http://localhost:5000/api/v1/llm/providers
```

The entry must show `"available": true` and a non-zero `size_bytes`. A folder
with no `*.safetensors` stays disabled in the chooser and the report uses the
deterministic fallback.

Instruction-following quality matters for this summary prompt. A very small
model can load correctly and still ignore the numbered-output format (for
example, it may continue the input list instead of summarizing it); Cycepta
then discards the output and falls back deterministically. Use an
instruct/chat model with enough capacity and verify the first report. This
flow was tested with `Qwen/Qwen2.5-1.5B-Instruct`; a 0.5B variant loaded but
did not follow the format reliably.

The new entry appears in Generate Summaries after the YAML is re-read; native
NCD reloads the registry when the file changes, so no restart is needed.
Re-open the chooser after editing it. In Docker the YAML is copied into the
image at build time, so rebuild the image (or bind-mount the YAML) and mount
the model folder as described below. Only one local model stays loaded at a
time; switching entries unloads the previous one.

#### Tokenizers are not interchangeable

A tokenizer must match the model's vocabulary and architecture. Keep the
original file names from the model repository; do not copy a tokenizer from a
different model even when the architecture looks similar.

| Tokenizer family | Typical files | Common models |
|---|---|---|
| HF fast tokenizer (BPE) | `tokenizer.json`, `tokenizer_config.json` | Granite, Llama 3, Qwen, Mistral |
| SentencePiece | `tokenizer.model`, `spiece.model` or `sentencepiece.bpe.model` | LLaMA 1/2, T5, XLM-R |
| WordPiece | `vocab.txt` | BERT-family encoders |
| GPT-2 BPE | `vocab.json` + `merges.txt` | GPT-2-style models |

`tokenizer_config.json` carries the tokenizer class, special tokens and the
chat template; `special_tokens_map.json` maps `bos`/`eos`/`pad`/`unk`.
Cycepta calls `apply_chat_template()`, so use an instruct/chat model whose
tokenizer includes a chat template. A base model without one will fail or
produce poorly formatted prompts.

Wrong or missing tokenizer files usually show up as a load error, a vocabulary
size mismatch, repeated tokens or gibberish summaries.

### 4. Verify the LLM

Start NCD natively and hit `/summarize`:

```bash
curl -s -X POST http://localhost:5000/api/v1/summarize -H "Content-Type: application/json" \
  -d '{"concepts":[{"label":"Ransomware hits hospital","strength":0.9,"documentCount":3,"sentences":["Ransomware attack hits hospital network and exposes patient records.","The hospital said the ransomware attack disrupted care for several days."]}]}'
```

Expected response: `"fallback": false` with `llm_items` greater than zero.
If you get `"fallback": true` the model did not load: wrong path, missing
transformers/torch, or the license/token was not accepted.

### 5. Docker: include the LLM in the container

The image is built **without** the weights (they are in `.gitignore` and
`.dockerignore`). To enable the LLM with compose, mount the model folder and
set the path; the default `transformers` backend and CPU torch are already in
the image:

```yaml
services:
  cycepta:
    volumes:
      - ./ncdbody/models:/app/ncdbody/models:ro
    environment:
      - NCD_LLM_MODEL=/app/ncdbody/models/granite-4.0-1b
```

The same mount works for every entry in `llm_providers.yaml`: each `path` must
resolve inside the container. Rebuild the image after editing the YAML, or
bind-mount `ncdbody/llm_providers.yaml` into `/app/ncdbody/llm_providers.yaml`.

### 6. What you lose without the LLM

`/summarize` returns `"fallback": true` and the report still renders with
deterministic item summaries. IOC extraction, severity heuristics and MITRE
mapping are always deterministic and do not depend on the model.

### 7. API providers instead of local weights

The report chooser also lists OpenAI, Groq, OpenRouter and Anthropic. Set the
matching key in the environment (or paste it into the chooser; it is not
stored), for example:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Anthropic is wired to the Messages API with `format: anthropic` in
`ncdbody/llm_providers.yaml`; the other entries use the OpenAI-compatible
`/chat/completions` shape. Edit the `model` field there to pick a different
Claude or OpenAI model. This path avoids loading the ~3.3 GB Granite weights
into Docker, which is useful on 8 GB machines.

## NVIDIA (CUDA)

The same models run on NVIDIA GPUs. Generation goes through Hugging Face
Transformers with CUDA torch; the default `transformers` backend works on
CPU, Apple MPS and CUDA without changes.

**Backend selection:** `transformers` is the default. `mlx` is an explicit
Apple Silicon opt-in; `none` disables generation. `NCD_LLM_DEVICE`
(`auto` / `mps` / `cuda` / `cpu`) chooses the transformers device.

### 1. Setup (NVIDIA)

```bash
# from the repository root; run.sh uses this .venv
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r ncdbody/requirements.txt

# torch with CUDA (the Linux pip wheel already ships CUDA; pinned explicitly here)
uv pip install --python .venv/bin/python torch --index-url https://download.pytorch.org/whl/cu128
```

### 2. Model

The same `ibm-granite/granite-4.0-1b` weights are used on
NVIDIA — the section above is all you need here.

### 3. Run

```bash
export NCD_LLM_MODEL=/full/path/to/granite-4.0-1b     # or the default ncdbody/models/granite-4.0-1b
export NCD_LLM_BACKEND=transformers
export NCD_LLM_DEVICE=cuda                               # cuda:0 / auto are optional
# NCD_LLM_DTYPE=auto -> bfloat16 on Ampere+, float16 on older GPUs (overridable)
```

Verification is the same as for Apple Silicon (`/summarize`, expecting
`"fallback": false`). The response's `"model"` will read
`granite-4.0-1b (HF Transformers)`.

### 4. Docker with a GPU

Requires the NVIDIA runtime (Ubuntu:
`sudo apt install nvidia-container-toolkit && sudo systemctl restart docker`).

```yaml
services:
  cycepta:
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
    volumes:
      - ./ncdbody/models:/app/ncdbody/models:ro
    environment:
      - NCD_LLM_MODEL=/app/ncdbody/models/granite-4.0-1b
      - NCD_LLM_BACKEND=transformers
      - NCD_LLM_DEVICE=cuda
```

Note: the embedder cache (`~/.ncd/models`) is separate from the LLM; in the
image it simply downloads on first start (`NCD_MODEL_CACHE` is
overridable).

## Useful NCD env variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NCD_HEATMAP_BINS` | `400` | Heatmap resolution |
| `NCD_CLUSTER_MODE` | `blob` | `blob` (hard) or `gmm` (soft clustering) |
| `NCD_USE_DIFF` | `1` | Diff heatmap instead of absolute (paper-faithful) |
| `NCD_NOVELTY_THRESHOLD` | `0.5` | k-NN novelty threshold |
| `NCD_UMAP_REFIT_INTERVAL` | `0` | `0` = UMAP is fit once, coordinates stay stable |
| `NCD_UMAP_RANDOM_STATE` | `42` | UMAP seed for reproducibility |
| `NCD_UMAP_N_JOBS` | `1` | Single UMAP job (bit-reproducible) |
| `NUMBA_NUM_THREADS` | - | **1** - required on Apple Silicon |
| `NCD_EMBEDDING_MODEL` | `sentence-transformers/all-mpnet-base-v2` | Text embedder (HF) |
| `NCD_MODEL_CACHE` | `~/.ncd/models` | Embedder / weights cache |
| `NCD_LLM_MODEL` | `models/granite-4.0-1b` | Path to the Granite 4.0 model, relative to `ncdbody/` (empty = heuristics only) |
| `NCD_LLM_BACKEND` | `transformers` | `transformers` (default) · `mlx` (Apple, opt-in) · `none` |
| `NCD_LLM_CTX` | `4096` | Prompt window for memory-safe item-summary batches (tokens) |
| `NCD_LLM_MAX_TOKENS` | `1024` | Output ceiling for one item-summary batch |
| `NCD_LLM_TEMPERATURE` | `0.3` | Sampling temperature for item summaries; `0` = greedy, reproducible |
| `NCD_LLM_REPETITION_PENALTY` | `1.05` | Light loop guard; `1.0` disables it |
| `NCD_LLM_QUANT` | `none` | Weight quantization for the transformers backend: `none` (default) · `int4` (4-bit via torchao — ~3x less LLM memory, faster on MPS/CUDA, needs `pip install torchao`) |
| `NCD_LLM_DEVICE` | `auto` | For transformers: `auto` / `mps` / `cuda` / `cuda:0` / `cpu` |
| `NCD_LLM_DTYPE` | `auto` | For transformers: `auto` / `bfloat16` / `float16` / `float32` |
| `OPENAI_API_KEY` / `GROQ_API_KEY` / `OPENROUTER_API_KEY` / `ANTHROPIC_API_KEY` | — | Optional keys for the report provider chooser; Anthropic uses the Messages API |
| `Ingest__AnalysisChunkSize` | `250` | Documents per NCD batch during Fetch & Analyze; each finished batch updates the heatmap |
| `NcdService__TimeoutSeconds` | `300` | Per-batch NCD timeout; the whole interactive run can take longer |
| `Ingest__FeedTimeoutSeconds` | `15` | Per-feed timeout; a slow host releases its worker instead of blocking the queue |
| `Ingest__FeedBudgetSeconds` | `120` | Wall-clock budget for the whole RSS fetch; feeds that finish late are retried next run |
| `Ingest__FeedConcurrency` | `12` | Maximum feed hosts fetched in parallel |

## FAQ

**Why does Fetch & Analyze return the same periods?**
The feeds (Krebs, BleepingComputer) update rarely. Re-running shortly after a
previous run parses the same articles and yields the same result. New data
arrives after new publications or via `?source=nvd`.

**Why did a run show only one or two sources?**
Older builds shared a single 25-second cancellation token across every feed.
Slow hosts occupied the worker pool, the queue was cancelled, and only the
fastest hosts (GitLab, arXiv) survived. Each feed now has its own 15-second
timeout inside a 120-second budget, and the fetch/aggregation order rotates
between runs. Check the latest per-feed document counts with:

```bash
curl -s http://localhost:5001/api/v1/sources | python3 -m json.tool
```

Bot-walled feeds (for example The Record, SecurityWeek, Talos, CrowdStrike)
are excluded from the default list because they return 403 from many
networks; the curated list keeps a broad mix of government, vendor research,
news, AppSec/DFIR, independent and academic sources that do respond.

**Why does Fetch & Analyze take several minutes, and why does the map update before it finishes?**
The run is split into NCD batches (250 documents by default). Each batch is
embedded, clustered and persisted, then pushed to the dashboard over SignalR,
so concepts appear on the heatmap and live feed as they are found. The final
HTTP response arrives only after the last batch. On CPU a full run can take a
few minutes. Lower `Ingest__AnalysisChunkSize` to see the first
concepts sooner, or raise it for fewer, larger batches.

**The LLM does not load in Docker.**
The image is built without the Granite weights (`NCD_LLM_MODEL=""`).
Summarization then returns deterministic item summaries. IOCs, severity and
MITRE are always deterministic. The model is available only as a separate
download.
