# Testing

## Fast checks (seconds, no network)

```bash
bash scripts/test.sh
```

This runs:

| Layer | Command | What it covers |
|-------|---------|----------------|
| .NET | `dotnet test ThreatDetector/ThreatDetector.sln` | RSS stable ids, SSRF guard, batch-window timer, concurrent SQLite writes, concept-event period ids |
| Python | `python3 -m unittest discover -s tests/python -v` | production NCD defaults and eval/production parity pins |
| Dashboard | `node --test tests/js/*.test.mjs` | `safeUrl()` rejects `javascript:`/`data:` URLs |
| Syntax | `py_compile`, `bash -n` | import/parse errors in entrypoints |

Requirements: .NET 10 SDK, Python 3.11+, Node 22+ (Node is only needed for the
dashboard test and is skipped when absent).

## Synthetic replay (about 10 seconds)

The keyword-space replay does not download models or touch the network:

```bash
python3 benchmark/score.py --split dev
```

Expected trunk score: `50.1667` (seed 11, blob mode). This is a regression
check for detection logic, not for UMAP/embeddings.

## Wall-clock re-baseline (expensive, real NVD stream)

```bash
NUMBA_NUM_THREADS=1 python3 benchmark/wallclock.py --split dev \
  --metrics-json /tmp/wallclock_dev.json
```

Current baseline (Python 3.13 / torch 2.9.1 / sentence-transformers 6.0.1,
2026-11-01): **dev 0.6955** (guardrail 0.8000, mean lead 0.8693) and
**test 0.6403** (guardrail 0.7273, mean lead 0.8804; 92 adopted / 88 flagged /
25 missed; 199/199 periods, 0 unit-count mismatches, 634 entities,
~46 min replay). A re-run must reproduce these within noise; the smoke
3-period replay is byte-identical across runs (deterministic UMAP +
content-addressed concept ids).

Use the interpreter that has `numpy`/`sentence-transformers` installed and
was used to build the embedding cache, not a bare system Python. The first
run embeds ~10^5 CVE texts and takes tens of minutes; later runs reuse
`stream/data/emb_store/`. The harness pins `USE_DIFF=True`,
`UMAP_REFIT_INTERVAL=0`, `UMAP_RANDOM_STATE=42`, `UMAP_N_JOBS=1` and disables
the judge, so a run must match the service representation. Re-run both dev and
test before publishing new scores; old numbers were produced with
`USE_DIFF=0` and are not comparable.

Scores are also tied to the ML stack that built the cache. The recorded
baseline used Python 3.13 / torch 2.9.1 / sentence-transformers 6.0.1, while
`ncdbody/requirements.txt` and the image pin the known-good older set. Before
quoting a score for a release, run the harness inside the built image (or
rebuild the cache from the pinned requirements) and note
`python -c "import torch, sentence_transformers; print(torch.__version__, sentence_transformers.__version__)"`.

## What is deliberately not automated

- Live RSS/NVD retrieval (external services, rate limits).
- Docker image build (slow; run `docker compose build` before a release).
- Full endpoint/auth tests (the dashboard is local-only by default and has no
  user authentication yet; front it with a reverse proxy before exposing it).

## Release gate

Run these before exposing the dashboard beyond localhost:

1. `bash scripts/test.sh` — fast checks must be green.
2. `docker compose build && docker compose up -d`, then wait for the
   container to report `healthy` (`docker compose ps`). This is the only
   check that exercises the non-root user, the model-cache volume and both
   processes.
3. `curl -fsS http://127.0.0.1:5001/health` and open the dashboard; run one
   Fetch & Analyze and one Generate Summaries.
4. Re-run the wallclock harness on the image's Python stack (see the note
   above) and record the score with the image tag.
5. Put a reverse proxy with authentication and TLS in front; keep the
   published ports on `127.0.0.1`. The dashboard and API have no built-in
   user authentication.
6. Back up the `/data` volume (SQLite + WAL) before upgrades.
