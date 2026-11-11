"""FastAPI application for NCD Microservice."""
from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .config import NcdConfig
from .llm import providers_snapshot, summarize_space
from .models import (
    DetectionResult,
    DocumentBatch,
    EmbeddingRequest,
    EmbeddingResponse,
    HealthResponse,
)
from .ncd_engine import get_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

_start_time = time.time()

# The engine keeps mutable per-stream state (reference heatmaps, concept graph,
# k-NN pool). process_batch/embed are CPU-bound, so run them in the threadpool
# to keep /health responsive, but serialize access to the engine.
_engine_lock = asyncio.Lock()


def _to_pascal_case(obj):
    """Recursively convert snake_case keys to PascalCase."""
    if isinstance(obj, dict):
        return {"".join(w.title() for w in k.split("_")): _to_pascal_case(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_pascal_case(i) for i in obj]
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return obj


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model on startup."""
    engine = get_engine()
    engine._ensure_model_loaded()
    logger.info("NCD service ready")
    yield
    logger.info("NCD service shutting down")


app = FastAPI(
    title="NCD Microservice",
    description="New Concept Detection engine for real-time threat analysis",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS is only needed for local browser tools. The dashboard talks to the
# .NET API, which proxies to NCD server-to-server, so the safe default is the
# local API origin rather than "*". Override with a comma-separated list.
_cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "NCD_CORS_ORIGINS",
        "http://localhost:5001,http://127.0.0.1:5001",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.get("/api/v1/health", response_model=HealthResponse)
async def health():
    engine = get_engine()
    stats = engine.get_stats()
    return HealthResponse(
        status="ok",
        model_loaded=stats["model_loaded"],
        model_name=stats["model_name"],
        device=stats["device"],
        periods_processed=stats["periods_processed"],
        uptime_seconds=stats["uptime_seconds"],
    )


@app.post("/api/v1/embed", response_model=EmbeddingResponse)
async def embed_texts(req: EmbeddingRequest):
    engine = get_engine()
    async with _engine_lock:
        embeddings = await run_in_threadpool(engine.embed_texts, req.texts)
    return EmbeddingResponse(
        embeddings=embeddings.tolist(),
        model=engine.config.EMBEDDING_MODEL,
        dimensions=embeddings.shape[1],
    )


@app.post("/api/v1/detect")
async def detect_concepts(batch: DocumentBatch):
    engine = get_engine()
    try:
        async with _engine_lock:
            result = await run_in_threadpool(engine.process_batch, batch)
        return JSONResponse(content=_to_pascal_case(result.model_dump()))
    except Exception:
        logger.exception("Detection failed")
        raise HTTPException(status_code=500, detail="detection failed")


@app.get("/api/v1/concepts")
async def list_concepts():
    engine = get_engine()
    async with _engine_lock:
        concepts = list(engine.get_all_concepts())
    return {"concepts": concepts}


@app.post("/api/v1/summarize")
def summarize_detected(payload: dict):
    concepts = payload.get("concepts") or []
    llm = payload.get("llm")
    if llm is not None and not isinstance(llm, dict):
        logger.warning("Ignoring malformed 'llm' request (expected an object)")
        llm = None
    try:
        import time as _t
        t0 = _t.time()
        result = summarize_space(concepts, llm=llm)
        result["processing_time_ms"] = round((_t.time() - t0) * 1000, 1)
        return JSONResponse(content=result)
    except Exception:
        logger.exception("LLM summarization failed")
        raise HTTPException(status_code=500, detail="summarization failed")


@app.get("/api/v1/llm/providers")
def list_llm_providers():
    return providers_snapshot()


@app.get("/api/v1/stats")
async def stats():
    engine = get_engine()
    # get_stats walks counters the replay thread mutates.
    async with _engine_lock:
        stats_snapshot = engine.get_stats()
    return stats_snapshot


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("NCD_BIND_HOST", "127.0.0.1"), port=8080)
