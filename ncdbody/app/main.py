"""FastAPI application for NCD Microservice."""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import NcdConfig
from .llm import summarize_space
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    embeddings = engine.embed_texts(req.texts)
    return EmbeddingResponse(
        embeddings=embeddings.tolist(),
        model=engine.config.EMBEDDING_MODEL,
        dimensions=embeddings.shape[1],
    )


@app.post("/api/v1/detect")
async def detect_concepts(batch: DocumentBatch):
    engine = get_engine()
    try:
        result = engine.process_batch(batch)
        return JSONResponse(content=_to_pascal_case(result.model_dump()))
    except Exception as e:
        logger.exception("Detection failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/concepts")
async def list_concepts():
    engine = get_engine()
    return {"concepts": engine.get_all_concepts()}


@app.post("/api/v1/summarize")
def summarize_detected(payload: dict):
    concepts = payload.get("concepts") or []
    try:
        import time as _t
        t0 = _t.time()
        result = summarize_space(concepts)
        result["processing_time_ms"] = round((_t.time() - t0) * 1000, 1)
        return JSONResponse(content=result)
    except Exception as e:
        logger.exception("LLM summarization failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stats")
async def stats():
    engine = get_engine()
    return engine.get_stats()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
