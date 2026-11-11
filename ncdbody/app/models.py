"""Pydantic models for NCD API."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


def _snake_to_camel(name: str) -> str:
    components = name.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


class Document(BaseModel):
    model_config = ConfigDict(populate_by_name=True, alias_generator=_snake_to_camel)

    id: str = Field(..., description="Unique document identifier")
    text: str = Field(..., min_length=1, max_length=10000)
    source: str = Field(default="unknown", description="Source identifier (e.g., rss, cve, twitter)")
    timestamp: Optional[datetime] = None
    metadata: dict = Field(default_factory=dict)


class DocumentBatch(BaseModel):
    model_config = ConfigDict(populate_by_name=True, alias_generator=_snake_to_camel)

    documents: list[Document] = Field(..., min_length=1, max_length=10000)
    period_id: Optional[str] = Field(None, description="Time period identifier for incremental mode")


class DetectedConcept(BaseModel):
    model_config = ConfigDict(populate_by_name=True, alias_generator=_snake_to_camel)

    concept_id: str
    label: str = ""
    summary: str = ""
    sentences: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    document_count: int = 0
    document_ids: list[str] = Field(default_factory=list, description="Ids of documents whose sentences are members of this concept")
    strength: float = Field(0.0, ge=0.0, description="Detection strength/confidence")
    coordinates: list[float] = Field(default_factory=list, description="Position in embedding space")
    source: str = ""
    # P2/A: two-tier emerging flag (novelty < t1 AND growth >= t2 AND not stable-blacklisted)
    emerging: bool = False
    # P2/A: number of periods this graph-length / appearances
    appearances: int = 0


class DetectionResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True, alias_generator=_snake_to_camel)

    period_id: str
    concepts_found: int
    concepts: list[DetectedConcept] = Field(default_factory=list)
    processing_time_ms: float = 0.0
    total_documents: int = 0
    heatmap_diff_summary: dict = Field(default_factory=dict)


class EmbeddingRequest(BaseModel):
    texts: list[str] = Field(..., min_length=1, max_length=10000)


class EmbeddingResponse(BaseModel):
    embeddings: list[list[float]]
    model: str
    dimensions: int


class HealthResponse(BaseModel):
    status: str = "ok"
    model_loaded: bool = False
    model_name: str = ""
    device: str = ""
    periods_processed: int = 0
    uptime_seconds: float = 0.0


class ConceptUpdate(BaseModel):
    event_type: str  # "new_concept", "concept_evolved", "concept_merged"
    concept: DetectedConcept
    timestamp: datetime = Field(default_factory=datetime.utcnow)
