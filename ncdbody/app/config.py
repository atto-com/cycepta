"""Configuration for NCD Engine."""
import os
from pathlib import Path


class NcdConfig:
    EMBEDDING_MODEL: str = os.getenv("NCD_EMBEDDING_MODEL", "sentence-transformers/all-mpnet-base-v2")
    UMAP_N_COMPONENTS: int = int(os.getenv("NCD_UMAP_N_COMPONENTS", "2"))
    HEATMAP_BINS: int = int(os.getenv("NCD_HEATMAP_BINS", "400"))
    # Fixed-range margin: the first-period coordinate range is padded by this
    # fraction of its span and reused forever, so concepts keep a stable bin
    # position across periods while outliers are clipped instead of shifted.
    HEATMAP_RANGE_MARGIN: float = float(os.getenv("NCD_HEATMAP_RANGE_MARGIN", "1.0"))
    BLOB_RHO: float = float(os.getenv("NCD_BLOB_RHO", "0.05"))
    BLOB_MAX_DIST: int = int(os.getenv("NCD_BLOB_MAX_DIST", "5"))
    SMOOTH_SIGMA: float = float(os.getenv("NCD_SMOOTH_SIGMA", "1.0"))
    SENTENCE_LEVEL: bool = os.getenv("NCD_SENTENCE_LEVEL", "1").lower() in ("1", "true", "yes")
    USE_DIFF: bool = os.getenv("NCD_USE_DIFF", "0").lower() in ("1", "true", "yes")
    WINDOW_SIZE: int = int(os.getenv("NCD_WINDOW_SIZE", "10"))
    BATCH_SIZE: int = int(os.getenv("NCD_BATCH_SIZE", "32"))
    MAX_SENTENCES_PER_CONCEPT: int = int(os.getenv("NCD_MAX_SENTS", "50"))
    MODEL_CACHE_DIR: str = os.getenv("NCD_MODEL_CACHE", str(Path.home() / ".ncd" / "models"))
    DEVICE: str = os.getenv("NCD_DEVICE", "cpu")
    # LLM-генерация: auto | mlx (Apple Silicon) | transformers (NVIDIA CUDA / CPU) | none
    LLM_BACKEND: str = os.getenv("NCD_LLM_BACKEND", "auto").strip().lower()
    # Для transformers: auto | cuda | cuda:0 | cpu
    LLM_DEVICE: str = os.getenv("NCD_LLM_DEVICE", "auto").strip()
    # Для transformers: auto | float16 | bfloat16 | float32
    LLM_DTYPE: str = os.getenv("NCD_LLM_DTYPE", "auto").strip().lower()

    # P0: k-NN novelty detection in raw embedding space
    KNN_K: int = int(os.getenv("NCD_KNN_K", "10"))
    # P2/A: two-tier emerging detection - novelty < threshold AND growth >= growth_threshold
    NOVELTY_THRESHOLD: float = float(os.getenv("NCD_NOVELTY_THRESHOLD", "0.5"))
    # P2/D: embedding-scale-agnostic novelty. When enabled, "novel" means
    # novelty < mean(running pool) - ADAPTIVE_K * std(running pool), i.e. a
    # genuine dip below the ambient familiarity floor. Falls back to the
    # absolute NOVELTY_THRESHOLD until the pool is populated.
    NOVELTY_ADAPTIVE: bool = os.getenv("NCD_NOVELTY_ADAPTIVE", "0").lower() in ("1", "true", "yes")
    ADAPTIVE_K: float = float(os.getenv("NCD_ADAPTIVE_K", "1.8"))
    GROWTH_WINDOW: int = int(os.getenv("NCD_GROWTH_WINDOW", "3"))
    GROWTH_THRESHOLD: float = float(os.getenv("NCD_GROWTH_THRESHOLD", "0.3"))

    # P2/A: stable-topic suppression - blacklist top-K recurring concepts from warmup periods
    STABLE_WARMUP_PERIODS: int = int(os.getenv("NCD_STABLE_WARMUP_PERIODS", "3"))
    STABLE_TOP_K: int = int(os.getenv("NCD_STABLE_TOP_K", "8"))

    # D: optional input prefix for e5/Retriever-style models (e.g. "passage: ", "query: ")
    EMBEDDING_PREFIX: str = os.getenv("NCD_EMBEDDING_PREFIX", "")

    # P0: UMAP periodic refit to prevent drift (0 = refit only on first call)
    UMAP_REFIT_INTERVAL: int = int(os.getenv("NCD_UMAP_REFIT_INTERVAL", "5"))

    # P0: Cross-period concept tracking via Graph
    GRAPH_MAX_DIST: int = int(os.getenv("NCD_GRAPH_MAX_DIST", "5"))
    GRAPH_MAX_PERIOD_GAP: int = int(os.getenv("NCD_GRAPH_MAX_PERIOD_GAP", "2"))

    # P2: GMM clusters shift more per period than blob centroids; use a wider
    # matching distance so persistent topics still link across periods.
    GMM_GRAPH_MAX_DIST: int = int(os.getenv("NCD_GMM_GRAPH_MAX_DIST", "10"))

    # P2: soft clustering ("blob" = hard blob_log, "gmm" = soft Gaussian mixture)
    CLUSTER_MODE: str = os.getenv("NCD_CLUSTER_MODE", "blob")
    GMM_MAX_COMPONENTS: int = int(os.getenv("NCD_GMM_MAX_COMPONENTS", "20"))
    GMM_MIN_SAMPLES: int = int(os.getenv("NCD_GMM_MIN_SAMPLES", "3"))
    GMM_PROB_THRESHOLD: float = float(os.getenv("NCD_GMM_PROB_THRESHOLD", "0.9"))

    # P2: concept drift detection (JS divergence between neighboring periods)
    DRIFT_BINS: int = int(os.getenv("NCD_DRIFT_BINS", "64"))
    DRIFT_WINDOW: int = int(os.getenv("NCD_DRIFT_WINDOW", "5"))
    DRIFT_THRESHOLD: float = float(os.getenv("NCD_DRIFT_THRESHOLD", "0.35"))
