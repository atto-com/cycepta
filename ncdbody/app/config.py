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
    # Production default matches the paper-faithful difference heatmap. The
    # eval harness pins this too, so offline and live detection see the same
    # representation.
    USE_DIFF: bool = os.getenv("NCD_USE_DIFF", "1").lower() in ("1", "true", "yes")
    WINDOW_SIZE: int = int(os.getenv("NCD_WINDOW_SIZE", "10"))
    BATCH_SIZE: int = int(os.getenv("NCD_BATCH_SIZE", "32"))
    MAX_SENTENCES_PER_CONCEPT: int = int(os.getenv("NCD_MAX_SENTS", "50"))
    MODEL_CACHE_DIR: str = os.getenv("NCD_MODEL_CACHE", str(Path.home() / ".ncd" / "models"))
    DEVICE: str = os.getenv("NCD_DEVICE", "cpu")
    # LLM generation backend: transformers (default) | auto | mlx (Apple opt-in) | none
    LLM_BACKEND: str = os.getenv("NCD_LLM_BACKEND", "transformers").strip().lower()
    # For transformers: auto | cuda | cuda:0 | cpu
    LLM_DEVICE: str = os.getenv("NCD_LLM_DEVICE", "auto").strip()
    # For transformers: auto | float16 | bfloat16 | float32
    LLM_DTYPE: str = os.getenv("NCD_LLM_DTYPE", "auto").strip().lower()

    # Judge is the second, coarser garbage stage: the local LLM classifies whole
    # documents before unit construction, so dropped docs and their indices
    # vanish together; the per-sentence regex pre-filter at unit construction
    # stays. NCD_JUDGE=0 disables the judge entirely.
    JUDGE_ENABLED: bool = os.getenv("NCD_JUDGE", "1").lower() in ("1", "true", "yes")
    JUDGE_BATCH: int = int(os.getenv("NCD_JUDGE_BATCH", "40"))
    JUDGE_THRESHOLD: float = float(os.getenv("NCD_JUDGE_THRESHOLD", "0.5"))

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

    # UMAP refit cadence in periods (0 = fit once and keep stable coordinates).
    # Production batches arrive every few minutes, so the old interval of 5
    # meant a full refit of all accumulated embeddings every ~25 minutes.
    # Fit-once is both affordable and reproducible; the eval harness pins 0 too.
    UMAP_REFIT_INTERVAL: int = int(os.getenv("NCD_UMAP_REFIT_INTERVAL", "0"))
    # Deterministic UMAP layout. Without a fixed seed, two replays of the same
    # stream produce different entity sets and non-comparable scores.
    UMAP_RANDOM_STATE: int = int(os.getenv("NCD_UMAP_RANDOM_STATE", "42"))
    # UMAP's parallel SGD is not bit-reproducible; one job is the safe default.
    UMAP_N_JOBS: int = int(os.getenv("NCD_UMAP_N_JOBS", "1"))

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

    # N1.2: second-pass residual novelty clustering ("burst tier").
    # After the primary concept emission, units that are novel (novelty < gate)
    # but were NOT absorbed into any emitted concept are re-clustered with
    # connected components in the existing 2D embedding space. Components that
    # pass cohesion + min-size + min-source-diversity guards are emitted as
    # "burst" concepts flagged WITHOUT the growth/recurrence (emerging) gate.
    # Set NCD_BURST_TIER=0 to restore the primary-only behaviour exactly.
    BURST_TIER: bool = os.getenv("NCD_BURST_TIER", "1").lower() in ("1", "true", "yes")
    # Clustering radius expressed in heatmap-bin units: the radius in raw
    # coordinate space is derived from the fixed histogram edges, so it scales
    # with the embedding space instead of being an absolute magic number.
    BURST_EPS_BINS: float = float(os.getenv("NCD_BURST_EPS_BINS", "3"))
    # Guards: a burst must be big enough, span several source documents and be
    # internally cohesive in the RAW embedding space (pure scatter/noise has
    # near-zero mean pairwise cosine and never passes).
    BURST_MIN_SIZE: int = int(os.getenv("NCD_BURST_MIN_SIZE", "5"))
    BURST_MIN_SOURCES: int = int(os.getenv("NCD_BURST_MIN_SOURCES", "3"))
    BURST_COHESION: float = float(os.getenv("NCD_BURST_COHESION", "0.5"))
    # Safety valve: skip the residual pass if the novel pool is pathologically
    # large (pathological/real streams with a broken novelty gate).
    BURST_MAX_RESIDUAL: int = int(os.getenv("NCD_BURST_MAX_RESIDUAL", "5000"))

    # N1.3: per-entity online inflow change-point detector ("velocity gate").
    # Adoption is an ACCUMULATION-VELOCITY event (mass floor / KEV inclusion),
    # while text-novelty is anti-correlated with growth (a concept becomes MORE
    # self-similar as it accumulates members). This second, independent flag
    # source tracks each primary entity's weekly member inflow (engine sentence
    # units newly attributed to the entity) against the entity's OWN trailing
    # baseline with a two-sided CUSUM. Flags are the UNION (velocity OR
    # novelty); novelty math, clustering, heatmaps, burst tier, drift and
    # scoring are untouched. All knobs are env-overridable.
    # Master switch: NCD_INFLOW_GATE=0 restores the novelty-only behaviour.
    INFLOW_GATE: bool = os.getenv("NCD_INFLOW_GATE", "1").lower() in ("1", "true", "yes")
    # PRIOR OBSERVED inflows (emission periods) required before the detector
    # is eligible, i.e. the detector is live from the entity's
    # (INFLOW_WARMUP+1)-th emission. Baseline history is OBSERVED inflows only
    # (silent weeks carry no information about a sporadic emitter's baseline;
    # real-stream calibration showed dense-period baselines - warmup 4 dense
    # periods + zero-filled windows - suppress genuine change points on the
    # median entity, which emits only 2-5 times in 40 weeks).
    INFLOW_WARMUP: int = int(os.getenv("NCD_INFLOW_WARMUP", "1"))
    # Trailing baseline window (observed inflows) for mean/std of the series.
    INFLOW_WINDOW: int = int(os.getenv("NCD_INFLOW_WINDOW", "8"))
    # Two-sided CUSUM on the standardized inflow residual
    #   z_t = (x_t - mean(window)) / max(std(window), INFLOW_SIGMA_FLOOR)
    #   s_hi = max(0, s_hi + z_t - k)   upward side - the flag driver
    #   s_lo = min(0, s_lo + z_t + k)   downward side - tracked, never flags
    # fire when s_hi > h AND the residual was positive for INFLOW_CONFIRM
    # consecutive observed updates (sustained confirmation: a single spike,
    # however large, cannot fire).
    INFLOW_CUSUM_K: float = float(os.getenv("NCD_INFLOW_CUSUM_K", "1.5"))
    INFLOW_CUSUM_H: float = float(os.getenv("NCD_INFLOW_CUSUM_H", "7.0"))
    INFLOW_CONFIRM: int = int(os.getenv("NCD_INFLOW_CONFIRM", "2"))
    # Std floor (units/week) so a tiny or flat baseline yields finite z.
    INFLOW_SIGMA_FLOOR: float = float(os.getenv("NCD_INFLOW_SIGMA_FLOOR", "1.0"))
    # Momentum floors: cumulative UNIQUE member units seen so far, and at
    # least two observed inflows > 0, before an entity is eligible
    # (precision guard: 1-2 unit chatter noise never accumulates).
    INFLOW_MIN_CUM_UNITS: int = int(os.getenv("NCD_INFLOW_MIN_CUM_UNITS", "15"))

    # N1.4 (node 1.2): debut fast-path layered on the velocity gate. An
    # entity whose FIRST observed inflow (unique sentence units accrued at
    # its first emission) already reaches INFLOW_DEBUT units is flagged
    # emerging IMMEDIATELY - no CUSUM warmup, no confirmation. Rationale
    # (node 1.1 dev eval, score 0.0 with lead_days == 0 everywhere): the
    # CUSUM ramp detector needs >= INFLOW_WARMUP+1 observed emissions plus
    # INFLOW_CONFIRM sustained updates, but mass adoption (40 members within
    # 8 weeks) of a fast ramp completes EARLIER, and backlog giants born
    # with hundreds of members are adopted at birth (un-leadable). The
    # winnable class is entities born with a moderate first batch whose
    # adoption lands weeks later - their big debut week IS the
    # pre-adoption signal, so the first emission itself is the evidence.
    # The CUSUM path keeps its own warmup untouched; the two flag sources
    # are UNIONed and each latches one-shot per entity.
    # Calibration (see node 1.2 writeup): on the recorded dev replay the
    # first-observed inflow distribution is strongly adoption-skewed -
    # adopted entities median ~28 units vs non-adopted median ~11 (p90
    # ~30, p99 ~43); 24-42 flags entities born with 10-60 member-doc
    # debuts while cutting false-positive debuts ~40% vs 12.
    # NCD_INFLOW_DEBUT=0 disables the fast path (CUSUM-only, node 1.1
    # behaviour exactly).
    INFLOW_DEBUT: int = int(os.getenv("NCD_INFLOW_DEBUT", "24"))

    # P2: concept drift detection (JS divergence between neighboring periods)
    DRIFT_BINS: int = int(os.getenv("NCD_DRIFT_BINS", "64"))
    DRIFT_WINDOW: int = int(os.getenv("NCD_DRIFT_WINDOW", "5"))
    DRIFT_THRESHOLD: float = float(os.getenv("NCD_DRIFT_THRESHOLD", "0.35"))
