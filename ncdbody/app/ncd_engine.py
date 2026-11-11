"""Core NCD Engine - wraps the New Concept Detection pipeline for real-time use.

Implements:
  - k-NN novelty score in raw 768-dim embedding space (block-wise top-k over
    a disk-backed per-period reference store; replaces np.maximum.reduce)
  - Cross-period concept tracking via Graph (ported from reference impl)
  - Periodic UMAP refit to prevent embedding-space drift
  - N1.2 burst tier: second-pass clustering of the residual novelty pool
    (novel units the primary pass did not absorb) into cohesion-guarded
    "burst" concepts that skip the growth/recurrence gate
  - N1.3 velocity gate: per-entity online change-point detector (two-sided
    CUSUM on the standardized weekly member-inflow residual vs the entity's
    own trailing baseline); emerging flags are the UNION (novelty OR
    velocity). NCD_INFLOW_GATE=0 restores novelty-only behaviour.
"""
from __future__ import annotations

# Monkey-patch scipy for UMAP compatibility with scipy >= 1.14
import scipy.linalg
import scipy.sparse.linalg

_original_eigsh = scipy.sparse.linalg.eigsh
def _patched_eigsh(A, k=6, **kwargs):
    if scipy.sparse.issparse(A) and k >= A.shape[0]:
        from scipy.linalg import eigh
        A_dense = A.toarray()
        w, v = eigh(A_dense)
        return w[:k], v[:, :k]
    return _original_eigsh(A, k=k, **kwargs)
scipy.sparse.linalg.eigsh = _patched_eigsh

import atexit
import copy
import hashlib
import logging
import os
import re
import shutil
import tempfile
import time
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Iterator, Optional

import numpy as np
from scipy.ndimage import gaussian_filter
from scipy.spatial import cKDTree
from scipy.special import kl_div
from skimage.feature import blob_log

from .config import NcdConfig
from .input_hygiene import is_boilerplate as _is_boilerplate
from .judge import judge_documents
from .models import (
    ConceptUpdate,
    DetectedConcept,
    DetectionResult,
    Document,
    DocumentBatch,
)

logger = logging.getLogger(__name__)

_SENT_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")


def _split_sentences(text: str) -> list[str]:
    """Split document text into sentence-level units (as in the NCD paper)."""
    parts = [p.strip() for p in _SENT_SPLIT_RE.split(text) if p.strip()]
    return parts or ([text.strip()] if text.strip() else [])


def _stable_concept_id(sents: list[str], period_idx: int) -> str:
    """Content-addressed concept id.

    Random uuids made two replays of the same stream emit different ids (and
    therefore incomparable metrics/config diffs). Seed, period and member
    sentences are deterministic, so this id is reproducible while still
    unique for concepts that start in different periods.
    """
    if not sents:
        return uuid.uuid4().hex[:8]  # no sentences to hash: keep it unique
    material = f"{period_idx}\n" + "\n".join(sorted(set(sents)))
    return hashlib.blake2b(material.encode("utf-8"), digest_size=4).hexdigest()


# ---------------------------------------------------------------------------
# Cross-period Graph (ported from new_concept_detection/main.py)
# ---------------------------------------------------------------------------

def _is_similar(coord1, coord2, max_dist=1):
    return all(abs(c1 - c2) <= max_dist for c1, c2 in zip(coord1, coord2))


def _get_nearby_coords_single(coord, n):
    if n == 0:
        return [coord]
    nearby = [
        (coord[0] + dx, coord[1] + dy)
        for dx in range(-n, n + 1)
        for dy in range(-n, n + 1)
    ]
    return [x for x in nearby if all(0 <= c < 400 for c in x)]


def _get_nearby_coords_multi(coords, n):
    result = set()
    for c in coords:
        result.update(_get_nearby_coords_single(c, n))
    return list(result)


def _preprocess_blobs(blobs, max_dist):
    coords = [tuple(int(v) for v in b[:-1]) for b in blobs]
    coords.sort(key=lambda x: x[0])
    groups = []
    visited = set()
    for i in range(len(coords)):
        if i in visited:
            continue
        group = [coords[i]]
        max_0 = group[-1][0]
        visited.add(i)
        for j in range(i + 1, len(coords)):
            if coords[j][0] - max_0 > max_dist:
                groups.append(group)
                break
            if any(_is_similar(coords[j], c, max_dist) for c in group):
                if j in visited:
                    for g in groups:
                        if coords[j] in g:
                            group = list(set(group + g))
                            max_0 = max(c[0] for c in group)
                            groups.remove(g)
                            break
                else:
                    group.append(coords[j])
                    visited.add(j)
                    max_0 = max(max_0, coords[j][0])
        else:
            groups.append(group)
    return groups


def _get_sentences_for_group(bins_dict, grouped_coord, extend_range=0):
    sents = []
    for c in _get_nearby_coords_multi(grouped_coord, extend_range):
        sents.extend([x[0] for x in bins_dict.get(c, [])])
    return sents


class _ConceptGraph:
    """Tracks a concept across multiple periods (ported from reference impl)."""

    def __init__(self, start_coord, start_index, start_sents):
        self.nodes = [(start_coord, start_index)]
        self.last_update = start_index
        self.start = start_index
        self.length = 1
        self.sents = list(start_sents)
        self.concept_id = _stable_concept_id(start_sents, start_index)
        self.first_novel = False

    def add_coord(self, coord, list_index, sents_to_add=None):
        if (coord, list_index) in self.nodes:
            self.last_update = list_index
            return
        self.nodes.append((coord, list_index))
        self.last_update = list_index
        self.length += 1
        if sents_to_add:
            self.sents.extend(sents_to_add)

    def get_last_coord(self):
        return self.nodes[-1][0]

    def is_eligible(self, coord, list_index, max_gap, coord_dist: int = 1):
        last_coord, _ = self.nodes[-1]
        return (list_index - self.last_update <= max_gap) and _is_similar(last_coord, coord, coord_dist)


def _link_graphs_across_periods(all_blobs, bins_dicts, max_dist, max_gap):
    """Link blobs across periods into concept graphs."""
    graph_lookup = defaultdict(list)
    for list_index, current_blobs in enumerate(all_blobs):
        bins_dict = bins_dicts[list_index]
        grouped = _preprocess_blobs(current_blobs, max_dist)

        for grouped_coord in grouped:
            sents = _get_sentences_for_group(bins_dict, grouped_coord, extend_range=1)
            # Use centroid of the grouped coords as a single node coordinate
            centroid = tuple(
                int(round(sum(c[d] for c in grouped_coord) / len(grouped_coord)))
                for d in range(len(grouped_coord[0]))
            )

            if list_index == 0:
                g = _ConceptGraph(centroid, list_index, sents)
                graph_lookup[centroid].append(g)
            else:
                added = False
                for g in list(graph_lookup.values()):
                    for existing in g:
                        if existing.is_eligible(centroid, list_index, max_gap):
                            last = existing.get_last_coord()
                            for c in last:
                                if c in graph_lookup:
                                    graph_lookup[c].remove(existing)
                            existing.add_coord(centroid, list_index, sents)
                            for c in existing.get_last_coord():
                                graph_lookup[c].append(existing)
                            added = True
                            break
                    if added:
                        break

                if not added:
                    g = _ConceptGraph(centroid, list_index, sents)
                    graph_lookup[centroid].append(g)

        # Prune empty lookups
        graph_lookup = defaultdict(list, {k: v for k, v in graph_lookup.items() if v})

    # Deduplicate: return graphs with length > 1 (seen in >=2 periods)
    seen = set()
    result = []
    for graphs in graph_lookup.values():
        for g in graphs:
            if g.length > 1 and id(g) not in seen:
                seen.add(id(g))
                result.append(g)
    return result


class _PeriodEmbeddingStore:
    """Disk-backed append-only row store for per-period raw embeddings.

    Replaces the old in-RAM `list[np.ndarray]` reference so that reference
    bookkeeping stays O(1) in the number of periods (<= a few hundred KB of
    RAM regardless of stream length; the vectors themselves live in a plain
    float32 binary file). Rows are appended in period order, exactly the
    arrays the engine used to keep in the list. Reads are either bounded
    blocks (streamed for the block-wise k-NN novelty pass; RSS stays at one
    block) or a single full read (only for paths that genuinely need the
    whole matrix at once, e.g. a UMAP refit).

    Layout: <dir>/vecs.bin - C-order float32 [n, dim]; dim is fixed by the
    first append. The store is PER-RUN engine state, exactly like the in-RAM
    list it replaces: it lives in a unique `run-<pid>-<rand>` subdirectory of
    the base dir (env NCD_REF_STORE_DIR / WALLCLOCK_REF_DIR override; default
    stream/data/ncd_state/ inside the repo when present, else the system temp
    dir) and is removed on close()/process exit; stale run dirs of dead
    processes are pruned opportunistically on open.
    """

    def __init__(self, directory: str):
        self._dir = directory
        self._path = os.path.join(directory, "vecs.bin")
        os.makedirs(directory, exist_ok=True)
        self._wf = open(self._path, "w+b")   # write handle (append-only)
        self._rf = open(self._path, "rb")    # read handle (block streaming)
        self._rows: list[int] = []           # rows per period (tiny)
        self._n = 0                          # total rows
        self.dim = 0                         # fixed by first append
        self._closed = False
        atexit.register(self.close)

    # -- lifecycle / paths ---------------------------------------------------

    @classmethod
    def create(cls, directory: str | None = None) -> "_PeriodEmbeddingStore":
        base = directory or os.environ.get("NCD_REF_STORE_DIR") \
            or os.environ.get("WALLCLOCK_REF_DIR") or _default_ref_base_dir()
        _prune_stale_ref_dirs(base)
        run_dir = os.path.join(base, f"run-{os.getpid()}-{uuid.uuid4().hex[:6]}")
        return cls(run_dir)

    def close(self):
        if self._closed:
            return
        self._closed = True
        for fh in (self._wf, self._rf):
            try:
                fh.close()
            except OSError:
                pass
        shutil.rmtree(self._dir, ignore_errors=True)

    # -- writes --------------------------------------------------------------

    def append(self, embeddings: np.ndarray) -> None:
        """Append one period's raw embeddings (stored as-is, same bytes)."""
        if self._closed:
            raise RuntimeError("reference store is closed")
        arr = np.ascontiguousarray(embeddings, dtype=np.float32)
        if arr.ndim != 2:
            raise ValueError(f"expected 2D embeddings, got shape {arr.shape}")
        if self.dim == 0:
            self.dim = int(arr.shape[1])
        elif arr.shape[1] != self.dim:
            raise ValueError(f"embedding dim changed: {arr.shape[1]} != {self.dim}")
        self._wf.write(arr.tobytes())  # buffered handle -> full writes
        self._wf.flush()
        self._n += int(arr.shape[0])
        self._rows.append(int(arr.shape[0]))

    # -- reads ---------------------------------------------------------------

    def __len__(self) -> int:
        return self._n

    def iter_blocks(self, block_rows: int) -> Iterator[np.ndarray]:
        """Yield the stored rows as read-only float32 blocks (dim,).

        Sequential file reads - unlike slicing one big memmap, touched pages
        are freed after each block, so peak RSS stays at ~one block regardless
        of total reference size.
        """
        if self._closed:
            raise RuntimeError("reference store is closed")
        self._rf.seek(0)
        remaining = self._n
        while remaining > 0:
            take = min(block_rows, remaining)
            data = self._rf.read(take * self.dim * 4)
            if len(data) != take * self.dim * 4:
                raise RuntimeError(
                    f"reference store truncated: wanted {take * self.dim * 4} "
                    f"bytes at {remaining - take}/{self._n} rows, got {len(data)}")
            yield np.frombuffer(data, dtype=np.float32).reshape(take, self.dim)
            remaining -= take

    def read_all(self) -> np.ndarray:
        """Read every stored row into one RAM matrix (fit-time paths only)."""
        if self._closed:
            raise RuntimeError("reference store is closed")
        if self._n == 0:
            return np.zeros((0, self.dim), dtype=np.float32)
        arr = np.fromfile(self._path, dtype=np.float32,
                          count=self._n * self.dim).reshape(self._n, self.dim)
        if arr.shape[0] != self._n:
            raise RuntimeError(f"reference store truncated: {arr.shape} != {self._n} rows")
        return arr


def _default_ref_base_dir() -> str:
    """Default base dir for the engine's per-run reference store."""
    pkg_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    candidate = os.path.join(pkg_root, "stream", "data", "ncd_state")
    if os.path.isdir(os.path.dirname(candidate)):
        return candidate
    return os.path.join(tempfile.gettempdir(), "ncd_state")


def _prune_stale_ref_dirs(base: str, max_age_s: float = 7200.0) -> None:
    """Best-effort removal of run dirs left behind by killed processes.

    A watchdog SIGKILL skips close()/atexit, so dirs can leak; a dir is stale
    when its pid is dead or it has not been written to for max_age_s (live
    engines append every period, keeping mtime fresh).
    """
    try:
        names = os.listdir(base)
    except OSError:
        return
    now = time.time()
    for name in names:
        if not name.startswith("run-"):
            continue
        d = os.path.join(base, name)
        pid_part = name[4:].split("-", 1)[0]
        dead_pid = False
        try:
            os.kill(int(pid_part), 0)
        except ProcessLookupError:
            dead_pid = True
        except (ValueError, PermissionError):
            pass
        stale = False
        try:
            stale = (now - os.stat(d).st_mtime) > max_age_s
        except OSError:
            continue
        if dead_pid or stale:
            shutil.rmtree(d, ignore_errors=True)


class _InflowCUSUM:
    """N1.3: online two-sided CUSUM change-point detector on a per-entity
    weekly member-inflow series (OBSERVED inflows: one value per period the
    entity was emitted; silent weeks carry no observation, which is what a
    sporadic emitter's baseline requires).

    Statistic, exact:

        baseline mu/sigma = mean/population-std of the trailing `window`
        observed inflows (the current value is excluded; the window may be
        shorter early in the entity's life)
        z_t   = (x_t - mu) / max(sigma, sigma_floor)      (standardized residual)
        s_hi  = max(0, s_hi + z_t - k)                    (upward CUSUM, flags)
        s_lo  = min(0, s_lo + z_t + k)                    (downward CUSUM, tracked
                                                           for symmetry/telemetry,
                                                           never flags)

    A change point fires when s_hi > h AND the residual has been positive for
    `confirm` consecutive observed updates ending at t (sustained confirmation:
    a single spike, however large, cannot fire). On fire the statistic resets
    (the engine additionally latches the flag - one flag per entity).
    """

    __slots__ = ("k", "h", "sigma_floor", "confirm", "s_hi", "s_lo", "pos_streak")

    def __init__(self, k: float, h: float, sigma_floor: float, confirm: int):
        self.k = float(k)
        self.h = float(h)
        self.sigma_floor = max(1e-6, float(sigma_floor))
        self.confirm = max(1, int(confirm))
        self.s_hi = 0.0
        self.s_lo = 0.0
        self.pos_streak = 0

    def update(self, baseline_window: list[float], x: float) -> bool:
        """Feed one period's inflow `x` with its trailing observed inflows.

        Returns True exactly on the change-point crossing (then resets).
        """
        if baseline_window:
            n = len(baseline_window)
            mu = sum(baseline_window) / n
            var = sum((v - mu) ** 2 for v in baseline_window) / n
            sigma = var ** 0.5
        else:
            mu, sigma = 0.0, 0.0
        z = (x - mu) / max(sigma, self.sigma_floor)
        self.s_hi = max(0.0, self.s_hi + z - self.k)
        self.s_lo = min(0.0, self.s_lo + z + self.k)
        if z > 0:
            self.pos_streak += 1
        else:
            self.pos_streak = 0
        fire = self.s_hi > self.h and self.pos_streak >= self.confirm
        if fire:
            self.s_hi = 0.0
            self.pos_streak = 0
        return fire


class NcdEngine:
    """Stateful NCD engine supporting incremental real-time concept detection."""

    def __init__(self, config: NcdConfig | None = None,
                 ref_store_dir: str | None = None):
        self.config = config or NcdConfig()
        self._model = None
        self._reducer = None
        self._fitted = False

        # Heatmap state
        self._reference_heatmaps: list[np.ndarray] = []
        self._bins_dicts: list[dict] = []
        self._period_heatmap_blobs: list[list[np.ndarray]] = []
        self._period_ids: list[str] = []
        self._detected_concepts: list[DetectedConcept] = []
        self._start_time = time.time()
        # Fixed coordinate edges: established on the first period and reused so
        # that a topic keeps a stable bin position across periods (stable graph
        # linking / concept tracking). Outliers are clipped to the edge bins.
        self._edges: list[np.ndarray] | None = None

        # P0: raw 768-dim embeddings per period (for k-NN novelty). Kept in a
        # disk-backed per-run store (same vectors, same order as the old
        # in-RAM list) so reference bookkeeping costs O(1) RAM in #periods.
        self._ref_store = _PeriodEmbeddingStore.create(ref_store_dir)
        self._period_sentences: list[list[str]] = []

        # P0: cross-period concept graphs
        self._concept_graphs: list[_ConceptGraph] = []

        # P2/A: growth tracking per concept (period indices in which it appeared)
        self._graph_periods: dict[str, list[int]] = {}
        # P2/A: stable-topic suppression
        self._stable_frequency: dict[str, int] = defaultdict(int)
        self._stable_blacklist: set[str] = set()
        self._blacklist_ready = False

        # P2: concept drift (2D distributions per period + JS-divergence history)
        self._period_2d: list[np.ndarray] = []
        self._drift_history: list[float] = []

        # P2/D: adaptive novelty pool (running familiarity floor)
        self._novelty_pool: list[float] = []
        self._NOVELTY_POOL_MAX = 50_000

        # P0: UMAP refit counter
        self._period_count = 0

        # N1.3: per-entity weekly member-inflow change-point detector
        # ("velocity gate"). All keys are primary concept_ids (stable across
        # periods via graph tracking); burst-tier concepts get a fresh uuid
        # per emission and are already flagged, so they never enter here.
        self._entity_inflow: dict[str, dict[int, int]] = {}    # cid -> {period: new unique units}
        self._entity_obs_inflow: dict[str, list[int]] = {}     # cid -> observed inflows (emission order)
        self._entity_seen_units: dict[str, set[str]] = {}      # cid -> unique member units ever
        self._entity_pos_weeks: dict[str, int] = defaultdict(int)  # observed inflows > 0
        self._inflow_detectors: dict[str, _InflowCUSUM] = {}
        self._velocity_flagged: set[str] = set()               # latched: one flag per entity
        self._velocity_flags_total = 0
        # N1.4 (node 1.2): debut fast-path telemetry (subset of velocity flags)
        self._debut_flags_total = 0

        # Garbage judge: only the first failure warns so a missing model never
        # spams the ingest log on every batch.
        self._judge_failed = False

        logger.info("NCD Engine initialized (model=%s, device=%s)", self.config.EMBEDDING_MODEL, self.config.DEVICE)

    def _ensure_model_loaded(self):
        if self._model is not None:
            return
        from sentence_transformers import SentenceTransformer
        logger.info("Loading embedding model: %s", self.config.EMBEDDING_MODEL)
        self._model = SentenceTransformer(
            self.config.EMBEDDING_MODEL,
            cache_folder=self.config.MODEL_CACHE_DIR,
            device=self.config.DEVICE,
        )
        logger.info("Model loaded successfully")

    def _ensure_reducer_fitted(self, embeddings: np.ndarray):
        import umap

        self._period_count += 1
        refit_interval = self.config.UMAP_REFIT_INTERVAL

        if self._fitted and self._reducer is not None:
            # P0: periodic refit to prevent drift
            if refit_interval > 0 and self._period_count % refit_interval == 0:
                logger.info("Refitting UMAP at period %d (every %d periods)", self._period_count, refit_interval)
                self._reducer = umap.UMAP(
                    n_components=self.config.UMAP_N_COMPONENTS,
                    n_neighbors=min(15, len(embeddings) - 1),
                    random_state=self.config.UMAP_RANDOM_STATE,
                    n_jobs=self.config.UMAP_N_JOBS,
                    verbose=False,
                    low_memory=True,
                )
                # Refit on all accumulated raw embeddings (streamed from the
                # disk-backed reference store into one matrix - UMAP needs the
                # full matrix only at fit time; the wallclock replay sets
                # UMAP_REFIT_INTERVAL=0 so this path never runs there).
                cur = np.ascontiguousarray(embeddings, dtype=np.float32)
                parts = ([self._ref_store.read_all()] if len(self._ref_store) else []) + [cur]
                all_raw = np.concatenate(parts) if len(parts) > 1 else parts[0]
                self._reducer.fit(all_raw)
            return

        logger.info("Fitting UMAP reducer on %d embeddings", len(embeddings))
        self._reducer = umap.UMAP(
            n_components=self.config.UMAP_N_COMPONENTS,
            n_neighbors=min(15, len(embeddings) - 1),
            random_state=self.config.UMAP_RANDOM_STATE,
            n_jobs=self.config.UMAP_N_JOBS,
            verbose=False,
            low_memory=True,
        )
        self._reducer.fit(np.ascontiguousarray(embeddings, dtype=np.float32))
        self._fitted = True

    def embed_texts(self, texts: list[str]) -> np.ndarray:
        """Embed texts using the sentence transformer model."""
        self._ensure_model_loaded()
        prefix = self.config.EMBEDDING_PREFIX
        inputs = texts if not prefix else [prefix + t for t in texts]
        embeddings = self._model.encode(
            inputs,
            batch_size=self.config.BATCH_SIZE,
            show_progress_bar=False,
            normalize_embeddings=True,
        )
        return np.array(embeddings)

    def _compute_novelty_scores(
        self,
        current_embeddings: np.ndarray,
        reference_embeddings: np.ndarray | _PeriodEmbeddingStore | None,
    ) -> np.ndarray:
        """k-NN novelty score: mean cosine similarity to k nearest neighbors in reference.

        Low score = novel (new topic not seen before).
        Embeddings must be L2-normalized for cosine sim = dot product.

        Block-wise rewrite of the old full `current @ reference.T` matrix:
        the reference is iterated in blocks (env WALLCLOCK_NOVELTY_BLOCK,
        default 16384 rows, further capped so the per-block similarity
        matrix stays <= WALLCLOCK_NOVELTY_SIM_MB, default 32 MB) and a
        running per-row top-k is maintained with np.partition per block.
        The reference may be an in-RAM array (old
        call signature) or the engine's disk-backed store, which is streamed
        so peak RSS is one block regardless of reference size.

        Bit-identity: every similarity value is computed by the same float32
        sgemm dot products as before, and np.partition is exact selection, so
        the final per-row top-k multiset is BIT-IDENTICAL to the old global
        np.partition (verified on real data: max|diff| == 0 over sorted
        per-row top-k). The mean over the k values is the same expression as
        before; because np.partition leaves its output in an arbitrary order
        and float32 summation is not associative, individual scores can differ
        from the old code by <= ~1 float32 ULP (~2.4e-7 measured) - far below
        any downstream rounding (novelty prints use %.3f, strengths round to
        4 decimals; the only exact consumer is the novelty gate comparison).
        """
        n_ref = len(reference_embeddings) if reference_embeddings is not None else 0
        if n_ref == 0:
            return np.ones(len(current_embeddings))

        k = max(1, min(self.config.KNN_K, n_ref))
        try:
            block_rows = int(os.environ.get("WALLCLOCK_NOVELTY_BLOCK", "16384"))
        except ValueError:
            block_rows = 16384
        try:
            sim_cap_mb = float(os.environ.get("WALLCLOCK_NOVELTY_SIM_MB", "32"))
        except ValueError:
            sim_cap_mb = 32.0
        # Cap the per-block similarity matrix (n_current x block_rows float32)
        # so the transient stays bounded for large periods as well; the block
        # only affects speed, never the values (selection is exact).
        sim_cap_rows = max(k, int(sim_cap_mb * (1 << 20) // (4 * max(1, len(current_embeddings)))))
        block_rows = max(k, min(block_rows, sim_cap_rows))

        if isinstance(reference_embeddings, _PeriodEmbeddingStore):
            blocks = reference_embeddings.iter_blocks(block_rows)
        else:
            blocks = (reference_embeddings[i:i + block_rows]
                      for i in range(0, n_ref, block_rows))

        # Running per-row top-k similarities; each merge keeps the k largest
        # seen so far (unordered, as np.partition leaves them).
        best: np.ndarray | None = None
        for block in blocks:
            sims = current_embeddings @ block.T  # (n_current, block_rows)
            merged = sims if best is None else np.concatenate((best, sims), axis=1)
            width = merged.shape[1]
            if width > k:
                # ascontiguousarray: copy out just the k winners so the wide
                # partition output is freed instead of kept alive by the view
                merged = np.ascontiguousarray(
                    np.partition(merged, width - k, axis=1)[:, width - k:])
            best = merged
        novelty_scores = best.mean(axis=1)  # mean top-k similarity; low = novel
        return novelty_scores

    def _novelty_threshold(self) -> float:
        """Active novelty gate.

        Adaptive mode: mean(running pool) - ADAPTIVE_K * std(pool). Real
        embeddings have a high absolute baseline (~0.5+), so a hard fixed
        threshold never separates a genuine new concept from stable chatter;
        the dip below the running familiarity floor is the discriminator.
        Falls back to the absolute NOVELTY_THRESHOLD until the pool is large
        enough to estimate a spread.
        """
        if not self.config.NOVELTY_ADAPTIVE:
            return self.config.NOVELTY_THRESHOLD
        pool = np.asarray(self._novelty_pool, dtype=np.float64)
        if len(pool) < max(10, self.config.KNN_K * 2) or pool.std() < 1e-9:
            return self.config.NOVELTY_THRESHOLD
        return float(pool.mean() - self.config.ADAPTIVE_K * pool.std())

    def _record_novelty_pool(self, scores: np.ndarray):
        self._novelty_pool.extend(float(s) for s in scores)
        if len(self._novelty_pool) > self._NOVELTY_POOL_MAX:
            self._novelty_pool = self._novelty_pool[-self._NOVELTY_POOL_MAX:]

    # ------------------------------------------------------------------
    # P2/A: two-tier emerging detection (novelty < t1 AND growth >= t2)
    # ------------------------------------------------------------------
    def _record_graph_period(self, concept_id: str, period_idx: int):
        """Record that a concept (graph) appeared in a given period (deduped)."""
        periods = self._graph_periods.setdefault(concept_id, [])
        if not periods or periods[-1] != period_idx:
            periods.append(period_idx)

    def _graph_growth(self, concept_id: str, period_idx: int) -> float:
        """Appearance density of a concept over the last GROWTH_WINDOW periods.

        Returns fraction of recent periods (including current) in which the
        concept was present, over min(GROWTH_WINDOW, period_idx + 1).
        """
        window = max(1, self.config.GROWTH_WINDOW)
        periods = self._graph_periods.get(concept_id, [])
        recent = [p for p in periods if p > period_idx - window]
        denominator = min(window, period_idx + 1)
        return len(recent) / denominator

    def _update_stable_blacklist(self):
        """After the warmup window, blacklist recurring concepts.

        Two complementary criteria: any concept present in EVERY warmup period is
        definitionally stable; the remainder are capped at STABLE_TOP_K by
        frequency. This suppresses stable topics AND persistent unknown/noise
        clusters (e.g. "unassociated" chatter) that would otherwise look novel.
        """
        if self._blacklist_ready:
            return
        warmup = max(1, self.config.STABLE_WARMUP_PERIODS)
        always_present = {
            cid for cid, count in self._stable_frequency.items() if count >= warmup
        }
        recurring = [
            (cid, count) for cid, count in self._stable_frequency.items()
            if warmup > count >= 2
        ]
        recurring.sort(key=lambda x: x[1], reverse=True)
        self._stable_blacklist = always_present | {
            cid for cid, _ in recurring[: self.config.STABLE_TOP_K]
        }
        self._blacklist_ready = True
        if self._stable_blacklist:
            logger.info("Stable-topic suppression: blacklisted %d recurring concepts: %s",
                        len(self._stable_blacklist), sorted(self._stable_blacklist))

    # ------------------------------------------------------------------
    # N1.3: velocity gate (per-entity online inflow change-point detector)
    # ------------------------------------------------------------------
    def _velocity_flag(self, concept_id: str, period_idx: int, new_units: int) -> bool:
        """Update one entity's observed weekly inflow series and test its
        two-sided CUSUM for a change point (see _InflowCUSUM for the exact
        statistic).

        `new_units` = number of UNIQUE member units (sentences) the entity
        accrued this period - the engine's observable member inflow; the
        baseline is built from the entity's OBSERVED inflows (emission
        periods), so sporadic emitters are not diluted by silent weeks.
        Returns True at most once per entity (the flag latches), on the
        period the sustained excess first crosses the decision threshold.
        Precision guards before the statistic even runs: INFLOW_WARMUP prior
        observed inflows, INFLOW_MIN_CUM_UNITS cumulative unique units, and
        at least two observed inflows > 0.

        N1.4 (node 1.2) debut fast-path: if this is the entity's FIRST
        observed inflow and it already reaches INFLOW_DEBUT unique units,
        flag immediately - no warmup, no confirmation. Rationale: the CUSUM
        path needs >= WARMUP+1 observed emissions plus CONFIRM sustained
        updates, which is always later than mass adoption (40 members within
        8 weeks) on fast ramps; a large debut week IS the pre-adoption
        evidence. INFLOW_DEBUT=0 disables the fast path exactly.
        """
        cfg = self.config
        series = self._entity_inflow.setdefault(concept_id, {})
        series[period_idx] = new_units
        obs = self._entity_obs_inflow.setdefault(concept_id, [])
        if new_units > 0:
            self._entity_pos_weeks[concept_id] += 1
        eligible = (
            concept_id not in self._velocity_flagged
            and len(obs) >= cfg.INFLOW_WARMUP
            and len(self._entity_seen_units.get(concept_id, ())) >= cfg.INFLOW_MIN_CUM_UNITS
            and self._entity_pos_weeks[concept_id] >= 2
        )
        fire = False
        if (
            cfg.INFLOW_DEBUT > 0
            and concept_id not in self._velocity_flagged
            and not obs                      # first observed inflow == debut
            and new_units >= cfg.INFLOW_DEBUT
        ):
            # Debut fast-path: one-shot latch shared with the CUSUM path,
            # so a latched entity never fires a second time.
            fire = True
            self._velocity_flagged.add(concept_id)
            self._velocity_flags_total += 1
            self._debut_flags_total += 1
            logger.info(
                "Period %d: DEBUT fast-path flag on entity %s "
                "(first inflow=%d >= %d)",
                period_idx, concept_id, new_units, cfg.INFLOW_DEBUT,
            )
        elif eligible:
            det = self._inflow_detectors.get(concept_id)
            if det is None:
                det = self._inflow_detectors[concept_id] = _InflowCUSUM(
                    cfg.INFLOW_CUSUM_K, cfg.INFLOW_CUSUM_H,
                    cfg.INFLOW_SIGMA_FLOOR, cfg.INFLOW_CONFIRM)
            fire = det.update(obs[-cfg.INFLOW_WINDOW:], float(new_units))
            if fire:
                self._velocity_flagged.add(concept_id)
                self._velocity_flags_total += 1
                logger.info(
                    "Period %d: velocity change point on entity %s "
                    "(inflow=%d, cum_units=%d, baseline=%s)",
                    period_idx, concept_id, new_units,
                    len(self._entity_seen_units.get(concept_id, ())),
                    [int(v) for v in obs[-cfg.INFLOW_WINDOW:]])
        obs.append(new_units)
        return fire

    def _create_heatmap(
        self,
        embeddings_2d: np.ndarray,
        edges: list[np.ndarray] | None = None,
    ) -> tuple[np.ndarray, list[np.ndarray], dict]:
        """Create a heatmap from 2D embeddings. Returns (heatmap, edges, bins_dict)."""
        bins = self.config.HEATMAP_BINS

        if edges is None:
            ranges = []
            for i in range(embeddings_2d.shape[1]):
                lo, hi = float(embeddings_2d[:, i].min()), float(embeddings_2d[:, i].max())
                if lo == hi:
                    lo -= 1.0
                    hi += 1.0
                span = hi - lo
                margin = self.config.HEATMAP_RANGE_MARGIN * span
                ranges.append((lo - margin, hi + margin))
            _, edges = np.histogramdd(embeddings_2d, bins=bins, range=ranges)

        histogram, _ = np.histogramdd(embeddings_2d, bins=bins, range=[(e.min(), e.max()) for e in edges])

        bins_dict: dict[tuple, list[int]] = {}
        dim_bins = [np.digitize(embeddings_2d[:, i], edges[i]) - 1 for i in range(embeddings_2d.shape[1])]
        for i in range(len(embeddings_2d)):
            bin_key = tuple(
                max(0, min(dim_bins[d][i], bins - 1)) for d in range(embeddings_2d.shape[1])
            )
            if bin_key not in bins_dict:
                bins_dict[bin_key] = []
            bins_dict[bin_key].append(i)

        return histogram, edges, bins_dict

    def _compute_reference_heatmap(self) -> np.ndarray | None:
        """Compute reference heatmap as element-wise max over stored reference heatmaps."""
        if not self._reference_heatmaps:
            return None
        return np.maximum.reduce(self._reference_heatmaps)

    def _compute_difference_heatmap(
        self,
        current_heatmap: np.ndarray,
        reference_heatmap: np.ndarray,
    ) -> np.ndarray:
        """Compute normalized difference heatmap (current - reference), clamped to >= 0."""
        ref_sum = reference_heatmap.sum()
        cur_sum = current_heatmap.sum()
        if ref_sum == 0:
            return current_heatmap
        scale = ref_sum / cur_sum if cur_sum > 0 else 1.0
        diff = scale * current_heatmap - reference_heatmap
        return np.maximum(0, diff)

    def _detect_blobs(self, diff_heatmap: np.ndarray) -> list[np.ndarray]:
        """Detect blobs using Laplacian of Gaussian (on smoothed heatmap)."""
        smoothed = gaussian_filter(diff_heatmap, sigma=self.config.SMOOTH_SIGMA)
        blobs = blob_log(
            smoothed,
            min_sigma=1,
            max_sigma=10,
            threshold=self.config.BLOB_RHO * smoothed.max() if smoothed.max() > 0 else 0,
        )
        return blobs

    def _cluster_gmm(
        self,
        embeddings_2d: np.ndarray,
    ) -> tuple[np.ndarray, any]:
        """Soft clustering via BIC-selected Gaussian Mixture Model.

        Returns (component_labels, fitted_model). Components with fewer than
        GMM_MIN_SAMPLES samples are marked as -1 (noise).
        """
        from sklearn.mixture import GaussianMixture

        n = len(embeddings_2d)
        max_k = max(2, min(self.config.GMM_MAX_COMPONENTS, max(2, int(np.sqrt(n)))))
        best_model, best_bic = None, np.inf
        for k in range(1, max_k + 1):
            g = GaussianMixture(n_components=k, covariance_type="full",
                                random_state=42, reg_covar=1e-3)
            g.fit(np.ascontiguousarray(embeddings_2d, dtype=np.float32))
            bic = g.bic(np.ascontiguousarray(embeddings_2d, dtype=np.float32))
            if bic < best_bic:
                best_bic, best_model = bic, g

        labels = best_model.predict(np.ascontiguousarray(embeddings_2d, dtype=np.float32))
        for comp in range(best_model.n_components):
            if np.sum(labels == comp) < self.config.GMM_MIN_SAMPLES:
                labels[labels == comp] = -1
        return labels, best_model

    @staticmethod
    def _js_divergence(p: np.ndarray, q: np.ndarray) -> float:
        """Jensen-Shannon divergence between two normalized 1D distributions."""
        eps = 1e-12
        p = p.astype(np.float64) + eps
        q = q.astype(np.float64) + eps
        p /= p.sum()
        q /= q.sum()
        m = 0.5 * (p + q)
        return float(0.5 * float(np.sum(kl_div(p, m))) + 0.5 * float(np.sum(kl_div(q, m))))

    def _compute_drift(
        self,
        current_2d: np.ndarray,
        reference_2d: np.ndarray,
    ) -> float:
        """JS divergence between the current 2D distribution and a reference 2D distribution."""
        if len(current_2d) == 0 or len(reference_2d) == 0:
            return 0.0
        b = self.config.DRIFT_BINS
        lo = min(float(current_2d.min()), float(reference_2d.min()))
        hi = max(float(current_2d.max()), float(reference_2d.max()))
        if lo == hi:
            return 0.0
        range_ = [(lo, hi), (lo, hi)]
        cur, _ = np.histogramdd(current_2d, bins=b, range=range_)
        ref, _ = np.histogramdd(reference_2d, bins=b, range=range_)
        return self._js_divergence(cur.ravel(), ref.ravel())

    def _group_blobs(self, blobs: list[np.ndarray], max_dist: int) -> list[list[np.ndarray]]:
        """Group spatially-near blobs (Chebyshev distance <= max_dist) into one concept."""
        n = len(blobs)
        if n <= 1:
            return [[b] for b in blobs]

        parent = list(range(n))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(i: int, j: int) -> None:
            ri, rj = find(i), find(j)
            if ri != rj:
                parent[ri] = rj

        for i in range(n):
            yi, xi = int(blobs[i][0]), int(blobs[i][1])
            for j in range(i + 1, n):
                yj, xj = int(blobs[j][0]), int(blobs[j][1])
                if abs(yi - yj) <= max_dist and abs(xi - xj) <= max_dist:
                    union(i, j)

        groups: dict[int, list[np.ndarray]] = defaultdict(list)
        for i in range(n):
            groups[find(i)].append(blobs[i])
        return list(groups.values())

    def _extract_sentences_for_blob(
        self,
        blob_coord: np.ndarray,
        bins_dict: dict,
        extend_range: int = 1,
    ) -> list[int]:
        """Get document indices for nearby bins of a blob."""
        blob_y, blob_x = int(blob_coord[0]), int(blob_coord[1])
        nearby = set()
        for dy in range(-extend_range, extend_range + 1):
            for dx in range(-extend_range, extend_range + 1):
                key = (blob_y + dy, blob_x + dx)
                if key in bins_dict:
                    nearby.update(bins_dict[key])
        return list(nearby)

    @staticmethod
    def _bin_coord(v: float, axis: int, edges: list[np.ndarray]) -> int:
        """Map a UMAP coordinate value into a heatmap bin index."""
        try:
            idx = int(np.digitize([v], edges[axis])[0]) - 1
            # edges has bins+1 entries; last valid bin index = bins-1
            return max(0, min(idx, len(edges[axis]) - 2))
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # N1.2: second-pass residual novelty clustering ("burst tier")
    # ------------------------------------------------------------------
    @staticmethod
    def _bin_width(edges: list[np.ndarray]) -> float:
        """Mean histogram bin width expressed in raw 2D-coordinate units."""
        widths = [float(e[1] - e[0]) for e in edges if len(e) > 1]
        return float(np.mean(widths)) if widths else 1.0

    @staticmethod
    def _burst_components(points: np.ndarray, eps: float) -> list[list[int]]:
        """Connected components of 2D points under Euclidean distance <= eps.

        Single-linkage components (union-find over the k-d tree radius graph):
        a slow-arriving topic whose units sit on one spot links up even when
        individual units jitter by more than eps from each other.
        """
        n = len(points)
        parent = list(range(n))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(i: int, j: int) -> None:
            ri, rj = find(i), find(j)
            if ri != rj:
                parent[ri] = rj

        for i, j in cKDTree(points).query_pairs(eps):
            union(i, j)

        grouped: dict[int, list[int]] = defaultdict(list)
        for i in range(n):
            grouped[find(i)].append(i)
        # deterministic order: largest components first, then by smallest index
        return sorted(grouped.values(), key=lambda v: (-len(v), v[0]))

    @staticmethod
    def _mean_pairwise_cosine(x: np.ndarray) -> float:
        """Mean pairwise cosine similarity of the rows (0.0 for < 2 rows)."""
        if len(x) < 2:
            return 0.0
        norms = np.linalg.norm(x, axis=1, keepdims=True)
        xn = x / np.where(norms > 1e-9, norms, 1.0)
        sim = xn @ xn.T
        return float((sim.sum() - np.trace(sim)) / (len(x) * (len(x) - 1)))

    def _emit_burst_concepts(
        self,
        *,
        units: list[str],
        unit_to_doc: list[int],
        raw_embeddings: np.ndarray,
        embeddings_2d: np.ndarray,
        novelty_scores: np.ndarray,
        novelty_gate: float,
        absorbed: set[int],
        edges: list[np.ndarray],
        period_idx: int,
        period_id: str,
        docs: list[Document],
    ) -> list[DetectedConcept]:
        """Second pass over the RESIDUAL novelty pool.

        Units whose novelty is below the gate but which the primary pass did
        NOT absorb into any emitted concept are re-clustered with connected
        components in the existing 2D embedding space. Cohesive, sufficiently
        large, document-diverse components are emitted as "burst" concepts
        flagged WITHOUT the growth/recurrence gate -- the cohort-growth gate
        structurally drops late-appearing decaying topics (their first period
        never produces a blob, so no graph is ever "first novel"), while a
        first-sight burst is exactly what such topics look like. The
        cohesion + min-size + min-source guards keep scattered noise out.
        """
        cfg = self.config
        residual = np.array(
            [i for i in range(len(novelty_scores))
             if novelty_scores[i] < novelty_gate and i not in absorbed],
            dtype=np.int64,
        )
        if len(residual) < max(2, cfg.BURST_MIN_SIZE):
            return []
        if len(residual) > cfg.BURST_MAX_RESIDUAL:
            logger.info("Burst tier: residual pool %d exceeds cap %d; skipping pass",
                        len(residual), cfg.BURST_MAX_RESIDUAL)
            return []

        eps = cfg.BURST_EPS_BINS * self._bin_width(edges)
        components = self._burst_components(embeddings_2d[residual], eps)

        emitted: list[DetectedConcept] = []
        for comp in components:
            member_idx = sorted(int(i) for i in residual[comp])
            if len(member_idx) < cfg.BURST_MIN_SIZE:
                continue
            docs_in_comp = {unit_to_doc[i] for i in member_idx if i < len(unit_to_doc)}
            if len(docs_in_comp) < cfg.BURST_MIN_SOURCES:
                continue
            cohesion = self._mean_pairwise_cosine(raw_embeddings[member_idx])
            if cohesion < cfg.BURST_COHESION:
                continue

            sentences = [units[i] for i in member_idx if i < len(units)]
            if not sentences:
                continue
            mean_px = (float(embeddings_2d[member_idx, 0].mean()),
                       float(embeddings_2d[member_idx, 1].mean()))
            cx = self._bin_coord(mean_px[1], 1, edges)
            cy = self._bin_coord(mean_px[0], 0, edges)
            member_novelty = float(np.mean(novelty_scores[member_idx]))

            concept = DetectedConcept(
                concept_id=_stable_concept_id(sentences, period_idx),
                label=sentences[0][:60],
                summary=" ".join(sentences)[:300],
                sentences=sentences[: cfg.MAX_SENTENCES_PER_CONCEPT],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                document_count=len(docs_in_comp),
                document_ids=[docs[i].id for i in sorted(docs_in_comp) if i < len(docs)],
                strength=round(1.0 - member_novelty, 4),
                coordinates=[cx, cy],
                source=period_id,
                emerging=True,   # burst tier: cohesion replaces the recurrence gate
                appearances=1,
            )
            emitted.append(concept)
            logger.info(
                "Period %s: burst concept %s size=%d docs=%d cohesion=%.2f "
                "novelty=%.3f coord=[%d,%d]",
                period_id, concept.concept_id, len(member_idx), len(docs_in_comp),
                cohesion, member_novelty, cx, cy,
            )
        return emitted

    def _judge_filter(self, docs: list[Document]) -> list[Document]:
        """Drop whole documents the LLM judges junk; pass through on any failure."""
        if not self.config.JUDGE_ENABLED or not docs:
            return docs
        try:
            verdicts = judge_documents([d.text for d in docs])
        except Exception:
            if not self._judge_failed:
                self._judge_failed = True
                logger.warning("garbage judge unavailable, pass-through")
            else:
                logger.debug("garbage judge unavailable, pass-through")
            return docs
        if verdicts is None:
            return docs
        kept = [d for d, v in zip(docs, verdicts) if not v[0] or v[1] < self.config.JUDGE_THRESHOLD]
        dropped = len(docs) - len(kept)
        if dropped > 0:
            logger.info("judge dropped %d/%d documents", dropped, len(docs))
        return kept

    def process_batch(self, batch: DocumentBatch) -> DetectionResult:
        """Process a batch of documents and detect emerging concepts."""
        start = time.time()
        self._ensure_model_loaded()

        docs = batch.documents
        period_id = batch.period_id or f"period_{len(self._period_ids)}"

        # Judge before the split: dropped docs never produce units, and
        # unit_to_doc / document_ids indices refer to the filtered list.
        docs = self._judge_filter(docs)

        # Step 1: Split documents into sentence-level units
        if self.config.SENTENCE_LEVEL:
            units: list[str] = []
            unit_to_doc: list[int] = []
            batch_seen: set[str] = set()
            for di, doc in enumerate(docs):
                for s in _split_sentences(doc.text):
                    # Syndicated stories repeat one sentence across several
                    # docs inside a single batch; keep one unit for them.
                    if _is_boilerplate(s) or s in batch_seen:
                        continue
                    batch_seen.add(s)
                    units.append(s)
                    unit_to_doc.append(di)
        else:
            units = [doc.text for doc in docs]
            unit_to_doc = list(range(len(docs)))

        if not units:
            return DetectionResult(period_id=period_id, concepts_found=0, concepts=[],
                                   processing_time_ms=0, total_documents=len(docs))

        # Step 2: Embed (768-dim)
        embeddings = self.embed_texts(units)

        # P0: store raw embeddings for k-NN novelty
        raw_embeddings = embeddings.copy()
        has_reference_embeddings = len(self._ref_store) > 0

        # Step 3: Dimensionality reduction (with periodic refit)
        self._ensure_reducer_fitted(embeddings)
        embeddings_2d = self._reducer.transform(embeddings)

        # Step 4: Create heatmap
        edges = self._edges
        if self.config.USE_DIFF and self._reference_heatmaps:
            ref = self._compute_reference_heatmap()
            heatmap, edges, bins_dict = self._create_heatmap(embeddings_2d, edges=edges)
            diff_heatmap = self._compute_difference_heatmap(heatmap, ref)
        else:
            heatmap, edges, bins_dict = self._create_heatmap(embeddings_2d, edges=edges)
            diff_heatmap = heatmap
        if self._edges is None and edges is not None:
            self._edges = edges
        diff_heatmap_smoothed = gaussian_filter(diff_heatmap, sigma=self.config.SMOOTH_SIGMA)

        # P0: compute novelty scores for this period's embeddings (used by the
        # GMM novel-only clustering below and by concept extraction in step 6).
        # The reference is streamed block-wise from the disk-backed store
        # (same vectors/order as the old in-RAM concatenate).
        novelty_scores = self._compute_novelty_scores(
            raw_embeddings, self._ref_store if has_reference_embeddings else None)
        self._record_novelty_pool(novelty_scores)
        novelty_gate = self._novelty_threshold()

        # Step 5: Cluster / detect concept candidates
        blobs = np.empty((0, 3))
        if self.config.CLUSTER_MODE == "gmm":
            # GMM is density-driven: sparse emerging signals are swallowed by the
            # dominant stable density. So first select the NOVEL units (raw-space
            # k-NN novelty below threshold) and cluster those alone.
            novel_mask = novelty_scores < novelty_gate
            novel_idx = np.where(novel_mask)[0]
            groups = []
            if len(novel_idx) >= self.config.GMM_MIN_SAMPLES:
                novel_labels, _gmm_model = self._cluster_gmm(embeddings_2d[novel_idx])
                for comp in np.unique(novel_labels):
                    if comp < 0:
                        continue
                    idxs = novel_idx[novel_labels == comp]
                    if len(idxs) >= self.config.GMM_MIN_SAMPLES:
                        groups.append(sorted(idxs.tolist()))
            logger.info("Period %s: %d units, %d novel, %d GMM novel-concepts",
                        period_id, len(units), len(novel_idx), len(groups))
        else:
            # blob_log threshold relative to the global diff max (0.05 * max)
            blobs = blob_log(
                diff_heatmap_smoothed,
                min_sigma=1,
                max_sigma=10,
                threshold=self.config.BLOB_RHO * diff_heatmap_smoothed.max() if diff_heatmap_smoothed.max() > 0 else 0,
            )
            blob_groups = self._group_blobs(blobs, self.config.BLOB_MAX_DIST)
            groups = []
            for group in blob_groups:
                idxs: set[int] = set()
                for blob in group:
                    idxs.update(self._extract_sentences_for_blob(blob, bins_dict))
                groups.append(sorted(idxs))
            logger.info("Period %s: %d units, %d blobs -> %d concepts",
                        period_id, len(units), len(blobs), len(groups))

        # Step 6: Extract concepts
        period_idx = len(self._period_ids)
        new_concepts: list[DetectedConcept] = []
        concept_updates: list[ConceptUpdate] = []
        velocity_flags_period = 0   # N1.3: velocity-gate flags fired this period
        # N1.2: units the primary pass turned into a concept ("absorbed");
        # everything novel but unabsorbed is the burst-tier residual pool.
        absorbed_units: set[int] = set()

        for group in groups:
            unit_idx = set(group)
            if not unit_idx:
                continue
            absorbed_units.update(unit_idx)

            sentences = [units[i] for i in unit_idx if i < len(units)]
            if not sentences:
                continue

            # coordinates (bin space) from the member sentences' 2D points
            member_idx = sorted(unit_idx)
            member_novelty = float(np.mean(novelty_scores[member_idx])) if member_idx else 1.0
            mean_px = (float(embeddings_2d[member_idx, 0].mean()),
                       float(embeddings_2d[member_idx, 1].mean()))

            cx = self._bin_coord(mean_px[1], 1, edges)
            cy = self._bin_coord(mean_px[0], 0, edges)
            doc_set = sorted({unit_to_doc[i] for i in member_idx if i < len(unit_to_doc)})

            # strength: blob mode = normalized cluster mass on the diff heatmap;
            # gmm mode = 1 - member novelty (1.0 for a dense, familiar cluster)
            if self.config.CLUSTER_MODE == "gmm":
                strength = round(1.0 - member_novelty, 4)
            else:
                mass = float(diff_heatmap_smoothed[cy, cx])
                strength = round(mass / (diff_heatmap_smoothed.max() or 1.0), 4)

            # P0: novelty flag
            blob_novelty = member_novelty
            is_novel = blob_novelty < novelty_gate and has_reference_embeddings

            # P0: cross-period concept tracking via Graph
            blob_coord = (cy, cx)
            concept_id = None
            matched_graph = None
            if period_idx > 0:
                graph_max_dist = (self.config.GMM_GRAPH_MAX_DIST
                                  if self.config.CLUSTER_MODE == "gmm"
                                  else self.config.GRAPH_MAX_DIST)
                for g in self._concept_graphs:
                    if g.is_eligible(blob_coord, period_idx, self.config.GRAPH_MAX_PERIOD_GAP,
                                     graph_max_dist):
                        concept_id = g.concept_id
                        matched_graph = g
                        break

            if matched_graph is not None:
                matched_graph.add_coord(blob_coord, period_idx, sentences)
                concept_graph = matched_graph
            else:
                g = _ConceptGraph(blob_coord, period_idx, sentences)
                g.first_novel = is_novel
                concept_id = g.concept_id
                concept_graph = g
                self._concept_graphs.append(g)

            # P2/A: growth + stable-topic suppression for the two-tier emerging flag.
            # "emerging" = genuinely new (novel at first discovery) AND recurring
            # within the growth window AND within its establishment window AND not
            # a known-stable topic. Current-period novelty is intentionally NOT
            # required so a 2nd appearance some periods in still counts.
            self._record_graph_period(concept_id, period_idx)
            appearances = len(self._graph_periods.get(concept_id, []))
            growth = self._graph_growth(concept_id, period_idx)
            blacklisted = concept_id in self._stable_blacklist
            # GMM clusters scattered transient noise into components too (a
            # precision cost inherent to soft clustering); blob_log's diff-heatmap
            # suppresses it. No recurrence gate here: GMM components for real
            # topics form only sporadically (recall loss >> FP cost).
            emerging = bool(
                self._blacklist_ready
                and concept_graph.first_novel
                and appearances <= max(self.config.GROWTH_WINDOW, 3)
                and growth >= self.config.GROWTH_THRESHOLD
                and not blacklisted
            )
            # N1.3: velocity gate - union with the novelty gate (emerging =
            # novelty-emerging OR inflow change point). The entity's weekly
            # inflow is the count of NEW unique member units it accrued this
            # period; novelty math above is untouched.
            if self.config.INFLOW_GATE:
                seen = self._entity_seen_units.get(concept_id)
                if seen is None:
                    seen = self._entity_seen_units[concept_id] = set()
                new_units = 0
                for s in sentences:
                    if s not in seen:
                        seen.add(s)
                        new_units += 1
                if self._velocity_flag(concept_id, period_idx, new_units):
                    emerging = True
                    velocity_flags_period += 1
            if period_idx < self.config.STABLE_WARMUP_PERIODS:
                self._stable_frequency[concept_id] += 1

            concept = DetectedConcept(
                concept_id=concept_id,
                label=sentences[0][:60] if sentences else "",
                summary=" ".join(sentences)[:300] if sentences else "",
                sentences=sentences[: self.config.MAX_SENTENCES_PER_CONCEPT],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                document_count=len(doc_set),
                document_ids=[docs[i].id for i in doc_set if i < len(docs)],
                strength=round(strength, 4),
                coordinates=[cx, cy],
                source=period_id,
                emerging=emerging,
                appearances=appearances,
            )
            new_concepts.append(concept)

            event_type = "new_concept" if is_novel else "concept_evolved"
            concept_updates.append(ConceptUpdate(event_type=event_type, concept=concept))

        # Step 6b (N1.2): second-pass residual novelty clustering ("burst tier").
        # Novel units that no primary concept absorbed are re-clustered
        # (connected components in the 2D embedding space) and emitted as burst
        # concepts WITHOUT the growth/recurrence gate; cohesion + min-size +
        # min-source guards reject scattered noise.
        burst_concepts: list[DetectedConcept] = []
        if self.config.BURST_TIER and has_reference_embeddings:
            burst_concepts = self._emit_burst_concepts(
                units=units,
                unit_to_doc=unit_to_doc,
                raw_embeddings=raw_embeddings,
                embeddings_2d=embeddings_2d,
                novelty_scores=novelty_scores,
                novelty_gate=novelty_gate,
                absorbed=absorbed_units,
                edges=edges,
                period_idx=period_idx,
                period_id=period_id,
                docs=docs,
            )
            for concept in burst_concepts:
                new_concepts.append(concept)
                concept_updates.append(ConceptUpdate(event_type="new_concept", concept=concept))

        # Step 7: Update state
        # P2/A: finalize stable-topic blacklist once the warmup window has elapsed
        if period_idx + 1 >= self.config.STABLE_WARMUP_PERIODS:
            self._update_stable_blacklist()

        self._reference_heatmaps.append(heatmap)
        if len(self._reference_heatmaps) > self.config.WINDOW_SIZE:
            self._reference_heatmaps.pop(0)

        self._bins_dicts.append(bins_dict)
        self._period_heatmap_blobs.append(blobs)
        self._period_ids.append(period_id)
        self._detected_concepts.extend(new_concepts)

        # P2: store 2D embeddings and compute drift vs previous period (or reference)
        self._period_2d.append(embeddings_2d)
        if len(self._period_2d) >= 2:
            ref_2d = np.concatenate(self._period_2d[:-1])
            drift = self._compute_drift(embeddings_2d, ref_2d)
            self._drift_history.append(drift)
        else:
            drift = 0.0

        # P0: store raw embeddings and sentences for future k-NN
        self._ref_store.append(raw_embeddings)
        self._period_sentences.append(units)

        processing_time = (time.time() - start) * 1000

        drift_alert = drift > self.config.DRIFT_THRESHOLD
        if drift_alert:
            logger.warning("Concept drift detected in %s: JS divergence %.3f > %.3f",
                           period_id, drift, self.config.DRIFT_THRESHOLD)

        return DetectionResult(
            period_id=period_id,
            concepts_found=len(new_concepts),
            concepts=new_concepts,
            processing_time_ms=round(processing_time, 2),
            total_documents=len(docs),
            heatmap_diff_summary={
                "max_diff": float(diff_heatmap_smoothed.max()),
                "mean_diff": float(diff_heatmap_smoothed.mean()),
                "nonzero_bins": int(np.count_nonzero(diff_heatmap)),
                "units": len(units),
                "novel_concepts": sum(1 for c in new_concepts if c.emerging),
                "velocity_flags": velocity_flags_period,
                "burst_concepts": len(burst_concepts),
                "drift": round(drift, 4),
                "drift_alert": drift_alert,
                "cluster_mode": self.config.CLUSTER_MODE,
            },
        )

    def get_all_concepts(self) -> list[DetectedConcept]:
        """Return all detected concepts."""
        return self._detected_concepts

    def close(self):
        """Release engine resources (disk-backed reference store).

        Idempotent; also registered via atexit inside the store so killed-or-
        forgotten processes do not keep the per-run directory open. The
        SentenceTransformer is NOT released here: embeddings are interleaved
        with replay, so the model may still be needed by a later batch.
        """
        self._ref_store.close()

    def get_stats(self) -> dict:
        """Return engine statistics."""
        return {
            "model_loaded": self._model is not None,
            "model_name": self.config.EMBEDDING_MODEL,
            "device": self.config.DEVICE,
            "periods_processed": len(self._period_ids),
            "total_concepts": len(self._detected_concepts),
            "total_documents": sum(len(s) for s in self._period_sentences),
            "uptime_seconds": round(time.time() - self._start_time, 1),
            "knn_k": self.config.KNN_K,
            "novelty_threshold": self.config.NOVELTY_THRESHOLD,
            "umap_refit_interval": self.config.UMAP_REFIT_INTERVAL,
            "active_graphs": len([g for g in self._concept_graphs if g.length > 1]),
            "cluster_mode": self.config.CLUSTER_MODE,
            "last_drift": round(self._drift_history[-1], 4) if self._drift_history else 0.0,
            "drift_max": round(max(self._drift_history), 4) if self._drift_history else 0.0,
            "drift_count": len(self._drift_history),
            # N1.3/N1.4: velocity-gate telemetry
            "inflow_gate": self.config.INFLOW_GATE,
            "inflow_debut": self.config.INFLOW_DEBUT,
            "velocity_flagged_entities": len(self._velocity_flagged),
            "velocity_flags_total": self._velocity_flags_total,
            "debut_flags_total": self._debut_flags_total,
        }


# Singleton instance
_engine: NcdEngine | None = None


def get_engine() -> NcdEngine:
    global _engine
    if _engine is None:
        _engine = NcdEngine()
    return _engine
