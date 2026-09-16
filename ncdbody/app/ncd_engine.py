"""Core NCD Engine - wraps the New Concept Detection pipeline for real-time use.

Implements:
  - k-NN novelty score in raw 768-dim embedding space (replaces np.maximum.reduce)
  - Cross-period concept tracking via Graph (ported from reference impl)
  - Periodic UMAP refit to prevent embedding-space drift
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

import copy
import logging
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Optional

import numpy as np
from scipy.ndimage import gaussian_filter
from scipy.special import kl_div
from skimage.feature import blob_log

from .config import NcdConfig
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
        self.concept_id = str(uuid.uuid4())[:8]
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


class NcdEngine:
    """Stateful NCD engine supporting incremental real-time concept detection."""

    def __init__(self, config: NcdConfig | None = None):
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

        # P0: raw 768-dim embeddings per period (for k-NN novelty)
        self._period_raw_embeddings: list[np.ndarray] = []
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
                    verbose=False,
                    low_memory=True,
                )
                # Refit on all accumulated raw embeddings
                all_raw = np.concatenate(self._period_raw_embeddings + [embeddings])
                self._reducer.fit(np.ascontiguousarray(all_raw, dtype=np.float32))
            return

        logger.info("Fitting UMAP reducer on %d embeddings", len(embeddings))
        self._reducer = umap.UMAP(
            n_components=self.config.UMAP_N_COMPONENTS,
            n_neighbors=min(15, len(embeddings) - 1),
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
        reference_embeddings: np.ndarray | None,
    ) -> np.ndarray:
        """k-NN novelty score: mean cosine similarity to k nearest neighbors in reference.

        Low score = novel (new topic not seen before).
        Embeddings must be L2-normalized for cosine sim = dot product.
        """
        if reference_embeddings is None or len(reference_embeddings) == 0:
            return np.ones(len(current_embeddings))

        n_ref = len(reference_embeddings)
        k = max(1, min(self.config.KNN_K, n_ref))
        # Cosine similarity via dot product (embeddings are normalized)
        sim_matrix = current_embeddings @ reference_embeddings.T  # (n_current, n_ref)
        # For each current point, take top-k similarities and average
        top_k = np.partition(-sim_matrix, k - 1, axis=1)[:, :k]
        novelty_scores = (-top_k).mean(axis=1)  # mean similarity; low = novel
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

    def process_batch(self, batch: DocumentBatch) -> DetectionResult:
        """Process a batch of documents and detect emerging concepts."""
        start = time.time()
        self._ensure_model_loaded()

        docs = batch.documents
        period_id = batch.period_id or f"period_{len(self._period_ids)}"

        # Step 1: Split documents into sentence-level units
        if self.config.SENTENCE_LEVEL:
            units: list[str] = []
            unit_to_doc: list[int] = []
            for di, doc in enumerate(docs):
                for s in _split_sentences(doc.text):
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
        has_reference_embeddings = bool(self._period_raw_embeddings)
        if has_reference_embeddings:
            ref_embeddings = np.concatenate(self._period_raw_embeddings)
        else:
            ref_embeddings = None

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
        # GMM novel-only clustering below and by concept extraction in step 6)
        novelty_scores = self._compute_novelty_scores(raw_embeddings, ref_embeddings)
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

        for group in groups:
            unit_idx = set(group)
            if not unit_idx:
                continue

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
                strength=round(strength, 4),
                coordinates=[cx, cy],
                source=period_id,
                emerging=emerging,
                appearances=appearances,
            )
            new_concepts.append(concept)

            event_type = "new_concept" if is_novel else "concept_evolved"
            concept_updates.append(ConceptUpdate(event_type=event_type, concept=concept))

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
        self._period_raw_embeddings.append(raw_embeddings)
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
                "drift": round(drift, 4),
                "drift_alert": drift_alert,
                "cluster_mode": self.config.CLUSTER_MODE,
            },
        )

    def get_all_concepts(self) -> list[DetectedConcept]:
        """Return all detected concepts."""
        return self._detected_concepts

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
        }


# Singleton instance
_engine: NcdEngine | None = None


def get_engine() -> NcdEngine:
    global _engine
    if _engine is None:
        _engine = NcdEngine()
    return _engine
