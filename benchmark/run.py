"""Cycepta benchmark: replay threat streams and measure detection quality.

Metrics:
  - precision@K : fraction of *emerging* concepts the detector flags that match
                  ground-truth topics
  - recall@K    : fraction of ground-truth emerging topics that were flagged
  - lead time   : how far ahead of "mass adoption" a topic was first flagged
                  (periods, and days when the stream is weekly)

Datasets:
  --dataset toy        : clean 12-period stream (fast regression)
  --dataset realistic  : 52 weeks, 100-500 docs/wk, overlapping lexicon, noise,
                         dying topics, logistic growth (proxy for a real replay)
  --csv PATH           : replay a real CSV (columns: period,id,text,topic)

Engine mode: blob_log (default) or --mode gmm. Embeddings: deterministic fake
(default, no downloads) or --real (all-mpnet-base-v2 + UMAP).

Baselines: --baseline kmeans|bertopic|top2vec  (kmeans always runs if requested;
bertopic/top2vec need `pip install bertopic top2vec`). --all-baselines runs all.

Run:
  python benchmark/run.py
  python benchmark/run.py --dataset realistic
  python benchmark/run.py --real --dataset realistic --mode gmm --all-baselines
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ncdbody"))

from app.config import NcdConfig  # noqa: E402
from app.models import Document, DocumentBatch  # noqa: E402

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Topic:
    id: str
    seed: str          # keyword present in the document text for this topic
    start_period: int
    mass_period: int


@dataclass
class Stream:
    periods: list[list[Document]]
    mass_periods: dict[str, int]
    topic_index: dict[str, Topic]
    weekly: bool = False          # True => lead time in days = periods * 7

    @property
    def all_keywords(self) -> list[str]:
        kws = [t.seed for t in self.topic_index.values()]
        for st in _STABLE_KEYWORDS:
            if st not in kws:
                kws.append(st)
        return kws


_STABLE_KEYWORDS = ["ransomware", "patch tuesday", "ddos", "iot", "phishing", "zerotrust"]

# ---------------------------------------------------------------------------
# Toy dataset
# ---------------------------------------------------------------------------

_TOY_TOPICS = [
    Topic("zero_day", "zero-day", 5, 9),
    Topic("supply_chain", "supply chain", 6, 10),
    Topic("apt", "apt group", 7, 11),
    Topic("cred_phish", "phishing", 4, 8),
]


def _toy_doc(doc_id: str, keyword: str, period: int) -> Document:
    return Document(
        id=doc_id,
        source="synthetic",
        metadata={"topic": keyword},
        text=f"{keyword} incident report period {period}: {keyword} activity flagged.",
    )


def build_toy_stream(periods: int = 12, docs_per_period: int = 60, seed: int = 7) -> Stream:
    rng = np.random.RandomState(seed)
    stable = ["ransomware", "patch tuesday", "ddos", "iot"]
    stream = []

    for p in range(periods):
        docs = []
        for t in stable:
            for _ in range(rng.randint(3, 7)):
                docs.append(_toy_doc(f"s-{t}-{p}-{len(docs)}", t, p))
        for t in _TOY_TOPICS:
            occ = 0
            if p >= t.mass_period:
                occ = rng.randint(8, 14)
            elif p == t.start_period:
                occ = rng.randint(1, 3)
            elif p > t.start_period:
                occ = rng.randint(2, 6)
            for _ in range(occ):
                docs.append(_toy_doc(f"e-{t.id}-{p}-{len(docs)}", t.seed, p))
        stream.append(docs)

    return Stream(
        periods=stream,
        mass_periods={t.id: t.mass_period for t in _TOY_TOPICS},
        topic_index={t.id: t for t in _TOY_TOPICS},
        weekly=False,
    )


# ---------------------------------------------------------------------------
# Realistic dataset: 52 weeks, overlap, noise, dying topics, logistic growth
# ---------------------------------------------------------------------------

@dataclass
class _Emergent:
    id: str
    seed: str
    ramp_start: int
    ramp_end: int
    mass: int
    decays: bool = False
    alias: str | None = None     # secondary keyword creating overlap with stable topics


def build_realistic_stream(periods: int = 52, seed: int = 11) -> Stream:
    rng = np.random.RandomState(seed)

    stable = ["ransomware", "patch tuesday", "ddos", "iot", "phishing", "zerotrust"]
    dying = {"zerotrust": 22}     # dies out, must stay unflagged

    emergents = [
        _Emergent("cve_rce", "critical rce", 5, 12, 40, alias="unauthenticated code execution"),
        _Emergent("supply_chain", "supply chain", 8, 16, 34, alias="software vendor breach"),
        _Emergent("apt_state", "apt state actor", 12, 20, 28, alias="nation-state campaign"),
        _Emergent("cloud_exfil", "cloud exfiltration", 16, 25, 36, alias="data breach"),
        _Emergent("ai_prompt", "ai prompt injection", 20, 30, 30, alias="llm security"),
        _Emergent("ics_ot", "ics ot breach", 24, 34, 26, decays=True),
    ]
    stream: list[list[Document]] = []

    for p in range(periods):
        base = rng.randint(100, 500)
        docs: list[Document] = []
        di = 0

        for t in stable:
            if t in dying and p >= dying[t]:
                continue
            n = max(1, int(base * rng.uniform(0.05, 0.11)))
            for _ in range(n):
                docs.append(Document(id=f"st-{t}-{p}-{di}", source="synthetic",
                                     metadata={"topic": t},
                                     text=f"{t} incident report week {p}: {t} activity flagged."))
                di += 1

        for em in emergents:
            if p < em.ramp_start:
                continue
            w = (p - em.ramp_start) / max(1.0, em.ramp_end - em.ramp_start)
            frac = 1.0 / (1.0 + np.exp(-1.0 * (w - 1.2)))       # sigmoid ramp
            n = max(1, int(em.mass * frac * rng.uniform(0.7, 1.3)))
            if em.decays and p > em.ramp_end + 6:
                n = int(n * max(0.1, 1.0 - (p - em.ramp_end - 6) / 10))
            for _ in range(n):
                text = f"{em.seed} campaign report week {p}: {em.seed} observed."
                if em.alias:
                    text += f" {em.seed}: {em.alias}."
                if p > em.ramp_end:
                    text += f" {em.seed}: widespread exploitation reported."
                docs.append(Document(id=f"em-{em.id}-{p}-{di}", source="synthetic",
                                     metadata={"topic": em.id}, text=text))
                di += 1

        noise_n = int(base * rng.uniform(0.08, 0.2))
        for i in range(noise_n):
            docs.append(Document(id=f"nz-{p}-{i}", source="synthetic",
                                 metadata={"topic": "noise"},
                                 text=f"transient threat note #{p}-{i} unassociated activity mint-knarf."))
            di += 1

        stream.append(docs)

    topics = [Topic(em.id, em.seed, em.ramp_start, em.ramp_end)
              for em in emergents if em.ramp_end < periods]
    mass_periods = {t.id: t.mass_period for t in topics}
    return Stream(periods=stream, mass_periods=mass_periods,
                  topic_index={t.id: t for t in topics}, weekly=True)


def load_csv_stream(path: str, mass_floor: int = 40) -> Stream:
    """Replay a real CSV. Columns: period, id, text, topic(optional)."""
    rows: dict[int, list[tuple[str, str, str]]] = defaultdict(list)
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            rows[int(r["period"])].append((r["id"], r["text"], r.get("topic", "")))

    periods = max(rows) + 1 if rows else 0
    stream: list[list[Document]] = []
    counts: dict[str, int] = defaultdict(int)
    mass_periods: dict[str, int] = {}
    topics: dict[str, Topic] = {}

    for p in range(periods):
        docs = []
        for did, text, topic in rows.get(p, []):
            st = (topic or text[:40])
            topics.setdefault(st, Topic(st, st, 0, periods))
            docs.append(Document(id=did, source="csv", metadata={"topic": st}, text=text))
        stream.append(docs)
        for d in docs:
            st = d.metadata["topic"]
            counts[st] += 1
            if counts[st] >= mass_floor and st not in mass_periods:
                mass_periods[st] = p

    mass_topics = {st: t for st, t in topics.items() if st in mass_periods}
    return Stream(periods=stream, mass_periods=mass_periods, topic_index=mass_topics, weekly=True)


# ---------------------------------------------------------------------------
# Deterministic fake embeddings (shared keyword-space, order-independent)
# ---------------------------------------------------------------------------

class KeywordSpace:
    """Maps keywords -> fixed 32-dim basis and keywords -> fixed 2D slot."""

    def __init__(self, keywords: list[str]):
        self.basis: dict[str, np.ndarray] = {}
        for kw in keywords:
            rng = np.random.RandomState(_kw_seed(kw))
            v = rng.normal(0, 1, 32)
            self.basis[kw] = v / (np.linalg.norm(v) + 1e-9)
        self.coords: dict[str, np.ndarray] = {}
        for kw in keywords:
            rng = np.random.RandomState(_kw_seed("slot:" + kw))
            x = 25 + rng.uniform(0, 1) * 350
            y = 25 + rng.uniform(0, 1) * 350
            self.coords[kw] = np.array([x, y])

    def keywords_in(self, text: str) -> list[str]:
        return [kw for kw in self.basis if kw in text]


def _kw_seed(kw: str) -> int:
    acc = 0
    for ch in kw:                       # deterministic (no PYTHONHASHSEED dependence)
        acc = (acc * 31 + ord(ch)) & 0xFFFFFFFF
    return acc


class KeywordEmbedder:
    def __init__(self, space: KeywordSpace):
        self.space = space

    def encode(self, texts, **kwargs):
        out = []
        for t in texts:
            keys = self.space.keywords_in(t)
            if keys:
                v = sum(self.space.basis[k] for k in keys) / len(keys)
            else:
                v = np.zeros(32)
                corner = np.random.RandomState(_kw_seed("noise:" + t)).normal(0, 1, 32)
                v = corner
            noise = np.random.RandomState(_kw_seed("n:" + t)).normal(0, 0.08, 32)
            v = v + noise
            out.append(v)
        a = np.asarray(out, dtype=np.float32)
        return a / (np.linalg.norm(a, axis=1, keepdims=True) + 1e-9)


class KeywordReducer:
    def __init__(self, space: KeywordSpace):
        self.space = space

    def fit(self, X):
        pass

    def transform(self, X):
        basis = list(self.space.basis.values())
        sims = X @ np.asarray(basis).T          # (n, n_kw)
        best = np.argmax(sims, axis=1)
        conf = sims.max(axis=1)
        coords = np.array([self.space.coords[kw] for kw in self.space.basis])
        out = coords[best].astype(np.float64)
        # noise docs (no real keyword match) are scattered across the map so
        # they stay transient instead of stacking onto a real topic slot
        low = conf < 0.5
        if low.any():
            for i in np.where(low)[0]:
                rng = np.random.RandomState(int((X[i][0] * 1e6) % (2 ** 31)))
                out[i] = [25 + rng.uniform(0, 1) * 350, 25 + rng.uniform(0, 1) * 350]
        return out + np.random.RandomState(1).uniform(-2, 2, out.shape)


class RealPipeline:
    """Real embeddings (always) + UMAP reduction for the engine."""

    def __init__(self):
        self.embedder = None

    def embed(self, texts):
        from sentence_transformers import SentenceTransformer
        if self.embedder is None:
            self.embedder = SentenceTransformer("sentence-transformers/all-mpnet-base-v2", device="cpu")
        return np.array(self.embedder.encode(texts, normalize_embeddings=True, batch_size=32))

    def encode(self, texts, **kwargs):
        return self.embed(texts)

    def reduce(self, embeddings):
        import umap
        reducer = umap.UMAP(n_components=2, n_neighbors=15, low_memory=True, random_state=42)
        return reducer.fit_transform(embeddings.astype(np.float32))


class _RealReducerAdapter:
    def __init__(self, pipeline: RealPipeline):
        self.pipeline = pipeline

    def fit(self, X):
        pass

    def transform(self, X):
        # engine stores current batch; we refit on everything accumulated so far
        self._buf = getattr(self, "_buf", [])
        self._buf.extend(X.tolist())
        allX = np.asarray(self._buf)
        coords = self.pipeline.reduce(allX)
        return coords[len(allX) - len(X):]


# ---------------------------------------------------------------------------
# Engine runner
# ---------------------------------------------------------------------------

def _make_pipeline(stream: Stream, real: bool):
    if real:
        return RealPipeline(), dict(real=True)
    space = KeywordSpace(stream.all_keywords)
    return type("P", (), {"embedder": KeywordEmbedder(space), "reducer": KeywordReducer(space), "space": space})(), \
        dict(real=False)


def run_engine_benchmark(stream: Stream, cluster_mode: str, real: bool) -> tuple[dict, dict]:
    from app.ncd_engine import NcdEngine

    cfg = NcdConfig()
    # Keep eval independent of ambient env and optional model files; these
    # match benchmark/wallclock.py and the production defaults.
    cfg.USE_DIFF = True
    cfg.UMAP_REFIT_INTERVAL = 0
    cfg.UMAP_RANDOM_STATE = 42
    cfg.UMAP_N_JOBS = 1
    cfg.JUDGE_ENABLED = False
    cfg.CLUSTER_MODE = cluster_mode
    cfg.GMM_MIN_SAMPLES = int(os.getenv("NCD_GMM_MIN_SAMPLES", "2"))
    if real:
        cfg.WINDOW_SIZE = 8
        # Real embeddings have a much higher absolute similarity baseline than
        # the synthetic keyword space; absolute thresholds don't transfer, so
        # fall back to the embedding-scale-agnostic adaptive novelty gate.
        cfg.NOVELTY_ADAPTIVE = True

    pipeline, _ = _make_pipeline(stream, real)
    engine = NcdEngine(cfg)
    engine._model = pipeline if real else pipeline.embedder
    engine._reducer = _RealReducerAdapter(pipeline) if real else pipeline.reducer
    engine._fitted = True
    engine._ensure_reducer_fitted = lambda e, *a: None

    flagged: dict[str, list[int]] = defaultdict(list)
    emerging_flags = 0
    t0 = time.time()
    for p, docs in enumerate(stream.periods):
        if not docs:
            continue
        result = engine.process_batch(DocumentBatch(documents=docs, period_id=f"period_{p}"))
        for c in result.concepts:
            if not c.emerging:
                continue
            emerging_flags += 1
            topic = _match_topic(" ".join(c.sentences), stream)
            if p >= 1:
                flagged[topic].append(p)
    elapsed = time.time() - t0

    stats = engine.get_stats()
    return _stats_metrics(stream, flagged), {
        "runtime_s": round(elapsed, 2),
        "total_concepts": stats["total_concepts"],
        "emerging_flags": emerging_flags,
        "drift_max": stats["drift_max"],
        "drift_count": stats["drift_count"],
    }


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------

def _embed_all(stream: Stream, real: bool) -> list[np.ndarray]:
    if real:
        pipe, _ = _make_pipeline(stream, True)
        return [pipe.embed([d.text for d in docs]) for docs in stream.periods]
    pipe, _ = _make_pipeline(stream, False)
    return [pipe.embedder.encode([d.text for d in docs]) for docs in stream.periods]


def run_kmeans_baseline(stream: Stream, real: bool) -> dict[str, list[int]]:
    """Streaming k-means + centroid novelty + 2-period growth gate."""
    from sklearn.cluster import KMeans

    embeddings = _embed_all(stream, real)
    hist_centroids: list[np.ndarray] = []
    flagged: dict[str, list[int]] = defaultdict(list)
    streak: dict[str, int] = defaultdict(int)

    for p, docs in enumerate(stream.periods):
        if not docs:
            continue
        X = embeddings[p]
        k = max(2, min(8, int(np.sqrt(len(X)))))
        km = KMeans(n_clusters=k, n_init=3, random_state=42).fit(X)
        centroids = km.cluster_centers_
        norms = np.linalg.norm(centroids, axis=1, keepdims=True) + 1e-9
        centroids = centroids / norms

        for ci in range(k):
            members = np.where(km.labels_ == ci)[0]
            if len(members) < 3:
                continue
            novelty = 1.0 - (max((c @ centroids[ci]) for c in hist_centroids) if hist_centroids else 0.0)
            topic = _majority_topic([docs[i].metadata.get("topic", "") for i in members], stream)
            if topic is None:
                continue
            if novelty > 0.35:
                streak[topic] += 1
                if streak[topic] >= 2:
                    flagged[topic].append(p)
            else:
                streak[topic] = 0
        hist_centroids.extend(centroids)
        hist_centroids = hist_centroids[-200:]

    return {k: v for k, v in flagged.items()}


def _majority_topic(metadata: list[str], stream: Stream) -> str | None:
    counts = Counter(metadata)
    top = counts.most_common(1)
    if not top:
        return None
    label = top[0][0]
    if label in stream.topic_index:
        return label
    if label in _STABLE_KEYWORDS or label == "noise":
        return "stable:" + label
    return None


def run_windowed_baseline(stream: Stream, kind: str) -> dict[str, list[int]]:
    """Rolling-window document-topic model over a 6-week window; first-flag timing."""
    if kind == "bertopic":
        from bertopic import BERTopic
        words = ["supply chain", "apt state actor", "critical rce"]
        flagged: dict[str, list[int]] = defaultdict(list)
        for w0 in range(0, len(stream.periods), 2):
            w1 = min(len(stream.periods), w0 + 6)
            docs: list[str] = []
            for p in range(w0, w1):
                docs.extend(d.text for d in stream.periods[p])
            if len(docs) < 10:
                continue
            model = BERTopic(verbose=False, min_topic_size=3)
            topics, _ = model.fit_transform(docs)
            topic_docs: dict[int, list[str]] = defaultdict(list)
            for di, ti in enumerate(topics):
                if ti >= 0:
                    topic_docs[ti].append(docs[di])
            for members in topic_docs.values():
                if len(members) < 3:
                    continue
                sample = " ".join(members[:40]).lower()
                for tid, topic in stream.topic_index.items():
                    if topic.seed.lower()[:20] in sample and not flagged[tid]:
                        flagged[tid].append(w1 - 1)
        return dict(flagged)

    elif kind == "top2vec":
        from top2vec import Top2Vec
        flagged = {}
        for w0 in range(0, len(stream.periods), 2):
            w1 = min(len(stream.periods), w0 + 6)
            docs = [d.text for p in range(w0, w1) for d in stream.periods[p]]
            if len(docs) < 10:
                continue
            model = Top2Vec(documents=docs, workers=1, speed="learn")
            _, topic_nums = model.get_topic_sizes()
            for tn in topic_nums[: min(12, len(topic_nums))]:
                topic_words = model.get_topics(tn)[0][:5]
                sample = " ".join(topic_words).lower()
                for tid, topic in stream.topic_index.items():
                    if topic.seed.lower()[:20] in sample and tid not in flagged:
                        flagged[tid] = [w1 - 1]
        return flagged

    raise ValueError(kind)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def _stats_metrics(stream: Stream, flagged: dict[str, list[int]]) -> dict:
    mass_topics = set(stream.mass_periods) if stream.mass_periods else set(stream.topic_index)
    detected = {k for k in flagged if flagged[k]}
    tp = detected & mass_topics
    fp = detected - mass_topics
    fn = mass_topics - detected
    precision = len(tp) / max(1, len(detected))
    recall = len(tp) / max(1, len(mass_topics))
    f1 = 2 * precision * recall / (precision + recall + 1e-9)

    lead = {}
    for tid, mp in stream.mass_periods.items():
        if flagged.get(tid):
            d = mp - min(flagged[tid])
            if d >= 0:
                lead[tid] = d
    avg_lead = float(np.mean(list(lead.values()))) if lead else -1.0
    return {
        "precision@K": round(precision, 4),
        "recall@K": round(recall, 4),
        "F1": round(f1, 4),
        "avg_lead_periods": round(avg_lead, 2),
        "avg_lead_days": round(avg_lead * 7, 1) if stream.weekly else round(avg_lead, 2),
        "tp": sorted(tp),
        "fp": sorted(fp),
        "fn": sorted(fn),
        "lead_periods": {k: v for k, v in sorted(lead.items())},
    }


def _match_topic(joined: str, stream: Stream) -> str | None:
    lowered = joined.lower()
    for tid, topic in stream.topic_index.items():
        if topic.seed in lowered:
            return tid
    for st in _STABLE_KEYWORDS:
        if st in lowered:
            return "stable:" + st
    return None


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Cycepta benchmark")
    ap.add_argument("--real", action="store_true", help="real embeddings + UMAP")
    ap.add_argument("--mode", default="blob", choices=["blob", "gmm"])
    ap.add_argument("--dataset", default="toy", choices=["toy", "realistic"])
    ap.add_argument("--periods", type=int, default=12)
    ap.add_argument("--docs-per-period", type=int, default=60)
    ap.add_argument("--seed", type=int, default=None,
                    help="stream RNG seed (dev=11 for realistic, 7 for toy; test=23)")
    ap.add_argument("--csv", default=None, help="real CSV replay (period,id,text,topic)")
    ap.add_argument("--mass-floor", type=int, default=40)
    ap.add_argument("--baseline", action="append", default=[], choices=["kmeans", "bertopic", "top2vec"])
    ap.add_argument("--all-baselines", action="store_true", help="run kmeans+bertopic+top2vec")
    ap.add_argument("--install-baselines", action="store_true", help="pip install bertopic top2vec first")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.install_baselines:
        os.system("pip install -q bertopic top2vec")

    if args.csv:
        stream = load_csv_stream(args.csv, args.mass_floor)
    elif args.dataset == "realistic":
        stream = build_realistic_stream(periods=52, seed=args.seed if args.seed is not None else 11)
    else:
        stream = build_toy_stream(periods=args.periods, docs_per_period=args.docs_per_period,
                                  seed=args.seed if args.seed is not None else 7)

    name = f"engine[{args.mode}{'+real' if args.real else ''}]"
    metrics, extra = run_engine_benchmark(stream, args.mode, args.real)
    results = {name: {"metrics": metrics, "engine": extra}}

    baselines = args.baseline
    if args.all_baselines:
        baselines = ["kmeans", "bertopic", "top2vec"]

    for b in baselines:
        try:
            flagged = run_kmeans_baseline(stream, args.real) if b == "kmeans" \
                else run_windowed_baseline(stream, b)
            results[f"baseline:{b}"] = {"metrics": _stats_metrics(stream, flagged)}
        except Exception as ex:  # missing optional deps etc.
            results[f"baseline:{b}"] = {"error": f"{type(ex).__name__}: {ex}"}

    report = {
        "dataset": args.csv or args.dataset,
        "periods": len(stream.periods),
        "weekly": stream.weekly,
        "mass_topics": sorted(stream.mass_periods),
        "results": results,
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 60)
        print(f"Cycepta benchmark  dataset={report['dataset']}  periods={report['periods']}")
        print("=" * 60)
        for rname, r in results.items():
            print(f"\n[{rname}]")
            if "error" in r:
                print(f"  skipped: {r['error']}")
                continue
            for k, v in r["metrics"].items():
                print(f"  {k}: {v}")
            eng = r.get("engine", {})
            if eng:
                print(f"  runtime: {eng['runtime_s']}s  emerging_flags: {eng['emerging_flags']}  "
                      f"drift_max: {eng['drift_max']:.3f}")


if __name__ == "__main__":
    main()