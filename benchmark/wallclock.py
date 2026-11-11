#!/usr/bin/env python3
"""Wall-clock eval harness: replay the real NVD CVE stream and measure how many
DAYS before real-world adoption the engine flags an emerging concept.

Stream & labels
---------------
  stream/data/cve_stream.csv : one doc per CVE (2023-01-01 .. now), weekly
      periods (period = weeks since 2023-01-01), text = "<cve_id>: <desc>".
  stream/data/kev.json       : CISA Known-Exploited-Vulnerabilities catalog.
      Ground truth "adopted" label == the concept contains >= 1 KEV'd CVE.

Replay
------
The FULL stream is always replayed from period 0 (the engine warms up on real
history); the --split filter only restricts WHICH events are scored.

  dev  : adoption AND flag events dated in [2023-01-01, 2025-01-01)
  test : adoption AND flag events dated in [2025-01-01, 2026-01-01)
  (events in 2026 are scored by neither split - they are held out.)

Concept -> CVE mapping
----------------------
The engine splits each document into sentences (`_split_sentences`) and
returns concepts with member `sentences`. The harness pre-computes the exact
same split per period (sent_map: sentence text -> doc indices) and maps each
returned concept sentence back to the period's documents by EXACT string
membership. The engine's internal unit count (after its boilerplate filter and
per-batch sentence dedupe) is asserted against
`result.heatmap_diff_summary["units"]` every period; the check must stay at 0
mismatches or attribution is suspect. Only ~30% of CVE texts are a
single sentence (version numbers like "10.0.0. This issue..." and "e.g. "
splits are common), so sentence text is frequently a SUBSTRING of the doc
text -- exact matching against the same splitter is what makes member
attribution reliable, not sentence == document.
NOTE: concepts are emitted with the engine's MAX_SENTENCES_PER_CONCEPT cap;
this harness raises that cap (see deviations) so member attribution is
complete for the emitting period. NOTE 2: blob concepts collect sentences from
the blob's heatmap bin +/- 1 (engine behaviour), so member sets can include
semantically adjacent CVEs of the same week.

Entities / flags
----------------
An "entity" is one engine concept_id. Primary (blob/GMM) concepts keep a
stable concept_id across periods (engine graph tracking), so their members
accumulate over the whole replay. Burst-tier concepts get a FRESH uuid per
emission, so each burst emission is its own entity (members = that week's
docs only). Entity member sets are disjoint by construction (units are never
absorbed by two concepts, and a CVE belongs to exactly one week).
A concept is "flagged" in the first period in which it was emitted with
emerging=True (primary gate OR burst tier - burst is always emerging=True).
Flag date := MAX document timestamp of that period (the moment the week's
data was observable), not the week start - conservative.

Adoption label
--------------
adopted(c) := any member CVE is in KEV  OR  the entity reaches MASS_FLOOR=40
member docs. adoption_date := min(KEV dateAdded over members, ts of the 40th
member doc) - i.e. the EARLIEST of the two signals; the label kind is
recorded per entity in the metrics JSON.

Score
-----
  lead_c      = max(0, (adoption_date - first_flag_date).days) for every
                adopted concept c; lead_c = 0 if never flagged; clamped at 0
                if the flag came AFTER adoption (documented clamp: late ==
                missed, no negative credit).
  guardrail   = (# flagged entities in the split that are "real") /
                (# flagged entities in the split), clamped to [0, 1] as-is;
                "real" := >= 1 KEV'd member CVE, OR the entity reaches
                MASS_FLOOR=40 member docs within MASS_WINDOW_WEEKS=8 weeks
                after the flag (members counted by first-appeared period).
                0 flagged entities in the split => guardrail = 0.
  score       = mean(lead_c over ALL adopted entities in the split) * guardrail
                (no adopted entities in the split => score 0).

The harness pins the production representation explicitly (not inherited from
the shell environment): USE_DIFF=True, UMAP_REFIT_INTERVAL=0,
UMAP_RANDOM_STATE=42, UMAP_N_JOBS=1. Everything else is the production
default, in particular:
  * NOVELTY_ADAPTIVE stays False and WINDOW_SIZE stays 10, unlike
    benchmark/run.py's --real mode which sets adaptive+8. The absolute
    NOVELTY_THRESHOLD gate and the burst tier (NCD_BURST_TIER, default on,
    asserted below) are exactly what production runs.
  * cluster mode = blob (production default).
Deviation 1: MAX_SENTENCES_PER_CONCEPT 50 -> 10000. Detection is unaffected;
  it only controls how many member sentences the engine RETURNS per concept,
  i.e. how much of the concept the harness can attribute to CVE ids.
Deviation 2: JUDGE_ENABLED False. The judge needs optional local LLM weights;
  scoring must not depend on whether those files exist on the eval machine.
Optional CLI overrides (--novelty-threshold, --adaptive, --cluster-mode) exist
for engine experiments and are recorded verbatim in the metrics JSON; the
defaults are the production values.

Embeddings
----------
all-mpnet-base-v2 (cpu, normalized), cached in stream/data/emb_store/ as a
disk-backed row store: vecs.npy float32 [capacity, 768] and keys.npy U40
(sha1(text) hex) both created via numpy.lib.format.open_memmap, plus a small
meta.json {"n": live_rows, "capacity": ...} rewritten atomically on each
checkpoint. RAM holds only a key -> row-index dict (strings -> ints); encode()
fancy-indexes the memmap for one period-sized copy. New rows are appended
rows n..n+k (the store starts at 262144 rows and doubles when full, so appends
never rewrite it) and a checkpoint is O(new rows): memmap flush + meta.json.
Only texts missing from the cache are encoded on a replay; the cache is
checkpoint-saved while embedding and at the end (never on a pure replay).
A legacy stream/data/emb_cache.npz is migrated once into the store in
<=50k-row chunks and renamed emb_cache.npz.migrated (kept as backup, not
deleted); every later run reads the store.
--rebuild-cache wipes the store and forces re-embedding everything.

Known limitations (documented, by design)
-----------------------------------------
  * Identical texts (e.g. "Rejected reason: ..." boilerplate CVEs) share a
    hash and a sentence; if such a sentence lands in a concept, ALL docs
    carrying it become members (exact sentence membership).
  * A cached replay of the FULL stream is expected to stay fast, but the
    engine's k-NN novelty and drift computations grow with total history
    (O(T^2) over periods); actual runtime is printed and recorded.

Usage:
  python3 benchmark/wallclock.py --split dev --viz out.png --metrics-json m.json
  python3 benchmark/wallclock.py --split test
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timezone

import numpy as np

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "ncdbody"))

from app.config import NcdConfig  # noqa: E402
from app.input_hygiene import is_boilerplate  # noqa: E402
from app.models import Document, DocumentBatch  # noqa: E402
from app.ncd_engine import NcdEngine, _split_sentences  # noqa: E402

STREAM_START = date(2023, 1, 1)
MASS_FLOOR = 40            # member docs that define the secondary "mass adoption" signal
MASS_WINDOW_WEEKS = 8      # weeks after a flag within which MASS_FLOOR counts as "real"
SPLIT_WINDOWS = {          # [lo, hi) by date
    "dev": (date(2023, 1, 1), date(2025, 1, 1)),
    "test": (date(2025, 1, 1), date(2026, 1, 1)),
}
EMBED_MODEL = "sentence-transformers/all-mpnet-base-v2"

# Embedding row-store layout (see module docstring "Embeddings")
EMB_STORE_DIRNAME = "emb_store"
MIN_STORE_CAPACITY = 262144    # initial #rows; appends never rewrite the file
EMB_COPY_CHUNK = 50_000        # max rows copied per chunk (growth / migration)


# ---------------------------------------------------------------------------
# Stream / KEV loading
# ---------------------------------------------------------------------------

@dataclass
class Doc:
    cve_id: str
    text: str
    ts: datetime
    period: int


def load_stream(path: str) -> tuple[dict[int, list[Doc]], dict[int, datetime], dict]:
    if not os.path.exists(path):
        raise SystemExit(f"FATAL: stream CSV {path} not found. "
                         f"Run stream/nvd_backfill.py && stream/build_stream.py first.")
    periods: dict[int, list[Doc]] = defaultdict(list)
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        required = {"period", "id", "text", "ts"}
        if not required.issubset(reader.fieldnames or []):
            raise SystemExit(f"FATAL: {path} has columns {reader.fieldnames}, need {sorted(required)}")
        n = 0
        for r in reader:
            ts = datetime.fromisoformat(r["ts"])
            period = int((ts.date() - STREAM_START).days // 7)
            if period != int(r["period"]):
                raise SystemExit(f"FATAL: period mismatch for {r['id']}: csv={r['period']} computed={period}")
            periods[period].append(Doc(r["id"], r["text"], ts, period))
            n += 1
    if n < 10_000:
        raise SystemExit(f"FATAL: only {n} docs in {path}; the stream looks empty/incomplete.")
    for p in periods:
        periods[p].sort(key=lambda d: (d.ts, d.cve_id))
    period_ts = {p: docs[-1].ts for p, docs in periods.items()}  # max doc ts per week
    info = {"docs": n, "weeks": len(periods), "min_period": min(periods), "max_period": max(periods)}
    return periods, period_ts, info


def load_kev(path: str) -> dict[str, datetime]:
    if not os.path.exists(path):
        raise SystemExit(f"FATAL: KEV catalog {path} not found. Run stream/build_stream.py first.")
    with open(path, encoding="utf-8") as fh:
        catalog = json.load(fh)
    kev: dict[str, datetime] = {}
    for v in catalog.get("vulnerabilities", []):
        cid, added = v.get("cveID"), v.get("dateAdded")
        if cid and added:
            kev[cid] = datetime.fromisoformat(added)
    if len(kev) < 1000:
        raise SystemExit(f"FATAL: KEV catalog at {path} has only {len(kev)} entries; looks broken.")
    return kev


def sha1_hex(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Embedding cache
# ---------------------------------------------------------------------------

class CachedEmbedder:
    """drop-in replacement for engine.embed_texts' SentenceTransformer call.

    Returns L2-normalized 768-d float32 rows for every input text, embedding
    only cache misses and checkpointing the memmap row store while embedding.
    RAM holds only a key -> row-index dict (strings -> ints); the rows live in
    a disk-backed memmap, so a load is O(index) in RAM and a checkpoint is
    O(new rows since the last one), never O(the whole cache).
    """

    def __init__(self, cache_path: str, model_name: str = EMBED_MODEL,
                 rebuild: bool = False, save_every_s: float = 180.0,
                 min_new_to_save: int = 8000, store_dir: str | None = None):
        self.cache_path = cache_path
        # Store directory: sibling emb_store/ of the cache path (overridable
        # via arg or WALLCLOCK_EMB_STORE, e.g. for tests on temp copies).
        self.store_dir = (store_dir
                          or os.environ.get("WALLCLOCK_EMB_STORE")
                          or os.path.join(os.path.dirname(os.path.abspath(cache_path)),
                                          EMB_STORE_DIRNAME))
        self.vecs_path = os.path.join(self.store_dir, "vecs.npy")
        self.keys_path = os.path.join(self.store_dir, "keys.npy")
        self.meta_path = os.path.join(self.store_dir, "meta.json")
        self.model_name = model_name
        # Robustness knobs (default behavior unchanged): hosts that kill
        # background processes can tighten checkpointing via env.
        self.save_every_s = float(os.environ.get("WALLCLOCK_SAVE_EVERY_S", save_every_s))
        self.min_new_to_save = int(os.environ.get("WALLCLOCK_MIN_NEW_TO_SAVE", min_new_to_save))
        self.idx: dict[str, int] = {}   # sha1-key -> row index (the only per-row RAM state)
        self.n = 0                      # live rows
        self.capacity = 0               # rows the store file can hold
        self._vecs: np.memmap | None = None
        self._keys: np.memmap | None = None
        self.cache_load_s = 0.0
        self.stats = {"texts_requested": 0, "cache_hits": 0, "new_texts_embedded": 0,
                      "cache_saves": 0, "encode_s": 0.0}
        if rebuild:
            self._wipe_store()
        elif os.path.exists(self.vecs_path):
            t0 = time.time()
            self._open_store()
            self.cache_load_s = time.time() - t0
        elif os.path.exists(cache_path):
            t0 = time.time()
            self._migrate_npz(cache_path)
            self.cache_load_s = time.time() - t0
        self._model = None
        self._dirty = False
        self._last_save = time.time()

    # ------------------------------------------------------------------
    # store internals
    # ------------------------------------------------------------------

    def _load_memmaps(self):
        """(Re)open the store files read-write; capacity follows vecs.npy."""
        self._vecs = np.load(self.vecs_path, mmap_mode="r+")
        self._keys = np.load(self.keys_path, mmap_mode="r+")
        self.capacity = int(self._vecs.shape[0])

    def _close_memmaps(self):
        for mm in (self._vecs, self._keys):
            if mm is not None:
                try:
                    mm.flush()
                    mm._mmap.close()
                except (AttributeError, ValueError, OSError):
                    pass
        self._vecs = self._keys = None

    def _create_store_files(self, capacity: int):
        """Create fresh vecs/keys memmaps and install them as the store."""
        os.makedirs(self.store_dir, exist_ok=True)
        tmp_vecs = f"{self.vecs_path}.{os.getpid()}.tmp"
        tmp_keys = f"{self.keys_path}.{os.getpid()}.tmp"
        mv = np.lib.format.open_memmap(tmp_vecs, mode="w+", dtype=np.float32,
                                       shape=(capacity, 768))
        mk = np.lib.format.open_memmap(tmp_keys, mode="w+", dtype="U40",
                                       shape=(capacity,))
        mv.flush()
        mk.flush()
        del mv, mk
        os.replace(tmp_vecs, self.vecs_path)
        os.replace(tmp_keys, self.keys_path)
        self._load_memmaps()

    def _open_store(self):
        """Open an existing store and rebuild the key -> row index (O(n) small
        strings). meta.json normally carries n; if it is missing or stale
        (crash between a memmap flush and the meta write, or a capacity
        growth interrupted between the two file replaces) we recover n from
        the keys file itself - unused rows are ''."""
        self._vecs = np.load(self.vecs_path, mmap_mode="r+")
        self.capacity = int(self._vecs.shape[0])
        if not os.path.exists(self.keys_path):
            raise RuntimeError(f"embedding store {self.store_dir} has vecs.npy "
                               f"but no keys.npy")
        keys = np.load(self.keys_path, mmap_mode="r+")
        if int(keys.shape[0]) != self.capacity:
            # crash between the vecs/keys replaces of a growth: live rows are
            # intact in both, only the keys FILE is the old size -> rebuild it.
            old_n = int(keys.shape[0])
            tmp = f"{self.keys_path}.{os.getpid()}.tmp"
            mk = np.lib.format.open_memmap(tmp, mode="w+", dtype="U40",
                                           shape=(self.capacity,))
            for s in range(0, old_n, EMB_COPY_CHUNK):
                e = min(s + EMB_COPY_CHUNK, old_n)
                mk[s:e] = keys[s:e]
            mk.flush()
            del mk
            try:
                keys._mmap.close()
            except (AttributeError, ValueError, OSError):
                pass
            os.replace(tmp, self.keys_path)
            keys = np.load(self.keys_path, mmap_mode="r+")
        self._keys = keys
        n = -1
        if os.path.exists(self.meta_path):
            try:
                with open(self.meta_path, encoding="utf-8") as fh:
                    n = int(json.load(fh).get("n", -1))
            except (OSError, ValueError, json.JSONDecodeError):
                n = -1
        if not (0 <= n <= self.capacity):
            n = self._infer_n()
        self.n = n
        for i, k in enumerate(self._keys[:self.n].tolist()):
            self.idx[str(k)] = i

    def _infer_n(self) -> int:
        """First empty ('') row in keys.npy == number of live rows (append-only)."""
        k = self._keys
        total = int(k.shape[0])
        for s in range(0, total, EMB_COPY_CHUNK):
            e = min(s + EMB_COPY_CHUNK, total)
            empties = np.flatnonzero(k[s:e] == "")
            if empties.size:
                return s + int(empties[0])
        return total

    def _wipe_store(self):
        """--rebuild-cache: remove every store file so the next append starts fresh."""
        for p in (self.meta_path, self.vecs_path, self.keys_path):
            try:
                os.remove(p)
            except FileNotFoundError:
                pass
        self.idx.clear()
        self.n = self.capacity = 0
        self._vecs = self._keys = None

    def _migrate_npz(self, npz_path: str):
        """One-shot migration from the legacy compressed npz: copy rows into the
        memmap store in <=EMB_COPY_CHUNK-row chunks, write meta.json, then RENAME
        the npz to <path>.migrated (backup kept, never deleted)."""
        with np.load(npz_path, allow_pickle=False) as z:
            keys = z["keys"]                 # U40 [N], sha1(text) hex
            vecs = z["vecs"]                 # float32 [N, 768]
            n_total = int(len(keys))
            self._create_store_files(max(MIN_STORE_CAPACITY, n_total))
            for s in range(0, n_total, EMB_COPY_CHUNK):
                e = min(s + EMB_COPY_CHUNK, n_total)
                self._vecs[s:e] = vecs[s:e].astype(np.float32, copy=False)
                self._keys[s:e] = keys[s:e].astype("U40", copy=False)
            self._vecs.flush()
            self._keys.flush()
            self.idx = {str(k): i for i, k in enumerate(keys.tolist())}
        self.n = n_total
        self._write_meta()
        os.replace(npz_path, npz_path + ".migrated")
        print(f"[wallclock] embedding cache migrated: {n_total} rows "
              f"{npz_path} -> {self.store_dir} (npz kept as .migrated)",
              file=sys.stderr, flush=True)

    def _write_meta(self):
        """Atomically (tmp + os.replace) write {n, capacity}."""
        meta = {"n": int(self.n), "capacity": int(self.capacity)}
        tmp = f"{self.meta_path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(meta, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.meta_path)

    def _add_rows(self, texts, vecs: np.ndarray):
        """Append newly embedded rows: write rows n..n+k into the memmap,
        extend the index. Persistence happens at the next save()."""
        k = len(texts)
        if k == 0:
            return
        if self._vecs is None:
            self._create_store_files(MIN_STORE_CAPACITY)
        if self.n + k > self.capacity:
            self._grow(self.n + k)
        keys = [sha1_hex(t) for t in texts]
        start = self.n
        self._vecs[start:start + k] = np.asarray(vecs, dtype=np.float32)
        self._keys[start:start + k] = np.asarray(keys, dtype="U40")
        for i, key in enumerate(keys):
            self.idx[key] = start + i
        self.n += k
        self._dirty = True

    def _grow(self, needed: int):
        """Capacity growth: new larger memmaps (x2), live rows copied in
        <=EMB_COPY_CHUNK-row chunks, both files atomically replaced."""
        new_cap = max(self.capacity * 2, needed, MIN_STORE_CAPACITY)
        os.makedirs(self.store_dir, exist_ok=True)
        tmp_vecs = f"{self.vecs_path}.{os.getpid()}.tmp"
        tmp_keys = f"{self.keys_path}.{os.getpid()}.tmp"
        mv = np.lib.format.open_memmap(tmp_vecs, mode="w+", dtype=np.float32,
                                       shape=(new_cap, 768))
        mk = np.lib.format.open_memmap(tmp_keys, mode="w+", dtype="U40",
                                       shape=(new_cap,))
        for s in range(0, self.n, EMB_COPY_CHUNK):
            e = min(s + EMB_COPY_CHUNK, self.n)
            mv[s:e] = self._vecs[s:e]
            mk[s:e] = self._keys[s:e]
        mv.flush()
        mk.flush()
        del mv, mk
        self._close_memmaps()
        os.replace(tmp_vecs, self.vecs_path)
        os.replace(tmp_keys, self.keys_path)
        self._load_memmaps()
        self._dirty = True

    # ------------------------------------------------------------------
    # engine-facing API
    # ------------------------------------------------------------------

    def _ensure_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            cache_dir = os.environ.get("NCD_MODEL_CACHE",
                                       os.path.join(os.path.expanduser("~"), ".ncd", "models"))
            # WALLCLOCK_DEVICE (default "cpu"): "mps" accelerates embedding on
            # Apple Silicon. MPS fp32 output matches CPU (cos=1.0, spot-checked),
            # but re-verified against the CPU-embedded cache subset before use.
            device = os.environ.get("WALLCLOCK_DEVICE", "cpu")
            self._model = SentenceTransformer(self.model_name, device=device, cache_folder=cache_dir)
        return self._model

    def encode(self, texts, batch_size: int = 32, show_progress_bar: bool = False,
               normalize_embeddings: bool = True, **kwargs) -> np.ndarray:
        t0 = time.time()
        keys = [sha1_hex(t) for t in texts]
        self.stats["texts_requested"] += len(texts)
        self.stats["cache_hits"] += sum(1 for k in keys if k in self.idx)

        missing: list[str] = []
        seen: set[str] = set()
        for t, k in zip(texts, keys):
            if k not in self.idx and k not in seen:
                seen.add(k)
                missing.append(t)
        if missing:
            model = self._ensure_model()
            # WALLCLOCK_BATCH (default 64): peak RSS scales hard with encode
            # batch size (~16MB/sample at fp32 on CPU); 16 keeps the whole
            # embedding phase under ~1.35GB RSS, within the 1.5GB budget.
            batch = int(os.environ.get("WALLCLOCK_BATCH", "64"))
            vecs = model.encode(missing, batch_size=batch, show_progress_bar=False,
                                normalize_embeddings=True)
            self._add_rows(missing, vecs)
            self.stats["new_texts_embedded"] += len(missing)
            if (len(missing) >= self.min_new_to_save
                    or time.time() - self._last_save >= self.save_every_s):
                self.save()
        self.stats["encode_s"] += time.time() - t0
        if not keys:
            return np.zeros((0, 768), dtype=np.float32)
        # fancy-index the memmap: one period-sized copy (~MBs), never the store
        return np.asarray(self._vecs[[self.idx[k] for k in keys]], dtype=np.float32)

    def save(self, final: bool = False):
        """Checkpoint the embedding store.

        Cheap by construction: rows were already written into the memmap as
        they were embedded, so a checkpoint is a memmap flush plus an atomic
        meta.json rewrite - O(new rows), not O(all). Two processes may share
        the store path (coordinated runs): appends are disjoint, memmap flush
        is idempotent, meta.json is replaced atomically, and each process
        keeps its own live n/index. A failed CHECKPOINT must never kill a
        multi-hour replay (new embeddings would be lost with it) - it warns
        and stays dirty for the next checkpoint; the FINAL save (end of run)
        raises loudly instead.
        """
        if not self._dirty:
            return
        last_err: Exception | None = None
        for attempt in range(5):
            try:
                if self._vecs is None:
                    self._create_store_files(MIN_STORE_CAPACITY)
                else:
                    self._vecs.flush()
                    self._keys.flush()
                self._write_meta()
                self.stats["cache_saves"] += 1
                self._dirty = False
                self._last_save = time.time()
                return
            except Exception as e:  # noqa: BLE001 - retry, then decide by finality
                last_err = e
                time.sleep(1.0)
        if final:
            raise RuntimeError(
                f"embedding cache final save failed after 5 attempts "
                f"({self.store_dir}): {last_err}") from last_err
        print(f"[wallclock] WARNING: embedding checkpoint save failed "
              f"({last_err}); will retry at next checkpoint", file=sys.stderr,
              flush=True)
        self._last_save = time.time()  # throttle the failing path


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

@dataclass
class Entity:
    concept_id: str
    members: dict[str, int] = field(default_factory=dict)      # cve_id -> first period seen
    member_ts: dict[str, datetime] = field(default_factory=dict)
    first_flag_period: int | None = None
    flag_periods: list[int] = field(default_factory=list)
    emissions: int = 0


def make_config(args) -> NcdConfig:
    cfg = NcdConfig()  # production defaults
    # --- pinned eval/production parity (recorded in every metrics file) ---
    # The eval harness must measure the same representation the service runs.
    # These are explicit (not inherited from the environment) so a stray .env
    # cannot silently change the score.
    cfg.USE_DIFF = True
    cfg.UMAP_REFIT_INTERVAL = 0
    cfg.UMAP_RANDOM_STATE = 42
    cfg.UMAP_N_JOBS = 1
    # The judge needs local LLM weights; eval must not depend on optional model
    # files, otherwise the same command scores differently on another machine.
    cfg.JUDGE_ENABLED = False
    cfg.MAX_SENTENCES_PER_CONCEPT = 10_000
    # --- optional experiment overrides (recorded in metrics) ---
    if args.novelty_threshold is not None:
        cfg.NOVELTY_THRESHOLD = args.novelty_threshold
    if args.adaptive:
        cfg.NOVELTY_ADAPTIVE = True
    if args.cluster_mode:
        cfg.CLUSTER_MODE = args.cluster_mode
    if not cfg.BURST_TIER:
        raise SystemExit("FATAL: burst tier must be active for this harness "
                         "(unset NCD_BURST_TIER or set it to 1).")
    return cfg


def replay(periods: dict[int, list[Doc]], period_ts: dict[int, datetime],
           embedder: CachedEmbedder, cfg: NcdConfig,
           max_periods: int | None = None) -> tuple[dict[str, Entity], dict, set[str]]:
    engine = NcdEngine(cfg)
    engine._model = embedder          # cached embedder injection (same pattern as benchmark/run.py)
    entities: dict[str, Entity] = {}
    period_diags: list[dict] = []
    unit_mismatches = 0
    single_sentence_docs = 0
    docs_total = 0

    p_list = sorted(periods)
    if max_periods is not None:
        p_list = [p for p in p_list if p < max_periods]

    t0 = time.time()
    for p in p_list:
        docs = periods[p]
        unit_lists = [_split_sentences(d.text) for d in docs]
        single_sentence_docs += sum(1 for u in unit_lists if len(u) == 1)
        sent_map: dict[str, list[int]] = defaultdict(list)
        for di, ul in enumerate(unit_lists):
            for s in ul:
                sent_map[s].append(di)

        batch = DocumentBatch(
            documents=[Document(id=d.cve_id, text=d.text, source="nvd",
                                metadata={"period": p, "ts": d.ts.isoformat()})
                       for d in docs],
            period_id=f"week_{p:03d}",
        )
        result = engine.process_batch(batch)
        docs_total += len(docs)
        hs = result.heatmap_diff_summary or {}
        # Mirror the engine's unit construction (boilerplate + per-batch dedupe)
        # so this diagnostic actually checks attribution plumbing. The judge is
        # pinned off above; with a judge active its document drops would also
        # have to be replicated here.
        expected_units = 0
        seen_units: set[str] = set()
        for ul in unit_lists:
            for s in ul:
                if is_boilerplate(s) or s in seen_units:
                    continue
                seen_units.add(s)
                expected_units += 1
        if hs.get("units") != expected_units:
            unit_mismatches += 1

        for c in result.concepts:
            ent = entities.get(c.concept_id)
            if ent is None:
                ent = entities[c.concept_id] = Entity(c.concept_id)
            ent.emissions += 1
            for s in c.sentences:
                for di in sent_map.get(s, ()):   # exact sentence membership -> doc
                    cid = docs[di].cve_id
                    if cid not in ent.members:
                        ent.members[cid] = p
                        ent.member_ts[cid] = docs[di].ts
            if c.emerging:
                ent.flag_periods.append(p)
                if ent.first_flag_period is None or p < ent.first_flag_period:
                    ent.first_flag_period = p

        period_diags.append({
            "period": p, "docs": len(docs), "units": expected_units,
            "concepts": result.concepts_found,
            "emerging": int(hs.get("novel_concepts", 0)),
            "burst": int(hs.get("burst_concepts", 0)),
            "processing_time_ms": result.processing_time_ms,
        })

    replay_s = time.time() - t0
    primary_ids = {g.concept_id for g in engine._concept_graphs}
    diagnostics = {
        "replay_s": round(replay_s, 2),
        "periods_processed": len(p_list),
        "docs_processed": docs_total,
        "unit_count_mismatches": unit_mismatches,
        "single_sentence_doc_frac": round(single_sentence_docs / max(1, docs_total), 4),
        "entities": len(entities),
        "entities_without_matched_members": sum(1 for e in entities.values() if not e.members),
        "primary_entities": sum(1 for cid in entities if cid in primary_ids),
        "burst_entities": sum(1 for cid in entities if cid not in primary_ids),
        "emitting_periods": sum(1 for d in period_diags if d["concepts"] > 0),
        "total_concepts_emitted": sum(d["concepts"] for d in period_diags),
        "total_emerging_flags": sum(d["emerging"] for d in period_diags),
        "total_burst_concepts": sum(d["burst"] for d in period_diags),
        "engine_stats": engine.get_stats(),
        "per_period": period_diags,
    }
    return entities, diagnostics, primary_ids


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_entities(entities: dict[str, Entity], kev: dict[str, datetime],
                   period_ts: dict[int, datetime], split: str) -> dict:
    w_lo, w_hi = SPLIT_WINDOWS[split]
    per_entity: list[dict] = []
    for cid, ent in entities.items():
        if not ent.members:
            continue
        kev_dates = [kev[m] for m in ent.members if m in kev]
        kev_date = min(kev_dates) if kev_dates else None
        ts_sorted = sorted(ent.member_ts.values())
        mass_date = ts_sorted[MASS_FLOOR - 1] if len(ts_sorted) >= MASS_FLOOR else None
        cands = [d for d in (kev_date, mass_date) if d is not None]
        adoption_dt = min(cands) if cands else None
        if kev_date and mass_date:
            adoption_kind = "kev+mass"
        elif kev_date:
            adoption_kind = "kev"
        elif mass_date:
            adoption_kind = "mass"
        else:
            adoption_kind = "none"

        flag_dt = period_ts.get(ent.first_flag_period) if ent.first_flag_period is not None else None
        lead_days = max(0, (adoption_dt - flag_dt).days) if (adoption_dt and flag_dt) else 0
        flagged_after_adoption = bool(adoption_dt and flag_dt and flag_dt > adoption_dt)

        # "real" flag definition (only meaningful for flagged entities)
        real = False
        if flag_dt is not None:
            if kev_dates:
                real = True
            else:
                lim = ent.first_flag_period + MASS_WINDOW_WEEKS
                n_within = sum(1 for p in ent.members.values() if p <= lim)
                real = n_within >= MASS_FLOOR

        per_entity.append({
            "concept_id": cid,
            "kind": "primary",  # corrected below
            "n_members": len(ent.members),
            "n_kev_members": len(kev_dates),
            "n_members_in_mass_window": (sum(1 for p in ent.members.values()
                                             if p <= ent.first_flag_period + MASS_WINDOW_WEEKS)
                                         if ent.first_flag_period is not None else 0),
            "emissions": ent.emissions,
            "first_flag_period": ent.first_flag_period,
            "flag_ts": flag_dt.isoformat() if flag_dt else None,
            "adoption_date": adoption_dt.isoformat() if adoption_dt else None,
            "adoption_kind": adoption_kind,
            "lead_days": lead_days,
            "flagged_after_adoption": flagged_after_adoption,
            "adopted": adoption_dt is not None,
            "real_if_flagged": real,
            "member_sample": sorted(ent.members)[:20],
        })

    adopted = [r for r in per_entity if r["adopted"]
               and w_lo <= date.fromisoformat(r["adoption_date"][:10]) < w_hi]
    flagged = [r for r in per_entity if r["flag_ts"]
               and w_lo <= date.fromisoformat(r["flag_ts"][:10]) < w_hi]
    leads = [r["lead_days"] for r in adopted]
    guardrail = (sum(1.0 for r in flagged if r["real_if_flagged"]) / len(flagged)) if flagged else 0.0
    guardrail = min(1.0, max(0.0, guardrail))
    mean_lead = float(np.mean(leads)) if leads else 0.0
    score = mean_lead * guardrail

    return {
        "score": score,
        "mean_lead_days": mean_lead,
        "guardrail": guardrail,
        "n_adopted_in_split": len(adopted),
        "n_flagged_in_split": len(flagged),
        "n_adopted_missed": sum(1 for r in adopted if r["first_flag_period"] is None),
        "n_flagged_late": sum(1 for r in flagged if r["flagged_after_adoption"]),
        "leads_days": sorted(leads),
        "per_entity": per_entity,
    }


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

def write_viz(path: str, split: str, scoring: dict):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    leads = scoring["leads_days"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.5, 4.8))

    if leads:
        ax1.hist(leads, bins=min(30, max(5, int(np.sqrt(len(leads))) * 2)),
                 color="steelblue", edgecolor="white")
    else:
        ax1.text(0.5, 0.5, "no adopted concepts in split", ha="center", va="center",
                 transform=ax1.transAxes)
    ax1.axvline(scoring["mean_lead_days"], color="crimson", linestyle="--",
                label=f"mean = {scoring['mean_lead_days']:.1f} d")
    ax1.set_xlabel("lead days (adoption − first flag, clamped ≥ 0)")
    ax1.set_ylabel("# adopted concepts")
    ax1.set_title(f"[{split}] per-concept lead-time distribution")
    ax1.legend()

    counts = [scoring["n_adopted_in_split"], scoring["n_flagged_in_split"],
              scoring["n_adopted_missed"]]
    labels = ["adopted", "flagged", "adopted\nbut missed"]
    bars = ax2.bar(labels, counts, color=["seagreen", "steelblue", "salmon"])
    for b, v in zip(bars, counts):
        ax2.text(b.get_x() + b.get_width() / 2, v + max(counts) * 0.02, str(v),
                 ha="center", va="bottom", fontsize=10)
    ax2.set_ylim(0, max(1, max(counts)) * 1.18)
    ax2.set_title(f"[{split}] precision guardrail = {scoring['guardrail']:.3f} "
                  f"(mean lead {scoring['mean_lead_days']:.1f} d → score {scoring['score']:.2f})")
    ax2.set_ylabel("concept count")

    fig.tight_layout()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fig.savefig(path, dpi=120)
    plt.close(fig)


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Wall-clock NVD/KEV replay harness")
    ap.add_argument("--split", default="dev", choices=["dev", "test"])
    ap.add_argument("--stream", default=os.path.join(REPO_ROOT, "stream", "data", "cve_stream.csv"))
    ap.add_argument("--kev", default=os.path.join(REPO_ROOT, "stream", "data", "kev.json"))
    ap.add_argument("--manifest", default=os.path.join(REPO_ROOT, "stream", "data", "manifest.json"))
    ap.add_argument("--emb-cache", default=os.path.join(REPO_ROOT, "stream", "data", "emb_cache.npz"))
    ap.add_argument("--rebuild-cache", action="store_true", help="re-embed every text")
    ap.add_argument("--viz", default=None, help="write a PNG chart to this path")
    ap.add_argument("--metrics-json", default=None, help="write full per-entity detail JSON")
    # optional engine overrides (production defaults otherwise; recorded in metrics)
    ap.add_argument("--novelty-threshold", type=float, default=None,
                    help="override NcdConfig.NOVELTY_THRESHOLD (default: production 0.5)")
    ap.add_argument("--adaptive", action="store_true",
                    help="enable NcdConfig.NOVELTY_ADAPTIVE (production default: off)")
    ap.add_argument("--cluster-mode", default=None, choices=["blob", "gmm"],
                    help="override NcdConfig.CLUSTER_MODE (default: production blob)")
    ap.add_argument("--max-periods", type=int, default=None,
                    help="SMOKE ONLY: replay periods < N (metrics marked partial)")
    args = ap.parse_args()

    t_start = time.time()

    periods, period_ts, stream_info = load_stream(args.stream)
    kev = load_kev(args.kev)
    stream_info["sha256"] = file_sha256(args.stream)
    if os.path.exists(args.manifest):
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = json.load(fh)
        stream_info["manifest_sha256_match"] = (manifest.get("stream_sha256") == stream_info["sha256"])
    t_load = time.time() - t_start

    embedder = CachedEmbedder(args.emb_cache, EMBED_MODEL, rebuild=args.rebuild_cache)
    cfg = make_config(args)
    entities, diag, primary_ids = replay(periods, period_ts, embedder, cfg,
                                         max_periods=args.max_periods)
    embedder.save(final=True)  # no-op on a pure replay; raises if it cannot persist
    scoring = score_entities(entities, kev, period_ts, args.split)
    for e in scoring["per_entity"]:
        e["kind"] = "primary" if e["concept_id"] in primary_ids else "burst"

    total_s = time.time() - t_start
    kev_keys = set(kev)
    runtime = {
        "load_s": round(t_load, 2),
        "cache_load_s": round(embedder.cache_load_s, 2),
        "replay_s": diag["replay_s"],
        "total_s": round(total_s, 2),
        "new_texts_embedded": embedder.stats["new_texts_embedded"],
        "cache_hits": embedder.stats["cache_hits"],
        "encode_wall_s": round(embedder.stats["encode_s"], 2),
    }

    config_snapshot = {k: getattr(cfg, k) for k in dir(cfg) if k.isupper()}

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split": args.split,
        "split_window": [SPLIT_WINDOWS[args.split][0].isoformat(), SPLIT_WINDOWS[args.split][1].isoformat()],
        "score_formula": "mean(lead_days over adopted-in-split, missed=0, late-clamped-0) "
                         "* guardrail(flagged-in-split: KEV member OR >=40 members within 8w)",
        "mass_floor": MASS_FLOOR,
        "mass_window_weeks": MASS_WINDOW_WEEKS,
        "partial_replay": args.max_periods is not None,
        "score": scoring["score"],
        "mean_lead_days": scoring["mean_lead_days"],
        "guardrail": scoring["guardrail"],
        "counts": {
            "adopted_in_split": scoring["n_adopted_in_split"],
            "flagged_in_split": scoring["n_flagged_in_split"],
            "adopted_but_missed": scoring["n_adopted_missed"],
            "flagged_after_adoption": scoring["n_flagged_late"],
            "kev_matched_members_total": sum(len(set(e.members) & kev_keys)
                                             for e in entities.values()),
        },
        "leads_days": scoring["leads_days"],
        "per_entity": scoring["per_entity"],
        "stream": stream_info,
        "kev_entries": len(kev),
        "config": config_snapshot,
        "runtime": runtime,
        "diagnostics": diag,
    }

    if args.metrics_json:
        os.makedirs(os.path.dirname(os.path.abspath(args.metrics_json)), exist_ok=True)
        with open(args.metrics_json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
    if args.viz:
        write_viz(args.viz, args.split, scoring)

    print("=" * 68)
    print(f"wallclock replay  split={args.split}  "
          f"stream={stream_info['docs']} docs / {stream_info['weeks']} weeks "
          f"(sha {stream_info['sha256'][:12]}…)")
    print(f"  config: cluster={cfg.CLUSTER_MODE} burst_tier={cfg.BURST_TIER} "
          f"novelty_adaptive={cfg.NOVELTY_ADAPTIVE} threshold={cfg.NOVELTY_THRESHOLD} "
          f"umap_refit={cfg.UMAP_REFIT_INTERVAL} window={cfg.WINDOW_SIZE}")
    print(f"  entities: {diag['entities']} "
          f"(primary {diag['primary_entities']}, burst {diag['burst_entities']}, "
          f"unmatched {diag['entities_without_matched_members']})  "
          f"emerging flags: {diag['total_emerging_flags']}  "
          f"burst emissions: {diag['total_burst_concepts']}")
    print(f"  sentence->doc mapping: single-sentence docs "
          f"{diag['single_sentence_doc_frac'] * 100:.1f}%  "
          f"unit-count mismatches: {diag['unit_count_mismatches']}/{diag['periods_processed']}")
    print(f"  adopted[{args.split}]: {scoring['n_adopted_in_split']}  "
          f"flagged[{args.split}]: {scoring['n_flagged_in_split']}  "
          f"missed: {scoring['n_adopted_missed']}  "
          f"late(clamped 0): {scoring['n_flagged_late']}")
    print(f"  mean_lead_days: {scoring['mean_lead_days']:.2f}  guardrail: {scoring['guardrail']:.4f}")
    print(f"  runtime: load {runtime['load_s']}s + replay {runtime['replay_s']}s "
          f"= {runtime['total_s']}s (embedded {runtime['new_texts_embedded']} new texts, "
          f"{runtime['cache_hits']} cache hits)")
    if args.metrics_json:
        print(f"  metrics: {args.metrics_json}")
    if args.viz:
        print(f"  viz: {args.viz}")
    print("=" * 68)
    print(f"score: {scoring['score']:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
