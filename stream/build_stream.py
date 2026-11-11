#!/usr/bin/env python3
"""Build the weekly CVE stream + KEV ground truth from the NVD backfill cache.

Inputs:
  stream/cache/nvd/*.json   raw NVD 2.0 window responses (from nvd_backfill.py)

Outputs (all under stream/data/):
  cve_stream.csv   header: period,id,text,source,ts,topic
                   id   = CVE id (e.g. CVE-2023-1234)
                   text = "<id>: <english description>"
                        (the engine's sentence splitter treats this as the
                         document text; the id is already "CVE-YYYY-NNNNN"
                         prefixed so no second "CVE" token is added)
                   ts   = cve.published as returned by NVD (ISO-8601)
                   period = int((published_date - Jan 1, STREAM_START_YEAR).days // 7), 0-based week index
                   source = "nvd", topic = "" (ground truth is KEV, not topics)
                   One row per CVE that has an English description, sorted by ts.
  kev.json         raw CISA KEV catalog (catalogVersion, dateReleased,
                   vulnerabilities[{cveID, dateAdded, ...}])
  manifest.json    counts, week range, stream sha256, KEV match stats.

The KEV catalog is also cached (raw) under stream/cache/kev.json so a replay
can be rebuilt offline from the two cache dirs.

Fails loudly if the NVD cache is missing/empty or the stream is implausibly
small, and if the KEV download fails. No silent empty stream.
Usage: python3 stream/build_stream.py [--offline]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import ssl
import sys
import urllib.request
from collections import Counter
from datetime import date, datetime, timezone

try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:  # pragma: no cover
    _SSL_CTX = ssl.create_default_context()

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Stream origin: Jan 1 of STREAM_START_YEAR. Override per run without code
# edits:  STREAM_START_YEAR=2019 python3 stream/build_stream.py
STREAM_START_YEAR = int(os.environ.get("STREAM_START_YEAR", "2025"))
STREAM_START = date(STREAM_START_YEAR, 1, 1)
MIN_PLAUSIBLE_CEVS = 10_000


def _log(msg: str) -> None:
    print(f"[build_stream {datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", flush=True)


def fetch_kev(cache_path: str, offline: bool) -> dict:
    """Return the raw KEV catalog, refreshing stream/cache/kev.json unless --offline."""
    if offline:
        if not os.path.exists(cache_path):
            raise SystemExit(f"FATAL: --offline requested but {cache_path} does not exist")
        _log(f"KEV: using cached {cache_path} (offline)")
        with open(cache_path, encoding="utf-8") as fh:
            return json.load(fh)
    last_err = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(KEV_URL, headers={"User-Agent": "cycepta-wallclock-build/1.0"})
            with urllib.request.urlopen(req, timeout=90, context=_SSL_CTX) as resp:
                raw = resp.read()
            catalog = json.loads(raw)
            if "vulnerabilities" not in catalog:
                raise RuntimeError("KEV catalog has no 'vulnerabilities' key")
            tmp = cache_path + ".tmp"
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(tmp, "wb") as fh:
                fh.write(raw)
            os.replace(tmp, cache_path)
            _log(f"KEV: downloaded catalogVersion={catalog.get('catalogVersion')} "
                 f"dateReleased={catalog.get('dateReleased')} "
                 f"vulnerabilities={len(catalog['vulnerabilities'])}")
            return catalog
        except Exception as e:  # noqa: BLE001 - fail loudly after retries
            last_err = e
            _log(f"KEV download attempt {attempt + 1}/3 failed: {e}")
    raise SystemExit(f"FATAL: could not download the CISA KEV catalog from {KEV_URL}: {last_err}")


def load_nvd_records(cache_dir: str) -> tuple[list[dict], dict]:
    """Parse + de-duplicate every cached NVD window. Returns (records, stats)."""
    if not os.path.isdir(cache_dir):
        raise SystemExit(f"FATAL: NVD cache dir {cache_dir} not found — run stream/nvd_backfill.py first")
    files = sorted(f for f in os.listdir(cache_dir) if f.endswith(".json"))
    if not files:
        raise SystemExit(f"FATAL: no cached NVD windows in {cache_dir} — run stream/nvd_backfill.py first")

    stats = {"windows": len(files), "raw_records": 0, "duplicates": 0,
             "no_published": 0, "no_english_description": 0}
    by_id: dict[str, dict] = {}
    for fname in files:
        with open(os.path.join(cache_dir, fname), encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as e:
                raise SystemExit(f"FATAL: corrupt cache file {fname}: {e}")
        vulns = data.get("vulnerabilities", [])
        stats["raw_records"] += len(vulns)
        for item in vulns:
            cve = item.get("cve") or {}
            cid = cve.get("id")
            if not cid:
                continue
            if cid in by_id:
                stats["duplicates"] += 1
                continue
            by_id[cid] = cve
    _log(f"NVD cache: {stats['windows']} windows, {stats['raw_records']} raw records, "
         f"{len(by_id)} unique CVE ids ({stats['duplicates']} boundary duplicates dropped)")
    return list(by_id.values()), stats


def english_description(cve: dict) -> str | None:
    descs = cve.get("descriptions") or []
    for d in descs:
        if d.get("lang") == "en" and d.get("value"):
            return d["value"]
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Build cve_stream.csv + kev.json + manifest.json")
    ap.add_argument("--cache-dir", default=None, help="default: <repo>/stream/cache/nvd")
    ap.add_argument("--out-dir", default=None, help="default: <repo>/stream/data")
    ap.add_argument("--offline", action="store_true", help="use cached KEV, no network")
    args = ap.parse_args()

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cache_dir = args.cache_dir or os.path.join(repo_root, "stream", "cache", "nvd")
    out_dir = args.out_dir or os.path.join(repo_root, "stream", "data")
    os.makedirs(out_dir, exist_ok=True)

    kev_cache = os.path.join(repo_root, "stream", "cache", "kev.json")
    kev = fetch_kev(kev_cache, args.offline)
    kev_map: dict[str, str] = {}
    for v in kev.get("vulnerabilities", []):
        cid, added = v.get("cveID"), v.get("dateAdded")
        if cid and added:
            kev_map[cid] = added

    records, stats = load_nvd_records(cache_dir)

    rows: list[tuple[datetime, int, str, str]] = []
    per_year: Counter = Counter()
    for cve in records:
        published = cve.get("published")
        if not published:
            stats["no_published"] += 1
            continue
        desc = english_description(cve)
        if not desc:
            stats["no_english_description"] += 1
            continue
        try:
            ts = datetime.fromisoformat(published.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            stats["no_published"] += 1
            continue
        period = (ts.date() - STREAM_START).days // 7
        if period < 0:
            continue
        cid = cve["id"]
        rows.append((ts, period, cid, f"{cid}: {desc}"))
        per_year[ts.year] += 1

    if len(rows) < MIN_PLAUSIBLE_CEVS:
        raise SystemExit(
            f"FATAL: only {len(rows)} usable CVE rows parsed from {cache_dir} "
            f"(< {MIN_PLAUSIBLE_CEVS} plausible for {STREAM_START_YEAR}..now). The backfill is incomplete; "
            f"re-run stream/nvd_backfill.py. Refusing to write a silently-empty stream.")
    rows.sort(key=lambda r: (r[0], r[2]))

    csv_path = os.path.join(out_dir, "cve_stream.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["period", "id", "text", "source", "ts", "topic"])
        for ts, period, cid, text in rows:
            w.writerow([period, cid, text, "nvd", ts.isoformat(), ""])

    kev_matched = sum(1 for _, _, cid, _ in rows if cid in kev_map)
    sha256 = hashlib.sha256()
    with open(csv_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha256.update(chunk)

    periods_present = sorted({p for _, p, _, _ in rows})
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stream_start": STREAM_START.isoformat(),
        "text_format": "<cve_id>: <english description>",
        "total_cves": len(rows),
        "per_year": {str(y): per_year[y] for y in sorted(per_year)},
        "parse_stats": stats,
        "week_range": {
            "min_period": periods_present[0],
            "max_period": periods_present[-1],
            "n_periods": len(periods_present),
            "min_ts": rows[0][0].isoformat(),
            "max_ts": rows[-1][0].isoformat(),
        },
        "kev": {
            "catalog_version": kev.get("catalogVersion"),
            "date_released": kev.get("dateReleased"),
            "catalog_total": len(kev.get("vulnerabilities", [])),
            "kev_matched_cves": kev_matched,
        },
        "stream_file": "cve_stream.csv",
        "stream_sha256": sha256.hexdigest(),
        "stream_bytes": os.path.getsize(csv_path),
    }
    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    shutil.copyfile(kev_cache, os.path.join(out_dir, "kev.json"))

    _log(f"Wrote {csv_path} ({manifest['stream_bytes'] / 1e6:.1f} MB, {len(rows)} rows)")
    _log(f"per-year: {manifest['per_year']}")
    _log(f"weeks: {manifest['week_range']['min_period']}..{manifest['week_range']['max_period']} "
         f"({manifest['week_range']['n_periods']} weeks, {manifest['week_range']['min_ts']} .. "
         f"{manifest['week_range']['max_ts']})")
    _log(f"KEV matches: {kev_matched} stream CVEs in catalog of {len(kev_map)}")
    _log(f"sha256: {manifest['stream_sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
