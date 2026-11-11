#!/usr/bin/env python3
"""Build cve_stream.csv + kev.json + manifest.json from cvelistV5 containers.

Sibling of stream/build_stream.py (which builds from NVD window JSONs); the
NVD path is untouched and keeps working. Data source here is the OFFICIAL
CVEProject/cvelistV5 tree acquired by stream/cvelist_backfill.py - the same
upstream JSON containers the NVD API serves, minus the flaky API.

The stream CONTRACT is identical to the NVD build:
  * csv columns: period,id,text,source,ts,topic
  * id   = CVE id (e.g. CVE-2023-1234)
  * text = "<id>: <english description>"
  * ts   = cveMetadata.datePublished, normalized to naive ISO-8601 (Z stripped)
           - byte-compatible with the NVD build's ts format
  * period = int((published_date - Jan 1, STREAM_START_YEAR).days // 7)
  * only CVEs published Jan 1 STREAM_START_YEAR..now; de-duplicated by id; entries without
    an English description are skipped (counted in manifest.parse_stats);
    loud failure below MIN_PLAUSIBLE_CEVS.
  * source column = "cvelistV5" (provenance; the wallclock harness ignores
    this column and hardcodes Document(source="nvd") internally)
  * topic = "" (ground truth is KEV, not topics)

English description resolution: containers.cna.descriptions with lang
"en" or any BCP-47 English variant ("en-US", ... - CNAs increasingly use
regional tags) first; if absent, the same scan over containers.adp[].
This mirrors what NVD imports for the vast majority of records.

Equivalence check (--equivalence-sample N, default 200): sample N CVE ids
that exist in BOTH the parsed cvelistV5 set and the locally cached NVD window
JSONs (stream/cache/nvd, top-level window files only), and compare the
descriptions and published dates verbatim. Rates + examples go into the
manifest under "equivalence_check" and are printed.

Usage:
  python3 stream/build_stream_v5.py
  python3 stream/build_stream_v5.py --equivalence-sample 200
  python3 stream/build_stream_v5.py --offline      # reuse cached KEV catalog
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import random
import re
import shutil
import sys
from collections import Counter
from datetime import date, datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_stream import fetch_kev, STREAM_START_YEAR  # noqa: E402  (shared KEV download logic + stream origin)

# Stream origin comes from build_stream (env STREAM_START_YEAR, default 2025).
STREAM_START = date(STREAM_START_YEAR, 1, 1)
MIN_PLAUSIBLE_CEVS = 10_000
WINDOW_FILE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{4}-\d{2}-\d{2}\.json$")


def _log(msg: str) -> None:
    print(f"[build_stream_v5 {datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}",
          flush=True)


def _is_en(lang: str | None) -> bool:
    """BCP-47 aware: CNAs increasingly write "en-US" instead of "en"."""
    return bool(lang) and (lang == "en" or lang.startswith("en-"))


def english_description(doc: dict) -> str | None:
    containers = doc.get("containers") or {}
    for container in [containers.get("cna")] + list(containers.get("adp") or []):
        if not container:
            continue
        for d in container.get("descriptions") or []:
            if _is_en(d.get("lang")) and d.get("value"):
                return d["value"]
    return None


def parse_ts(raw: str) -> datetime | None:
    """cvelistV5 datePublished ('2023-01-05T13:15:09.143Z') -> naive datetime."""
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None)
    except ValueError:
        return None


def load_v5_records(src_dir: str) -> tuple[list[dict], dict]:
    stats = {"files_scanned": 0, "bad_json": 0, "no_cve_id": 0,
             "no_published": 0, "no_english_description": 0,
             "duplicates": 0, "states": Counter()}
    by_id: dict[str, dict] = {}
    cves_root = os.path.join(src_dir, "cves")
    if not os.path.isdir(cves_root):
        raise SystemExit(f"FATAL: {cves_root} not found - run stream/cvelist_backfill.py first")
    # Scan EVERY year dir (1999..now): backlog IDs that were first published
    # in 2023+ still live under their ID-year dir (e.g. CVE-2006-10001 ->
    # cves/2006/...), and NVD counts them in the window. The 2023-01-01
    # contract boundary is enforced later via the period filter, not here.
    paths: list[str] = []
    for name in sorted(os.listdir(cves_root)):
        if re.fullmatch(r"\d{4}", name):
            paths.extend(glob.glob(os.path.join(cves_root, name, "*", "CVE-*.json")))
    for path in sorted(paths):
        stats["files_scanned"] += 1
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError):
            stats["bad_json"] += 1
            continue
        meta = doc.get("cveMetadata") or {}
        cid = meta.get("cveId")
        if not cid:
            stats["no_cve_id"] += 1
            continue
        if cid in by_id:
            stats["duplicates"] += 1
            continue
        by_id[cid] = {
            "id": cid,
            "published": meta.get("datePublished"),
            "state": meta.get("state") or "UNKNOWN",
            "description": english_description(doc),
            "path": path,
        }
        stats["states"][by_id[cid]["state"]] += 1
    _log(f"cvelistV5: scanned {stats['files_scanned']} files -> {len(by_id)} unique CVE ids "
         f"({stats['duplicates']} duplicates, {stats['bad_json']} unreadable)")
    return list(by_id.values()), stats


def nvd_window_map(nvd_cache_dir: str) -> dict[str, tuple[str, str]]:
    """id -> (english description, published string) from cached NVD windows.

    Only TOP-LEVEL window files are read (the supervisor crawl's pages/ dir
    is not touched).
    """
    out: dict[str, tuple[str, str]] = {}
    if not os.path.isdir(nvd_cache_dir):
        return out
    for fname in sorted(os.listdir(nvd_cache_dir)):
        if not WINDOW_FILE_RE.match(fname):
            continue
        with open(os.path.join(nvd_cache_dir, fname), encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError:
                continue
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve") or {}
            cid = cve.get("id")
            desc = next((d["value"] for d in (cve.get("descriptions") or [])
                         if d.get("lang") == "en" and d.get("value")), None)
            if cid and desc and cve.get("published"):
                out[cid] = (desc, cve["published"])
    return out


def equivalence_check(rows_by_id: dict[str, dict], nvd_cache_dir: str, n: int) -> dict:
    nvd = nvd_window_map(nvd_cache_dir)
    shared = sorted(set(rows_by_id) & set(nvd))
    if not shared:
        return {"status": "no_shared_ids", "nvd_cache_dir": nvd_cache_dir}
    sample = random.Random(42).sample(shared, min(n, len(shared)))
    desc_exact = 0
    desc_norm = 0
    ts_exact = 0
    ts_same_date = 0
    ts_within_24h = 0
    by_state: dict[str, Counter] = {"PUBLISHED": Counter(), "REJECTED": Counter(),
                                    "OTHER": Counter()}
    examples: list[dict] = []
    for cid in sample:
        v5 = rows_by_id[cid]
        nvd_desc, nvd_ts = nvd[cid]
        state = v5["state"] if v5["state"] in by_state else "OTHER"
        by_state[state]["n"] += 1
        ok_exact = v5["description"] == nvd_desc
        ok_norm = " ".join(v5["description"].split()) == " ".join(nvd_desc.split())
        nvd_dt = parse_ts(nvd_ts)
        ok_ts = v5["ts_dt"] == nvd_dt
        # NVD `published` is NVD's ingest/publication time; the CNA
        # `datePublished` may be date-only (midnight) or minutes earlier, so
        # exact equality is not the right equivalence bar for ts: we also
        # measure same-calendar-date and within-24h agreement.
        ok_date = nvd_dt is not None and v5["ts_dt"].date() == nvd_dt.date()
        ok_24h = nvd_dt is not None and abs((nvd_dt - v5["ts_dt"]).total_seconds()) <= 86400
        desc_exact += ok_exact
        desc_norm += ok_norm
        ts_exact += ok_ts
        ts_same_date += ok_date
        ts_within_24h += ok_24h
        by_state[state]["desc_exact"] += ok_exact
        by_state[state]["ts_exact"] += ok_ts
        by_state[state]["ts_same_date"] += ok_date
        if (not ok_exact or not ok_date) and len(examples) < 3:
            examples.append({
                "id": cid, "state": state,
                "v5_desc": v5["description"][:140], "nvd_desc": nvd_desc[:140],
                "v5_ts": v5["ts"], "nvd_ts": nvd_ts,
            })
    result = {
        "nvd_cache_dir": nvd_cache_dir,
        "shared_ids": len(shared),
        "sample": len(sample),
        "desc_exact_match_rate": round(desc_exact / len(sample), 4),
        "desc_whitespace_norm_match_rate": round(desc_norm / len(sample), 4),
        "published_ts_exact_match_rate": round(ts_exact / len(sample), 4),
        "published_ts_same_date_rate": round(ts_same_date / len(sample), 4),
        "published_ts_within_24h_rate": round(ts_within_24h / len(sample), 4),
        "ts_note": "NVD 'published' is NVD's ingest time and may be date-only "
                   "midnight in the CNA record; exact-time equality is not "
                   "expected, same-date agreement is the meaningful bar",
        "by_state": {k: {"n": v["n"],
                         "desc_exact_rate": round(v["desc_exact"] / max(1, v["n"]), 4),
                         "ts_exact_rate": round(v["ts_exact"] / max(1, v["n"]), 4),
                         "ts_same_date_rate": round(v["ts_same_date"] / max(1, v["n"]), 4)}
                     for k, v in by_state.items() if v["n"]},
        "mismatch_examples": examples,
    }
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the stream CSV/manifest from cvelistV5")
    ap.add_argument("--src-dir", default=None,
                    help="cvelistV5 checkout (default: <repo>/stream/cache/cvelistV5/src)")
    ap.add_argument("--out-dir", default=None, help="default: <repo>/stream/data")
    ap.add_argument("--nvd-cache-dir", default=None,
                    help="NVD window cache for the equivalence check "
                         "(default: <repo>/stream/cache/nvd)")
    ap.add_argument("--equivalence-sample", type=int, default=200,
                    help="sample size for the NVD-vs-cvelistV5 field comparison (0=off)")
    ap.add_argument("--offline", action="store_true", help="reuse cached KEV, no network")
    args = ap.parse_args()

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    src_dir = args.src_dir or os.path.join(repo_root, "stream", "cache", "cvelistV5", "src")
    out_dir = args.out_dir or os.path.join(repo_root, "stream", "data")
    nvd_dir = args.nvd_cache_dir or os.path.join(repo_root, "stream", "cache", "nvd")
    os.makedirs(out_dir, exist_ok=True)

    kev_cache = os.path.join(repo_root, "stream", "cache", "kev.json")
    kev = fetch_kev(kev_cache, args.offline)
    kev_map: dict[str, str] = {}
    for v in kev.get("vulnerabilities", []):
        cid, added = v.get("cveID"), v.get("dateAdded")
        if cid and added:
            kev_map[cid] = added

    records, stats = load_v5_records(src_dir)

    rows: list[tuple[datetime, int, str, str, str]] = []
    per_year: Counter = Counter()
    for rec in records:
        if not rec["published"]:
            stats["no_published"] += 1
            continue
        if not rec["description"]:
            stats["no_english_description"] += 1
            continue
        ts = parse_ts(rec["published"])
        if ts is None:
            stats["no_published"] += 1
            continue
        period = (ts.date() - STREAM_START).days // 7
        if period < 0:
            continue
        cid = rec["id"]
        rows.append((ts, period, cid, f"{cid}: {rec['description']}", rec["state"]))
        per_year[ts.year] += 1

    if len(rows) < MIN_PLAUSIBLE_CEVS:
        raise SystemExit(
            f"FATAL: only {len(rows)} usable CVE rows parsed from {src_dir} "
            f"(< {MIN_PLAUSIBLE_CEVS} plausible for {STREAM_START_YEAR}..now). The cvelistV5 "
            f"acquisition is incomplete; re-run stream/cvelist_backfill.py --force. "
            f"Refusing to write a silently-empty stream.")
    rows.sort(key=lambda r: (r[0], r[2]))

    csv_path = os.path.join(out_dir, "cve_stream.csv")
    import csv as csv_mod
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv_mod.writer(fh)
        w.writerow(["period", "id", "text", "source", "ts", "topic"])
        for ts, period, cid, text, _state in rows:
            w.writerow([period, cid, text, "cvelistV5", ts.isoformat(), ""])

    sha256 = hashlib.sha256()
    with open(csv_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha256.update(chunk)

    rows_by_id = {r[2]: {"ts": r[0].isoformat(), "ts_dt": r[0],
                         "description": r[3].split(": ", 1)[1],
                         "state": r[4]} for r in rows}
    equiv = None
    if args.equivalence_sample > 0:
        _log(f"equivalence check vs {nvd_dir} (sample {args.equivalence_sample}) ...")
        equiv = equivalence_check(rows_by_id, nvd_dir, args.equivalence_sample)
        _log(f"equivalence: desc_exact={equiv.get('desc_exact_match_rate')} "
             f"ts_exact={equiv.get('published_ts_exact_match_rate')} "
             f"ts_same_date={equiv.get('published_ts_same_date_rate')} "
             f"(by state: {json.dumps(equiv.get('by_state'))})")

    kev_matched = sum(1 for r in rows if r[2] in kev_map)
    periods_present = sorted({r[1] for r in rows})
    source_meta = None
    source_meta_path = os.path.join(repo_root, "stream", "cache", "cvelistV5", "SOURCE.json")
    if os.path.exists(source_meta_path):
        with open(source_meta_path, encoding="utf-8") as fh:
            source_meta = json.load(fh)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "cvelistV5",
        "source_meta": source_meta,
        "stream_start": STREAM_START.isoformat(),
        "text_format": "<cve_id>: <english description>",
        "total_cves": len(rows),
        "per_year": {str(y): per_year[y] for y in sorted(per_year)},
        "parse_stats": {**{k: v for k, v in stats.items() if k != "states"},
                        "states": dict(stats["states"]),
                        "row_states": dict(Counter(r[4] for r in rows))},
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
    if equiv is not None:
        manifest["equivalence_check"] = equiv
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
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
