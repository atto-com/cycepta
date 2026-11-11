#!/usr/bin/env python3
"""NVD CVE backfill for the cycepta-wallclock stream.

Pulls every CVE with a publication date from Jan 1 STREAM_START_YEAR (env,
default 2025) through "now" via the
NVD 2.0 API (https://services.nvd.nist.gov/rest/json/cves/2.0) using
pubStartDate/pubEndDate windows of at most 120 consecutive days (API maximum),
resultsPerPage=2000 with startIndex pagination.

Design:
  * Idempotent & resumable: each window's fully-assembled response is cached
    as raw JSON under stream/cache/nvd/<start>_<end>.json. A window that is
    already on disk is skipped. Files are written atomically (tmp + rename),
    so an interrupted run never leaves a truncated cache entry.
  * Rate limits: ~6.5 s sleep between requests by default. If the optional
    env var NVD_API_KEY is set it is sent as the "apiKey" header and the
    sleep drops to ~1.5 s (NVD allows 50 req/30 s with a key vs 5 req/30 s
    without). HTTP 403/429/5xx responses are retried with backoff.
  * Fails loudly: any window that cannot be fetched after all retries aborts
    the run with a non-zero exit code and a clear message. There is no
    silent-empty-stream path.

Usage:
  python3 stream/nvd_backfill.py                       # STREAM_START_YEAR-01-01 .. today
                                                       #   (env STREAM_START_YEAR, default 2025)
  python3 stream/nvd_backfill.py --end 2026-10-20
  NVD_API_KEY=... python3 stream/nvd_backfill.py

Dependencies: Python stdlib only (urllib); uses certifi for TLS if installed
(the macOS python.org interpreter often has no system CA store for urllib).
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone

# macOS python.org builds often lack system CA certs for urllib; use certifi.
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:  # pragma: no cover
    _SSL_CTX = ssl.create_default_context()

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_START = date(int(os.environ.get("STREAM_START_YEAR", "2025")), 1, 1)
MAX_WINDOW_DAYS = 120          # NVD hard limit for pubStartDate..pubEndDate
RESULTS_PER_PAGE = 500         # 2000 is the NVD hard limit, but ~14MB pages get truncated by middleboxes; 500 (~3MB) is reliable
SLEEP_NO_KEY = 6.5             # 5 req / 30 s without key, with margin
SLEEP_WITH_KEY = 1.5           # 50 req / 30 s with key, with margin
MAX_RETRIES = 8
RETRY_BACKOFF = (10.0, 20.0, 30.0, 45.0, 60.0, 90.0, 120.0, 150.0)
# NOTE: 500-record pages (~3MB) are small; truncated reads are cheap to retry,
# so the backoff stays short. HTTP 503 honours Retry-After when present.
REQUEST_TIMEOUT_S = 180


def _log(msg: str) -> None:
    print(f"[nvd_backfill {datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", flush=True)


def build_windows(start: date, end: date) -> list[tuple[date, date]]:
    """Half-open-ish windows [cursor, cursor + 120 d]; NVD treats both endpoints
    as inclusive, so adjacent windows overlap on their boundary instant. That
    is harmless: stream/build_stream.py de-duplicates by CVE id."""
    windows = []
    cursor = start
    while cursor < end:
        w_end = min(cursor + timedelta(days=MAX_WINDOW_DAYS), end)
        windows.append((cursor, w_end))
        cursor = w_end
    return windows


def _iso(d: date) -> str:
    # ISO-8601 with explicit UTC offset; urlencode() escapes '+' -> %2B.
    return f"{d.isoformat()}T00:00:00.000+00:00"


def fetch_window(start: date, end: date, api_key: str | None, sleep_s: float,
                 page_cache_dir: str | None = None) -> dict:
    """Fetch every CVE published in [start, end] (inclusive), paginating."""
    params = {
        "pubStartDate": _iso(start),
        "pubEndDate": _iso(end),
        "resultsPerPage": str(RESULTS_PER_PAGE),
        "startIndex": "0",
    }
    all_vulns: list[dict] = []
    total_results: int | None = None
    start_index = 0
    request_no = 0

    # Page-level resume: each successfully fetched page is written to
    # page_cache_dir, so a truncated later page never forces a re-download
    # of the pages that already succeeded.
    if page_cache_dir:
        os.makedirs(page_cache_dir, exist_ok=True)
        for fn in sorted(os.listdir(page_cache_dir)):
            if not (fn.startswith("page_") and fn.endswith(".json")):
                continue
            try:
                with open(os.path.join(page_cache_dir, fn), encoding="utf-8") as fh:
                    pg = json.load(fh)
            except (json.JSONDecodeError, OSError):
                continue
            if total_results is None:
                total_results = int(pg.get("totalResults", 0))
            all_vulns.extend(pg.get("vulnerabilities", []))
            try:
                idx = int(pg.get("startIndex", fn[5:-5]))
            except (TypeError, ValueError):
                continue
            start_index = max(start_index, idx + RESULTS_PER_PAGE)
        if all_vulns:
            _log(f"  window {start}..{end}: resumed from page cache "
                 f"({len(all_vulns)} records, next startIndex={start_index})")

    while not (total_results is not None and start_index >= total_results):
        params["startIndex"] = str(start_index)
        url = API_URL + "?" + urllib.parse.urlencode(params)
        headers = {"User-Agent": "cycepta-wallclock-backfill/1.0"}
        if api_key:
            headers["apiKey"] = api_key

        last_err: Exception | None = None
        body: str | None = None
        for attempt in range(MAX_RETRIES):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_S,
                                            context=_SSL_CTX) as resp:
                    body = resp.read().decode("utf-8")
                last_err = None
                break
            except urllib.error.HTTPError as e:
                last_err = e
                retry_after = e.headers.get("Retry-After")
                wait = float(retry_after) if retry_after and retry_after.isdigit() \
                    else RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
                _log(f"  HTTP {e.code} on {start}..{end} (startIndex={start_index}), "
                     f"retry {attempt + 1}/{MAX_RETRIES} in {wait:.0f}s")
                time.sleep(wait)
            except (urllib.error.URLError, TimeoutError, OSError,
                    http.client.HTTPException) as e:
                last_err = e
                wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
                _log(f"  network error ({e}) on {start}..{end} (startIndex={start_index}), "
                     f"retry {attempt + 1}/{MAX_RETRIES} in {wait:.0f}s")
                time.sleep(wait)
        if last_err is not None:
            raise RuntimeError(
                f"NVD request failed for window {start}..{end} (startIndex={start_index}) "
                f"after {MAX_RETRIES} attempts: {last_err}"
            )

        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"NVD returned invalid JSON for window {start}..{end} "
                f"(startIndex={start_index}): {e}"
            ) from e
        if page_cache_dir:
            atomic_write_json(os.path.join(page_cache_dir, f"page_{start_index:08d}.json"), data)

        if total_results is None:
            total_results = int(data.get("totalResults", 0))
        vulns = data.get("vulnerabilities", [])
        all_vulns.extend(vulns)
        request_no += 1

        start_index += RESULTS_PER_PAGE
        if start_index >= total_results:
            break
        time.sleep(sleep_s)

    _log(f"  window {start}..{end}: {len(all_vulns)}/{total_results} CVE records "
         f"({request_no} requests)")
    return {
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": 0,
        "totalResults": total_results,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "window": {"pubStartDate": _iso(start), "pubEndDate": _iso(end)},
        "vulnerabilities": all_vulns,
    }


def atomic_write_json(path: str, obj: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=f"Backfill NVD CVEs {DEFAULT_START.isoformat()} .. now (cached windows)")
    ap.add_argument("--start", default=DEFAULT_START.isoformat(), help="start date YYYY-MM-DD")
    ap.add_argument("--end", default=None, help="end date YYYY-MM-DD (default: today UTC)")
    ap.add_argument("--cache-dir", default=None, help="default: <repo>/stream/cache/nvd")
    ap.add_argument("--sleep", type=float, default=None,
                    help="override inter-request sleep seconds (default 6.5, or 1.5 with NVD_API_KEY)")
    ap.add_argument("--force", action="store_true", help="re-fetch windows even if cached")
    args = ap.parse_args()

    start = date.fromisoformat(args.start)
    end = date.fromisoformat(args.end) if args.end else datetime.now(timezone.utc).date()
    if end <= start:
        print(f"ERROR: end ({end}) must be after start ({start})", file=sys.stderr)
        return 2

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cache_dir = args.cache_dir or os.path.join(repo_root, "stream", "cache", "nvd")
    os.makedirs(cache_dir, exist_ok=True)

    api_key = os.environ.get("NVD_API_KEY", "").strip() or None
    sleep_s = args.sleep if args.sleep is not None else (SLEEP_WITH_KEY if api_key else SLEEP_NO_KEY)
    _log(f"range {start} .. {end}; cache={cache_dir}; key={'yes' if api_key else 'no'}; "
         f"sleep={sleep_s}s")

    windows = build_windows(start, end)
    _log(f"{len(windows)} windows of <= {MAX_WINDOW_DAYS} days")

    fetched_records = 0
    cached_records = 0
    for i, (w_start, w_end) in enumerate(windows, 1):
        cache_path = os.path.join(cache_dir, f"{w_start.isoformat()}_{w_end.isoformat()}.json")
        if os.path.exists(cache_path) and not args.force:
            try:
                with open(cache_path, encoding="utf-8") as fh:
                    n = len(json.load(fh).get("vulnerabilities", []))
                cached_records += n
                _log(f"window {i}/{len(windows)} {w_start}..{w_end}: cached ({n} records)")
                continue
            except (json.JSONDecodeError, OSError) as e:
                _log(f"window {i}/{len(windows)}: cached file corrupt ({e}); refetching")
        try:
            data = fetch_window(w_start, w_end, api_key, sleep_s,
                                page_cache_dir=os.path.join(cache_dir, "pages",
                                                    f"{w_start.isoformat()}_{w_end.isoformat()}"))
        except RuntimeError as e:
            print(f"\nFATAL: {e}\n"
                  f"Partial cache is kept under {cache_path.rsplit('/', 1)[0]}; "
                  f"re-run the same command to resume once the API is reachable.",
                  file=sys.stderr)
            return 1
        atomic_write_json(cache_path, data)
        fetched_records += len(data["vulnerabilities"])
        time.sleep(sleep_s)

    total = fetched_records + cached_records
    _log(f"DONE: {total} CVE records ({fetched_records} fetched, {cached_records} from cache) "
         f"in {len(windows)} windows")
    if total < 1000:
        print(f"FATAL: only {total} records fetched — that cannot be a full {start.year}..now backfill. "
              f"Aborting so downstream steps never see a silently-empty stream.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
