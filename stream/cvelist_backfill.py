#!/usr/bin/env python3
"""Bulk-acquire the official CVE JSON containers (CVEProject/cvelistV5).

The NVD REST API truncates large responses on some networks (IncompleteRead /
503), which makes a paginated NVD crawl impractical there. cvelistV5 is the
UPSTREAM source of CVE records (the same JSON containers NVD ingests), served
by GitHub, and can be acquired in ONE bulk transfer instead of hundreds of
rate-limited API calls.

Two acquisition modes (both cache under stream/cache/cvelistV5/):

  clone   (default)  `git clone --depth 1 --filter=blob:none --sparse` of
                     https://github.com/CVEProject/cvelistV5, then
                     `sparse-checkout set cves/<start year> ... cves/<current year>`
                     (start year = env STREAM_START_YEAR, default 2025).
                     - depth 1 + blob filter => no git history bloat: only the
                       tip commit/tree objects plus the blobs of the sparse
                       dirs are transferred.
                     - only start-year+ CVE dirs are checked out (the stream
                       starts Jan 1 of STREAM_START_YEAR; older-year dirs are
                       never downloaded).
                     - NOT byte-resumable: an interrupted transfer is retried
                       from scratch (idempotent: the partial dir is removed).

  tarball            codeload tarball (https://codeload.github.com/CVEProject/
                     cvelistV5/tar.gz/refs/heads/main), downloaded with
                     `curl -C -` so an interrupted download RESUMES
                     byte-wise, then extracted (whole repo, all years).
                     More bytes than `clone`, but the most robust choice on a
                     flaky link because progress is never lost.

  auto               try `clone`; if it fails after retries, fall back to
                     `tarball`. (DEFAULT)

Both paths are idempotent/resumable: if the cache already holds a verified
acquisition (clone HEAD present with checked-out CVE files, or extracted
tarball with >= MIN_PLAUSIBLE_FILES json files), the script exits 0 without
any network access. Metadata about what was acquired (mode, URL, commit /
tarball sha256, file count, when) is written to SOURCE.json next to the data.

The extractor consumed by this script is stream/build_stream_v5.py.

Usage:
  python3 stream/cvelist_backfill.py                 # auto
  python3 stream/cvelist_backfill.py --mode tarball
  python3 stream/cvelist_backfill.py --force         # re-acquire
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

REPO_URL = "https://github.com/CVEProject/cvelistV5.git"
TARBALL_URL = "https://codeload.github.com/CVEProject/cvelistV5/tar.gz/refs/heads/main"
MIN_PLAUSIBLE_FILES = 10_000
# First year of the stream; override per run: STREAM_START_YEAR=2019 ...
STREAM_START_YEAR = int(os.environ.get("STREAM_START_YEAR", "2025"))


def _log(msg: str) -> None:
    print(f"[cvelist_backfill {datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}",
          flush=True)


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    _log("$ " + " ".join(cmd))
    return subprocess.run(cmd, check=True, **kw)


def count_cve_files(src_dir: str) -> int:
    n = 0
    cves = os.path.join(src_dir, "cves")
    if not os.path.isdir(cves):
        return 0
    for root, _dirs, files in os.walk(cves):
        n += sum(1 for f in files if f.startswith("CVE-") and f.endswith(".json"))
    return n


def _years() -> list[str]:
    from datetime import date
    return [str(y) for y in range(STREAM_START_YEAR, date.today().year + 1)]


def write_source_meta(out_dir: str, meta: dict) -> None:
    meta["fetched_at"] = datetime.now(timezone.utc).isoformat()
    with open(os.path.join(out_dir, "SOURCE.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    _log(f"SOURCE.json: {json.dumps(meta)}")


def verified(out_dir: str) -> dict | None:
    """Return existing SOURCE.json if the cache is complete, else None."""
    src = os.path.join(out_dir, "src")
    meta_path = os.path.join(out_dir, "SOURCE.json")
    if not (os.path.isdir(src) and os.path.exists(meta_path)):
        return None
    n = count_cve_files(src)
    if n < MIN_PLAUSIBLE_FILES:
        return None
    try:
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    meta["recount_files"] = n
    return meta


def acquire_clone(out_dir: str, force: bool) -> dict:
    src = os.path.join(out_dir, "src")
    if force and os.path.exists(src):
        _log(f"--force: removing {src}")
        shutil.rmtree(src)
    tmp = src + ".partial"
    if os.path.exists(tmp):
        shutil.rmtree(tmp)  # interrupted clone: restart cleanly (not resumable)
    _log("cloning (depth=1, blob filter, sparse) ... this transfers only tip "
         f"objects + blobs of the {STREAM_START_YEAR}+ cve dirs")
    try:
        _run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
              "--branch", "main", REPO_URL, tmp])
        _run(["git", "-C", tmp, "sparse-checkout", "set",
              *[f"cves/{y}" for y in _years()]],
             stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        _log(f"clone failed ({e}); removing partial dir")
        if os.path.exists(tmp):
            shutil.rmtree(tmp)
        raise
    os.replace(tmp, src)
    n = count_cve_files(src)
    if n < MIN_PLAUSIBLE_FILES:
        raise SystemExit(f"FATAL: sparse clone produced only {n} CVE json files "
                         f"(< {MIN_PLAUSIBLE_FILES}) - acquisition incomplete")
    sha = subprocess.run(["git", "-C", src, "rev-parse", "HEAD"],
                         check=True, capture_output=True, text=True).stdout.strip()
    return {"mode": "clone", "url": REPO_URL, "commit": sha, "files": n,
            "sparse_dirs": [f"cves/{y}" for y in _years()]}


def acquire_tarball(out_dir: str, force: bool) -> dict:
    tarball = os.path.join(out_dir, "cvelistV5-main.tar.gz")
    src = os.path.join(out_dir, "src")
    tarball_sha: str | None = None
    if force:
        for p in (tarball, src):
            if os.path.exists(p):
                shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    os.makedirs(out_dir, exist_ok=True)
    if os.path.exists(src) and count_cve_files(src) >= MIN_PLAUSIBLE_FILES:
        _log("tarball cache already extracted; skipping download")
    else:
        for attempt in range(1, 6):
            # curl -C - resumes byte-wise; a flaky link never loses progress.
            cmd = ["curl", "-fL", "--retry", "5", "--retry-delay", "10",
                   "-C", "-", "-o", tarball, TARBALL_URL]
            _log(f"download attempt {attempt}/5 (resumable): {TARBALL_URL}")
            r = subprocess.run(cmd)
            if r.returncode == 0:
                break
            _log(f"curl exited {r}; retrying in 15s")
            time.sleep(15)
        else:
            raise SystemExit(f"FATAL: could not download {TARBALL_URL} after 5 attempts")
        sha = hashlib.sha256()
        with open(tarball, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 22), b""):
                sha.update(chunk)
        tarball_sha = sha.hexdigest()
        _log(f"downloaded {os.path.getsize(tarball) / 1e6:.1f} MB, sha256={tarball_sha[:16]}…")

        tmp = src + ".partial"
        if os.path.exists(tmp):
            shutil.rmtree(tmp)
        os.makedirs(tmp, exist_ok=True)
        _log("extracting (strip 1) ...")
        _run(["tar", "-xzf", tarball, "--strip-components", "1", "-C", tmp])
        if os.path.exists(src):
            shutil.rmtree(src)
        os.replace(tmp, src)
    n = count_cve_files(src)
    if n < MIN_PLAUSIBLE_FILES:
        raise SystemExit(f"FATAL: tarball extraction produced only {n} CVE json files "
                         f"(< {MIN_PLAUSIBLE_FILES}) - acquisition incomplete")
    meta = {"mode": "tarball", "url": TARBALL_URL, "files": n,
            "tarball_bytes": os.path.getsize(tarball)}
    if tarball_sha:
        meta["tarball_sha256"] = tarball_sha
    return meta


def main() -> int:
    ap = argparse.ArgumentParser(description="Bulk-acquire CVEProject/cvelistV5 (resumable, idempotent)")
    ap.add_argument("--out-dir", default=None, help="default: <repo>/stream/cache/cvelistV5")
    ap.add_argument("--mode", default="auto", choices=["auto", "clone", "tarball"])
    ap.add_argument("--force", action="store_true", help="re-acquire even if cached")
    args = ap.parse_args()

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    out_dir = args.out_dir or os.path.join(repo_root, "stream", "cache", "cvelistV5")
    os.makedirs(out_dir, exist_ok=True)

    if not args.force:
        meta = verified(out_dir)
        if meta is not None:
            _log(f"already acquired (mode={meta.get('mode')}, files={meta.get('recount_files', meta.get('files'))}); "
                 f"nothing to do (use --force to redo)")
            return 0

    try:
        if args.mode == "clone":
            meta = acquire_clone(out_dir, args.force)
        elif args.mode == "tarball":
            meta = acquire_tarball(out_dir, args.force)
        else:
            try:
                meta = acquire_clone(out_dir, args.force)
            except (subprocess.CalledProcessError, SystemExit) as e:
                _log(f"clone mode failed ({e}); falling back to tarball mode")
                meta = acquire_tarball(out_dir, args.force)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"FATAL: cvelistV5 acquisition failed: {e}") from e

    write_source_meta(out_dir, meta)
    total = meta.get("files", 0)
    _log(f"DONE: {total} CVE json files under {out_dir}/src/cves "
         f"({', '.join(_years())})")
    if total < MIN_PLAUSIBLE_FILES:
        print(f"FATAL: only {total} files - refusing to continue", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
