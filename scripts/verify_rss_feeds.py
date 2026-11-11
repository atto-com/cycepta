#!/usr/bin/env python3
"""Verify RSS/Atom feed reachability and parseability for RssFeedParser.

Reads one feed URL per line (comments with # allowed), fetches each with a
browser-like User-Agent, and PASSes only when the response is a parseable
XML feed with at least one <item>/<entry>. Mirrors the acceptance path of
ThreatDetector.Parsing.Feeds.RssFeedParser, so a PASS here predicts a
successful ParseFeedAsync round.

Fetches go through the system curl so verification uses the same trust
store as the operator's shell; the bundled Python.framework has no CA
bundle of its own (certificate verify fails against real sites).

Usage:
  python3 scripts/verify_rss_feeds.py feeds.txt
  python3 scripts/verify_rss_feeds.py feeds.txt --workers 24 --timeout 12

Output: per-feed table, then a JSON summary with the sorted PASS list ready
to paste into the SecurityFeeds array.
"""

import argparse
import concurrent.futures
import json
import re
import subprocess
import tempfile
import urllib.error

USER_AGENT = "ThreatDetector/1.0 (security research)"

XML_MARK = re.compile(r"<\?xml|<rss[\s>]|<feed[\s>]|<rdf[\s>]", re.I)
ITEM = re.compile(r"<item[\s>]|<entry[\s>]", re.I)


def verify(url: str, timeout: float) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        proc = subprocess.run(
            ["curl", "-sS", "-L", "--http1.1", "--max-time", str(timeout),
             "--max-filesize", "400000", "-A", USER_AGENT,
             "-o", tmp_path, "-w", "%{http_code}", url],
            capture_output=True, text=True, timeout=timeout + 5)
        status_text = proc.stdout.strip()
        status = int(status_text) if status_text.isdigit() else 0
        if proc.returncode == 0 and status == 0:
            status = 200
    except Exception as e:
        return {"url": url, "ok": False, "status": 0, "items": 0, "reason": type(e).__name__}

    try:
        with open(tmp_path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return {"url": url, "ok": False, "status": status, "items": 0, "reason": "no body"}

    items = len(ITEM.findall(text))
    if status != 200:
        ok, reason = False, f"HTTP {status}"
    elif not XML_MARK.search(text[:1000]):
        ok, reason = False, "no XML/feed marker"
    elif items == 0:
        ok, reason = False, "0 items"
    else:
        ok, reason = True, f"{items} items"

    if status == 0:
        reason = f"curl: {proc.stderr.strip()[-60:] or 'no output'}"

    return {"url": url, "ok": ok, "status": status, "items": items, "reason": reason}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("list_file")
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--timeout", type=float, default=12.0)
    args = ap.parse_args()

    urls = []
    with open(args.list_file, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    urls = list(dict.fromkeys(urls))

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda u: verify(u, args.timeout), urls))

    results.sort(key=lambda r: (not r["ok"], r["url"]))
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        print(f"{mark}  {r['status']:>4}  {r['items']:>4}  {r['reason']:<24} {r['url']}")

    passed = sorted(r["url"] for r in results if r["ok"])
    failed = sorted(r["url"] for r in results if not r["ok"])
    summary = {
        "total": len(results),
        "passed": len(passed),
        "failed": len(failed),
        "passing_urls": passed,
        "failing_urls": failed,
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
