#!/usr/bin/env python3
"""Purge boilerplate concepts already persisted by the ThreatDetector API.

Uses the same filter as the NCD engine (app.input_hygiene), so the DB
cleanup and the ingestion filter can never drift apart. Idempotent:
re-running on a clean DB deletes nothing.

Also collapses concepts that share one label across periods (blob linking
merges them going forward; historical duplicates are collapsed to the
strongest instance).

Usage: python3 clean_boilerplate_concepts.py [path/to/threats.db]
       (default: repo-relative API db path)
"""
from __future__ import annotations

import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "ncdbody"))

from app.input_hygiene import is_boilerplate  # noqa: E402


def main() -> int:
    db = Path(sys.argv[1] if len(sys.argv) > 1
              else REPO / "ThreatDetector/src/ThreatDetector.Api/threats.db")
    con = sqlite3.connect(str(db))
    cur = con.cursor()

    rows = cur.execute("SELECT id, label, summary, document_count FROM concepts").fetchall()
    boiler = [r for r in rows if is_boilerplate(r[1]) or is_boilerplate((r[2] or "")[:80])]

    by_label: dict[str, list] = defaultdict(list)
    for r in rows:
        by_label[r[1].strip().lower()].append(r)
    dupes = [r for group in by_label.values() if len(group) > 1
             for r in sorted(group, key=lambda x: (-x[3], x[0]))[1:]]

    victims = {r[0] for r in boiler} | {r[0] for r in dupes}
    victims.discard("")

    for cid in sorted(victims):
        cur.execute("DELETE FROM concept_documents WHERE concept_id = ?", (cid,))
        cur.execute("DELETE FROM concept_events WHERE concept_id = ?", (cid,))
        cur.execute("DELETE FROM concepts WHERE id = ?", (cid,))
    con.commit()

    print(f"concepts total:        {len(rows)}")
    print(f"  boilerplate:         {len(boiler)}")
    print(f"  duplicate-label:     {len(dupes)}")
    print(f"deleted concept rows:  {len(victims)}")
    for r in boiler[:10]:
        print("  boiler:", r[0], "|", (r[1] or "")[:60])
    for r in dupes[:10]:
        print("  dupe:  ", r[0], "|", (r[1] or "")[:60])
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
