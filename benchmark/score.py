"""Cycepta scalar score for the Arbor run (measurement plumbing, not product code).

Runs the realistic stream replay (benchmark/run.py) and prints ONE scalar:

    score: <float>

Formula (maximize):

    lead_all[t] = max(0, mass_period[t] - first_flag_period[t]) for EVERY mass
                  topic t (a MISSED topic contributes 0 days, not silence)
    score = mean(lead_all) * 7 days * min(1, precision/P0) * min(1, recall/R0)

  P0 = R0 = 0.8333  (trunk baseline on realistic/dev, seed=11)

Interpretation: how many DAYS earlier (on average) the engine flags a topic that
later becomes mass-adopted, with missed topics counted as 0 and a multiplicative
guardrail so quality losses shrink the score instead of trading away
precision/recall for lead time. Ceiling on the realistic stream:
(7+8+8+9+10+10)/6*7 = 60.67 days (flag each topic at its first appearance).

Splits:
  --split dev   : realistic, seed=11  (iteration)
  --split test  : realistic, seed=23  (merge verification ONLY)

Usage:
  python3 benchmark/score.py --split dev
  python3 benchmark/score.py --split dev --viz /tmp/viz.png --metrics-json /tmp/m.json
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

SEEDS = {"dev": 11, "test": 23}
P0 = 0.8333
R0 = 0.8333

_HERE = os.path.dirname(os.path.abspath(__file__))


def run_replay(split: str, mode: str = "blob") -> dict:
    cmd = [sys.executable, os.path.join(_HERE, "run.py"),
           "--dataset", "realistic", "--seed", str(SEEDS[split]),
           "--mode", mode, "--json"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def main():
    ap = argparse.ArgumentParser(description="Cycepta scalar score")
    ap.add_argument("--split", choices=["dev", "test"], default="dev")
    ap.add_argument("--mode", default="blob", choices=["blob", "gmm"])
    ap.add_argument("--viz", default=None, help="write a PNG visualization here")
    ap.add_argument("--metrics-json", default=None, help="write full metrics JSON here")
    args = ap.parse_args()

    report = run_replay(args.split, args.mode)
    key = f"engine[{args.mode}]"
    m = report["results"][key]["metrics"]
    eng = report["results"][key].get("engine", {})

    # Missed mass topics contribute 0 lead days (not silence).
    lead = {k: v for k, v in (m.get("lead_periods") or {}).items()}
    mass_topics = report.get("mass_topics") or []
    per_topic = {t: lead.get(t, 0) for t in mass_topics}
    days_per_period = 7 if report.get("weekly") else 1
    lead_days = [v * days_per_period for v in per_topic.values()]
    avg_lead_days = sum(lead_days) / max(1, len(lead_days))

    prec, rec = m["precision@K"], m["recall@K"]
    score = avg_lead_days * min(1.0, prec / P0) * min(1.0, rec / R0)

    payload = {
        "split": args.split,
        "seed": SEEDS[args.split],
        "mode": args.mode,
        "score": round(score, 4),
        "avg_lead_days_all_topics": round(avg_lead_days, 3),
        "per_topic_lead_periods": per_topic,
        "metrics": m,
        "engine": eng,
    }
    if args.metrics_json:
        with open(args.metrics_json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)

    if args.viz:
        try:
            write_viz(payload, args.viz)
        except Exception as ex:  # viz is best-effort, never fails the score
            print(f"[viz-failed: {ex}]", file=sys.stderr)

    print(f"score: {score:.4f}")
    print(f"  split={args.split} seed={SEEDS[args.split]} mode={args.mode}")
    print(f"  avg_lead_days(all mass topics, missed=0)={avg_lead_days:.2f}  "
          f"precision={prec}  recall={rec}  F1={m['F1']}")
    print(f"  per_topic_lead_periods={per_topic}")
    print(f"  runtime_s={eng.get('runtime_s')}  emerging_flags={eng.get('emerging_flags')}")


def write_viz(payload: dict, path: str):
    """Two-panel viz for the researcher (NOT shipped in the product).

    Left  : per-topic lead time (periods) - bars for detected topics.
    Right : precision / recall / F1 vs trunk baseline.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    m = payload["metrics"]
    lead = payload.get("per_topic_lead_periods") or {}

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))

    ax = axes[0]
    if lead:
        topics = list(lead.keys())
        vals = [lead[t] for t in topics]
        colors = ["#2a9d8f" if v > 0 else "#e76f51" for v in vals]
        ax.bar(topics, vals, color=colors)
        ax.set_title(f"Lead time per topic (periods)  split={payload['split']}")
        ax.set_ylabel("periods before mass adoption")
        ax.tick_params(axis="x", rotation=35)
    else:
        ax.text(0.5, 0.5, "no topics detected", ha="center", va="center")
        ax.set_title("Lead time per topic")

    ax = axes[1]
    names = ["precision", "recall", "F1"]
    now = [m["precision@K"], m["recall@K"], m["F1"]]
    base = [P0, R0, 0.8333]
    xs = range(len(names))
    ax.bar([x - 0.18 for x in xs], base, width=0.36, label="baseline", color="#adb5bd")
    ax.bar([x + 0.18 for x in xs], now, width=0.36, label="this run", color="#457b9d")
    ax.set_xticks(list(xs))
    ax.set_xticklabels(names)
    ax.set_ylim(0, 1.05)
    ax.set_title(f"Quality vs baseline  score={payload['score']}")
    ax.legend()

    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    print(f"  viz -> {path}")


if __name__ == "__main__":
    main()
