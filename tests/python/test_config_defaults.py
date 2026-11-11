"""Contract tests for the production NCD defaults and eval/production parity.

Run with:
    python3 -m unittest discover -s tests/python -v
"""
from __future__ import annotations

import ast
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# The config is evaluated at import time, so remove ambient overrides first.
for _key in (
    "NCD_USE_DIFF",
    "NCD_UMAP_REFIT_INTERVAL",
    "NCD_UMAP_RANDOM_STATE",
    "NCD_UMAP_N_JOBS",
):
    os.environ.pop(_key, None)

sys.path.insert(0, str(ROOT / "ncdbody"))

from app.config import NcdConfig  # noqa: E402


def _eval_pins() -> dict[str, object]:
    """Read the constant cfg.<attr> assignments inside benchmark/wallclock.py.

    A full import would load torch/UMAP and make this suite slow; the AST keeps
    the parity check cheap while still failing if a pin is removed or changed.
    """
    source = (ROOT / "benchmark" / "wallclock.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    func = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "make_config"
    )
    pins: dict[str, object] = {}
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Constant):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "cfg"
            ):
                pins[target.attr] = node.value.value
    return pins


class ProductionDefaultsTest(unittest.TestCase):
    def test_deterministic_detection_defaults(self):
        self.assertIs(NcdConfig.USE_DIFF, True)
        self.assertEqual(NcdConfig.UMAP_REFIT_INTERVAL, 0)
        self.assertEqual(NcdConfig.UMAP_RANDOM_STATE, 42)
        self.assertEqual(NcdConfig.UMAP_N_JOBS, 1)

    def test_eval_harness_pins_match_production(self):
        pins = _eval_pins()

        self.assertIs(pins.get("USE_DIFF"), NcdConfig.USE_DIFF)
        self.assertEqual(pins.get("UMAP_REFIT_INTERVAL"), NcdConfig.UMAP_REFIT_INTERVAL)
        self.assertEqual(pins.get("UMAP_RANDOM_STATE"), NcdConfig.UMAP_RANDOM_STATE)
        self.assertEqual(pins.get("UMAP_N_JOBS"), NcdConfig.UMAP_N_JOBS)
        self.assertIs(pins.get("JUDGE_ENABLED"), False)


if __name__ == "__main__":
    unittest.main()
