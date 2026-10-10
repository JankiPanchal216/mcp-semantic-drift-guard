"""
tests/test_v4_baselines_and_novelty.py - Validates integrity of Phase 2 and Phase 3 result artifacts.
"""

import json
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestV4BaselinesAndNovelty(unittest.TestCase):
    def test_v4_baselines_summary_integrity(self):
        p = ROOT_DIR / "results" / "baselines_v4" / "baselines_summary.json"
        self.assertTrue(p.exists(), "baselines_summary.json must exist")
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("baselines_test_results", data)
        self.assertIn("param_delta_matched_fpr_50", data["baselines_test_results"])
        self.assertIn("tfidf_matched_fpr_0", data["baselines_test_results"])

    def test_novel_methods_summary_integrity(self):
        p = ROOT_DIR / "results" / "novel_methods_v4" / "novel_methods_summary.json"
        self.assertTrue(p.exists(), "novel_methods_summary.json must exist")
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("held_out_test_results", data)
        self.assertIn("Capability-Set Tracking (Root-Anchored)", data["held_out_test_results"])
        self.assertIn("Calibrated Drift Budget (B*=4.1)", data["held_out_test_results"])


if __name__ == "__main__":
    unittest.main()
