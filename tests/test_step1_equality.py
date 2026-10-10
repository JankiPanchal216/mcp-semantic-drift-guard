"""
tests/test_step1_equality.py - Unit test asserting that Adjacent and Cumulative strategies
see identical diffs and produce identical alerts at Step 1 across all 40 benchmark chains.
"""

import json
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestStep1Equality(unittest.TestCase):
    def setUp(self):
        self.preds_adj_file = ROOT_DIR / "results" / "salami_drift_v3_per_step" / "predictions.jsonl"
        self.preds_cum_file = ROOT_DIR / "results" / "salami_drift_v3_cumulative" / "predictions.jsonl"
        self.preds_dual_file = ROOT_DIR / "results" / "salami_drift_v3_dual" / "predictions.jsonl"

    def test_step1_predictions_match_between_adjacent_and_cumulative(self):
        """Assert that at step_index == 1, Adjacent and Cumulative predictions match identically."""
        self.assertTrue(self.preds_adj_file.exists(), f"Missing {self.preds_adj_file}")
        self.assertTrue(self.preds_cum_file.exists(), f"Missing {self.preds_cum_file}")

        adj_preds = {}
        with open(self.preds_adj_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    if item.get("step_index") == 1:
                        adj_preds[item["chain_id"]] = item

        cum_preds = {}
        with open(self.preds_cum_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    if item.get("step_index") == 1:
                        cum_preds[item["chain_id"]] = item

        self.assertEqual(len(adj_preds), 40, "Expected 40 chains in benchmark")
        self.assertEqual(len(cum_preds), 40, "Expected 40 chains in benchmark")

        mismatches = []
        for cid, adj_item in adj_preds.items():
            cum_item = cum_preds.get(cid)
            self.assertIsNotNone(cum_item, f"Missing cumulative prediction for chain {cid}")
            
            # Compare verdict, action, and deciding_tier at step 1
            if (adj_item.get("verdict") != cum_item.get("verdict") or 
                adj_item.get("action") != cum_item.get("action") or
                adj_item.get("predicted_label") != cum_item.get("predicted_label")):
                mismatches.append((cid, adj_item, cum_item))

        self.assertEqual(
            len(mismatches), 0,
            f"Expected 0 mismatches at Step 1 between Adjacent and Cumulative, found {len(mismatches)}: {mismatches}"
        )

    def test_benign_step1_alert_counts_match(self):
        """Verify that per-step alert counts at Step 1 match across all benign chains."""
        self.assertTrue(self.preds_adj_file.exists(), f"Missing {self.preds_adj_file}")
        self.assertTrue(self.preds_cum_file.exists(), f"Missing {self.preds_cum_file}")

        adj_step1_benign_alerts = 0
        cum_step1_benign_alerts = 0

        with open(self.preds_adj_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    if item.get("step_index") == 1 and item.get("gold_label") == "BENIGN":
                        if item.get("predicted_label") == "MALICIOUS" or item.get("action") != "ALLOW":
                            adj_step1_benign_alerts += 1

        with open(self.preds_cum_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    if item.get("step_index") == 1 and item.get("gold_label") == "BENIGN":
                        if item.get("predicted_label") == "MALICIOUS" or item.get("action") != "ALLOW":
                            cum_step1_benign_alerts += 1

        self.assertEqual(
            adj_step1_benign_alerts, cum_step1_benign_alerts,
            f"Step 1 benign alerts must match: Adjacent={adj_step1_benign_alerts}, Cumulative={cum_step1_benign_alerts}"
        )


if __name__ == "__main__":
    unittest.main()
