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

    def test_hybrid_guard_disjunction_recall(self):
        """Verifies that a boolean OR disjunction of detectors satisfies per-chain recall >= each component
        under any-after-onset detection, and verifies the strict first-alarm anomaly where premature false alarms
        prior to onset (d < m) cause strict recall to drop."""
        from experiments.evaluate_novel_methods_v4 import load_v4_chains_and_predictions, evaluate_capability_delta

        chains, adj_preds, cum_preds = load_v4_chains_and_predictions()
        test_cids = [cid for cid, steps in chains.items() if steps[0]["metrics_evaluator_metadata"]["split"] == "held_out_test"]
        test_mal = [cid for cid in test_cids if not chains[cid][0]["category"].startswith("C_")]

        # 1. Verify that for ANY chain, any-after-onset detection for (A or B) >= A and >= B
        def cap_alert(s):
            return evaluate_capability_delta(s["root_tool_definition"], s["tool_definition"])["flagged"]

        def adj_alert(s):
            return adj_preds.get(s["item_id"], {}).get("rule_verdicts", {}).get("rule_b_balanced", False)

        for cid in test_mal:
            steps = sorted(chains[cid], key=lambda x: x["step_index"])
            m_step = next((s["step_index"] for s in steps if s["gold_label"] == "MALICIOUS"), None)
            det_adj = any(adj_alert(s) for s in steps if s["step_index"] >= m_step)
            det_cap = any(cap_alert(s) for s in steps if s["step_index"] >= m_step)
            det_hybrid = any((adj_alert(s) or cap_alert(s)) for s in steps if s["step_index"] >= m_step)

            self.assertTrue(det_hybrid >= det_adj, f"Chain {cid}: Hybrid ({det_hybrid}) must be >= Adj ({det_adj})")
            self.assertTrue(det_hybrid >= det_cap, f"Chain {cid}: Hybrid ({det_hybrid}) must be >= Cap ({det_cap})")

        # 2. Strict metric analysis: first alarm >= m_step
        def strict_det(alert_fn, cid):
            steps = sorted(chains[cid], key=lambda x: x["step_index"])
            m_step = next((s["step_index"] for s in steps if s["gold_label"] == "MALICIOUS"), None)
            first_alert = next((s["step_index"] for s in steps if alert_fn(s)), None)
            return first_alert is not None and m_step is not None and first_alert >= m_step

        adj_strict = sum(strict_det(adj_alert, cid) for cid in test_mal)
        cap_strict = sum(strict_det(cap_alert, cid) for cid in test_mal)
        hybrid_strict = sum(strict_det(lambda s: adj_alert(s) or cap_alert(s), cid) for cid in test_mal)

        self.assertEqual(adj_strict, 32, "Adjacent alone detects 32/33 under strict recall")
        self.assertEqual(cap_strict, 23, "Capability tracking alone detects 23/33 under strict recall")
        self.assertEqual(hybrid_strict, 28, "Under strict recall, premature capability flags at step 2 drop hybrid to 28/33")


if __name__ == "__main__":
    unittest.main()
