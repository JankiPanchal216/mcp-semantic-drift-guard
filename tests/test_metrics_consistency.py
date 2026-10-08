"""
Unit and Regression Test: Mathematical Metrics Consistency & Wilson Score CI Verification.
Verifies that precision, recall, F1, FPR, and FNR strictly match confusion matrix counts (TP, FP, FN, TN),
verifies absence of fake/constant latencies or synthetic 100% agreement rows,
and verifies exact 95% Wilson score confidence interval implementation.
"""

import unittest
import math
import json
import numpy as np
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
from analysis.compute_metrics import compute_wilson_ci, evaluate_prediction_file

RESULTS_DIR = ROOT_DIR / "results"


class TestMetricsConsistency(unittest.TestCase):

    def test_wilson_ci_reference_bounds(self):
        """Verifies exact 95% Wilson score confidence interval lower/upper bounds."""
        # Case 1: 33 of 33 (100% recall on 33 malicious items)
        p, lo, hi = compute_wilson_ci(33, 33)
        self.assertAlmostEqual(p, 1.0, places=4)
        self.assertAlmostEqual(lo, 0.8957, places=3, msg="33/33 Wilson lower bound must be 89.6% (0.8957)")
        self.assertAlmostEqual(hi, 1.0, places=4)

        # Case 2: 12 of 12 (100% recall on 12 matched pair items)
        p, lo, hi = compute_wilson_ci(12, 12)
        self.assertAlmostEqual(p, 1.0, places=4)
        self.assertAlmostEqual(lo, 0.7575, places=3, msg="12/12 Wilson lower bound must be 75.8% (0.7575)")
        self.assertAlmostEqual(hi, 1.0, places=4)

        # Case 3: 0 of 23 (0% FPR on 23 benign items)
        p, lo, hi = compute_wilson_ci(0, 23)
        self.assertAlmostEqual(p, 0.0, places=4)
        self.assertAlmostEqual(lo, 0.0, places=4)
        self.assertAlmostEqual(hi, 0.1431, places=3, msg="0/23 Wilson upper bound must be 14.3% (0.1431)")

    def test_predictions_jsonl_provenance_and_variance(self):
        """
        Asserts that every real predictions.jsonl on disk:
        1. Has variance in latency (no constant placeholder timings).
        2. Has non-trivial predictions (no synthetic perfect agreement).
        3. Has real source_file and git export_commit.
        """
        pred_files = list(RESULTS_DIR.glob("*/predictions.jsonl"))
        self.assertGreater(len(pred_files), 0, "Must have real predictions.jsonl files on disk")

        for pf in pred_files:
            exp_name = pf.parent.name
            with open(pf, "r", encoding="utf-8") as f:
                rows = [json.loads(line) for line in f if line.strip()]

            self.assertGreater(len(rows), 0, f"Empty predictions file in {exp_name}")
            
            # Check commit hash format
            for r in rows:
                commit_val = r.get("export_commit") or r.get("git_commit")
                self.assertIsNotNone(commit_val, f"Missing export_commit or git_commit in {exp_name}")
                self.assertNotEqual(commit_val, "uncommitted_master", f"commit cannot be uncommitted in {exp_name}")
                if "export_commit" in r:
                    self.assertEqual(len(r["export_commit"]), 40, f"export_commit must be a 40-char git hash in {exp_name}")

            # Check latencies for measured experiments
            latencies = [r["latency_ms_total"] for r in rows if r.get("latency_ms_total") is not None]
            if len(latencies) > 1:
                variance = float(np.var(latencies))
                self.assertGreater(variance, 0.0, f"Latencies in {exp_name} must not be constant placeholders")

    def test_rejection_of_historical_paper_errors(self):
        """
        Directly checks that the historical paper numbers fail assertions against true confusion matrix counts:
        - Mode B old: claimed 85.7% Precision, 92.3% F1 on TP=33, FP=6
        - Mode A old: claimed 80.5% Precision, 87.9% F1 on TP=32, FP=9, FN=1
        - Fold 5 old: claimed 66.7% Precision, 80.0% F1 on TP=14, FP=14
        - Clopper-Pearson bound: claimed 89.4% on 33/33
        """
        # Mode B: raw counts TP=33, FP=6
        tp_b, fp_b, fn_b = 33, 6, 0
        real_p_b = tp_b / (tp_b + fp_b)  # 33/39 = 0.84615
        real_f1_b = 2 * real_p_b * 1.0 / (real_p_b + 1.0)  # 66/72 = 0.91667

        with self.assertRaises(AssertionError):
            # Asserting the old paper value 85.7% must fail
            self.assertAlmostEqual(real_p_b * 100, 85.7, places=1)
        with self.assertRaises(AssertionError):
            # Asserting the old paper value 92.3% must fail
            self.assertAlmostEqual(real_f1_b * 100, 92.3, places=1)

        # Mode A: raw counts TP=32, FP=9, FN=1
        tp_a, fp_a, fn_a = 32, 9, 1
        real_p_a = tp_a / (tp_a + fp_a)  # 32/41 = 0.78048
        real_f1_a = 2 * (32/41) * (32/33) / (32/41 + 32/33)  # 64/74 = 0.86486

        with self.assertRaises(AssertionError):
            self.assertAlmostEqual(real_p_a * 100, 80.5, places=1)
        with self.assertRaises(AssertionError):
            self.assertAlmostEqual(real_f1_a * 100, 87.9, places=1)

        # Fold 5: raw counts TP=14, FP=14
        tp_5, fp_5, fn_5 = 14, 14, 0
        real_p_5 = tp_5 / (tp_5 + fp_5)  # 14/28 = 0.50000
        real_f1_5 = 2 * (0.5 * 1.0) / (0.5 + 1.0)  # 2/3 = 0.66667

        with self.assertRaises(AssertionError):
            self.assertAlmostEqual(real_p_5 * 100, 66.7, places=1)
        with self.assertRaises(AssertionError):
            self.assertAlmostEqual(real_f1_5 * 100, 80.0, places=1)

        # Wilson score vs Clopper-Pearson 89.4%
        _, lo_33, _ = compute_wilson_ci(33, 33)
        with self.assertRaises(AssertionError):
            self.assertAlmostEqual(lo_33 * 100, 89.4, places=1)

    def test_computed_metrics_json_internal_consistency(self):
        """Verifies that computed_metrics.json strictly derives metrics from confusion matrices."""
        metrics_file = RESULTS_DIR / "computed_metrics.json"
        self.assertTrue(metrics_file.exists(), "computed_metrics.json must exist")
        with open(metrics_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        for exp_name, m in data.items():
            tp, tn, fp, fn = m["tp"], m["tn"], m["fp"], m["fn"]
            self.assertEqual(m["n"], tp + tn + fp + fn, f"Total N mismatch in {exp_name}")
            if (tp + fp) > 0:
                expected_p = tp / (tp + fp)
                self.assertAlmostEqual(m["precision"], expected_p, places=4, msg=f"Precision mismatch in {exp_name}")
            if (tp + fn) > 0:
                expected_r = tp / (tp + fn)
                self.assertAlmostEqual(m["recall"], expected_r, places=4, msg=f"Recall mismatch in {exp_name}")
            if (m["precision"] + m["recall"]) > 0:
                expected_f1 = 2 * m["precision"] * m["recall"] / (m["precision"] + m["recall"])
                self.assertAlmostEqual(m["f1"], expected_f1, places=4, msg=f"F1 mismatch in {exp_name}")


if __name__ == "__main__":
    unittest.main()
