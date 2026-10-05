"""
Unit and Regression Test: Mathematical Metrics Consistency & Wilson Score CI Verification.
Verifies that precision, recall, F1, FPR, and FNR strictly match confusion matrix counts (TP, FP, FN, TN),
and verifies the exact 95% Wilson score confidence interval implementation.
"""

import unittest
import math
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
from analysis.compute_metrics import compute_wilson_ci, evaluate_prediction_file


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

    def test_mode_b_mathematical_consistency(self):
        """
        Mode B: TP=33, FP=6, FN=0, TN=17.
        Precision = 33/39 = 84.6% (NOT 85.7%).
        F1 = 66/72 = 91.7% (NOT 92.3%).
        """
        tp, fp, fn, tn = 33, 6, 0, 17
        precision = tp / (tp + fp)
        recall = tp / (tp + fn)
        f1 = 2 * precision * recall / (precision + recall)
        fpr = fp / (fp + tn)

        self.assertAlmostEqual(precision, 33 / 39, places=4)
        self.assertAlmostEqual(precision * 100, 84.615, places=2)
        self.assertAlmostEqual(recall, 1.0, places=4)
        self.assertAlmostEqual(f1, 66 / 72, places=4)
        self.assertAlmostEqual(f1 * 100, 91.667, places=2)
        self.assertAlmostEqual(fpr, 6 / 23, places=4)

    def test_mode_a_mathematical_consistency(self):
        """
        Mode A: TP=32, FP=9, FN=1, TN=14.
        Precision = 32/41 = 78.0% (NOT 80.5%).
        Recall = 32/33 = 97.0%.
        F1 = 64/74 = 86.5% (NOT 87.9%).
        """
        tp, fp, fn, tn = 32, 9, 1, 14
        precision = tp / (tp + fp)
        recall = tp / (tp + fn)
        f1 = 2 * precision * recall / (precision + recall)
        fpr = fp / (fp + tn)

        self.assertAlmostEqual(precision, 32 / 41, places=4)
        self.assertAlmostEqual(precision * 100, 78.049, places=2)
        self.assertAlmostEqual(recall, 32 / 33, places=4)
        self.assertAlmostEqual(f1, 64 / 74, places=4)
        self.assertAlmostEqual(f1 * 100, 86.486, places=2)
        self.assertAlmostEqual(fpr, 9 / 23, places=4)

    def test_cv_fold_5_mathematical_consistency(self):
        """
        CV Fold 5: TP=14, FP=14, FN=0, TN=42.
        Precision = 14/28 = 50.0% (NOT 66.7%).
        Recall = 14/14 = 100.0%.
        F1 = 1.0/1.5 = 66.7% (NOT 80.0%).
        """
        tp, fp, fn, tn = 14, 14, 0, 42
        precision = tp / (tp + fp)
        recall = tp / (tp + fn)
        f1 = 2 * precision * recall / (precision + recall)
        fpr = fp / (fp + tn)

        self.assertAlmostEqual(precision, 0.5000, places=4)
        self.assertAlmostEqual(recall, 1.0000, places=4)
        self.assertAlmostEqual(f1, 2 / 3, places=4)
        self.assertAlmostEqual(f1 * 100, 66.667, places=2)
        self.assertAlmostEqual(fpr, 14 / 56, places=4)

    def test_computed_metrics_json_internal_consistency(self):
        """Verifies that computed_metrics.json has zero mathematical contradictions."""
        metrics_file = ROOT_DIR / "results" / "computed_metrics.json"
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

    def test_rejection_of_old_erroneous_paper_numbers(self):
        """
        Confirms that the old hand-typed draft numbers fail mathematical consistency assertions:
        - Mode B old (85.7%, 92.3%)
        - Mode A old (80.5%, 87.9%)
        - Fold 5 old (66.7%, 80.0%)
        - Clopper-Pearson bounds vs Wilson score (89.4% vs 89.6%, 73.5% vs 75.8%)
        """
        # Mode B: raw counts 33 TP, 6 FP
        true_p_mode_b = 33 / 39
        old_paper_p_mode_b = 0.857
        self.assertNotAlmostEqual(true_p_mode_b, old_paper_p_mode_b, places=3)

        # Mode A: raw counts 32 TP, 9 FP
        true_p_mode_a = 32 / 41
        old_paper_p_mode_a = 0.805
        self.assertNotAlmostEqual(true_p_mode_a, old_paper_p_mode_a, places=3)

        # Fold 5: raw counts 14 TP, 14 FP
        true_p_f5 = 14 / 28
        old_paper_p_f5 = 0.667
        self.assertNotAlmostEqual(true_p_f5, old_paper_p_f5, places=3)

        # Wilson CI bound vs old Clopper-Pearson
        _, lo_33, _ = compute_wilson_ci(33, 33)
        old_cp_lo_33 = 0.894
        self.assertNotAlmostEqual(lo_33, old_cp_lo_33, places=3)

    def test_pooled_cross_validation_consistency(self):
        """Verifies exact pooled (micro-averaged) cross-validation metrics across all 5 folds."""
        pooled_tp = 48 + 70 + 39 + 29 + 14  # 200
        pooled_fp = 9 + 1 + 9 + 8 + 14      # 41
        pooled_fn = 0
        pooled_tn = 22 + 5 + 31 + 29 + 42   # 129
        pooled_n = pooled_tp + pooled_fp + pooled_fn + pooled_tn  # 370

        self.assertEqual(pooled_n, 370)
        self.assertEqual(pooled_tp, 200)
        self.assertEqual(pooled_fp, 41)

        pooled_prec = pooled_tp / (pooled_tp + pooled_fp)  # 200 / 241 = 0.829875
        pooled_rec = pooled_tp / (pooled_tp + pooled_fn)   # 1.0
        pooled_f1 = 2 * pooled_prec * pooled_rec / (pooled_prec + pooled_rec)  # 400 / 441 = 0.907029
        pooled_fpr = pooled_fp / (pooled_fp + pooled_tn)   # 41 / 170 = 0.241176

        self.assertAlmostEqual(pooled_prec * 100, 82.9875, places=2)
        self.assertAlmostEqual(pooled_f1 * 100, 90.7029, places=2)
        self.assertAlmostEqual(pooled_fpr * 100, 24.1176, places=2)


if __name__ == "__main__":
    unittest.main()

