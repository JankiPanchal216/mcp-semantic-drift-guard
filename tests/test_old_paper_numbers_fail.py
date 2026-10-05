"""
Demonstration: Asserts the historical draft paper numbers against ground-truth confusion matrix math.
Every test below is marked @unittest.expectedFailure so `python -m unittest discover tests` passes.
"""

import unittest
from analysis.compute_metrics import compute_wilson_ci


class TestHistoricalPaperNumbersMustFail(unittest.TestCase):

    @unittest.expectedFailure
    def test_mode_b_old_numbers_fail(self):
        # Raw counts: TP=33, FP=6 -> True precision = 33/39 = 84.615%, F1 = 91.667%
        tp, fp, fn = 33, 6, 0
        real_precision = tp / (tp + fp)
        real_f1 = 2 * real_precision * 1.0 / (real_precision + 1.0)
        # Old paper claimed: Precision = 85.7%, F1 = 92.3%
        self.assertEqual(round(real_precision * 100, 1), 85.7, "Mode B Precision 85.7% is mathematically impossible for TP=33, FP=6")

    @unittest.expectedFailure
    def test_mode_a_old_numbers_fail(self):
        # Raw counts: TP=32, FP=9, FN=1 -> True precision = 32/41 = 78.049%, F1 = 86.486%
        tp, fp, fn = 32, 9, 1
        real_precision = tp / (tp + fp)
        real_recall = tp / (tp + fn)
        real_f1 = 2 * real_precision * real_recall / (real_precision + real_recall)
        # Old paper claimed: Precision = 80.5%, F1 = 87.9%
        self.assertEqual(round(real_precision * 100, 1), 80.5, "Mode A Precision 80.5% is mathematically impossible for TP=32, FP=9")

    @unittest.expectedFailure
    def test_cv_fold_5_old_numbers_fail(self):
        # Raw counts: TP=14, FP=14 -> True precision = 14/28 = 50.000%, F1 = 66.667%
        tp, fp = 14, 14
        real_precision = tp / (tp + fp)
        real_f1 = 2 * real_precision * 1.0 / (real_precision + 1.0)
        # Old paper claimed: Precision = 66.7%, F1 = 80.0%
        self.assertEqual(round(real_precision * 100, 1), 66.7, "Fold 5 Precision 66.7% is mathematically impossible for TP=14, FP=14")

    @unittest.expectedFailure
    def test_clopper_pearson_bounds_fail_against_wilson(self):
        # 33/33 Wilson 95% lower bound = 89.6% (0.8957)
        _, lo_33, _ = compute_wilson_ci(33, 33)
        # Old paper cited Clopper-Pearson bound 89.4%
        self.assertEqual(round(lo_33 * 100, 1), 89.4, "Wilson score 95% lower bound for 33/33 is 89.6%, not 89.4%")


if __name__ == "__main__":
    unittest.main()
