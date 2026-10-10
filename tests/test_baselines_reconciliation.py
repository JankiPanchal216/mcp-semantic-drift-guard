"""
tests/test_baselines_reconciliation.py - Regression test verifying that all deterministic baselines
and matched-FPR points are computed identically via guard/baselines.py.
"""

import unittest
from pathlib import Path
from guard.baselines import evaluate_chain_baselines

ROOT_DIR = Path(__file__).resolve().parent.parent
BENCHMARK_FILE = ROOT_DIR / "data" / "salami_drift_benchmark_v3.jsonl"


class TestBaselinesReconciliation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = evaluate_chain_baselines(BENCHMARK_FILE)

    def test_total_chains(self):
        self.assertEqual(self.results["total_chains"], 40)

    def test_parameter_deltas_distribution(self):
        records = self.results["chain_records"]
        salami = [r for r in records if r["is_salami"]]
        fast = [r for r in records if r["is_fast"]]
        benign = [r for r in records if r["is_benign"]]

        self.assertEqual(len(salami), 16)
        self.assertEqual(len(fast), 8)
        self.assertEqual(len(benign), 16)

        # In V3, all 4-step salami chains reached delta=4
        for r in salami:
            self.assertEqual(r["max_param_delta"], 4, f"Chain {r['chain_id']} expected delta 4")

        # In V3, all 3-step fast-jump chains reached delta=3
        for r in fast:
            self.assertEqual(r["max_param_delta"], 3, f"Chain {r['chain_id']} expected delta 3")

        # In V3, Category C reached delta 4, Std Benign reached delta 3
        cat_c = [r for r in benign if r["total_steps"] == 4]
        std_ben = [r for r in benign if r["total_steps"] == 3]
        self.assertEqual(len(cat_c), 8)
        self.assertEqual(len(std_ben), 8)
        for r in cat_c:
            self.assertEqual(r["max_param_delta"], 4)
        for r in std_ben:
            self.assertEqual(r["max_param_delta"], 3)


if __name__ == "__main__":
    unittest.main()
