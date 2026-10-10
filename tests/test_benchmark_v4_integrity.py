"""
tests/test_benchmark_v4_integrity.py - Regression Test Suite for Benchmark V4 Dataset Integrity
"""

import json
import unittest
import hashlib
from pathlib import Path
from experiments.generate_salami_benchmark_v4 import generate_and_validate_benchmark_v4, OUTPUT_DATA_FILE

class TestBenchmarkV4Integrity(unittest.TestCase):
    def test_benchmark_v4_gates_and_scale(self):
        records, report, all_passed = generate_and_validate_benchmark_v4()
        
        self.assertTrue(all_passed, "All 10 benchmark quality gates must pass")
        self.assertGreaterEqual(report["total_chains"], 100, "V4 must contain >= 100 total chains")
        self.assertGreaterEqual(report["malicious_chains"], 60, "V4 must contain >= 60 malicious chains")
        self.assertGreaterEqual(report["benign_chains"], 40, "V4 must contain >= 40 benign control chains")
        
        # Trivial separator AUC checks
        sep = report["trivial_separator_metrics"]
        self.assertLess(sep["auc_chain_length"], 0.65, "Chain length AUC must be < 0.65")
        self.assertLess(sep["auc_cumulative_param_delta"], 0.65, "Cumulative parameter delta AUC must be < 0.65")
        self.assertLess(sep["auc_cumulative_levenshtein"], 0.65, "Cumulative Levenshtein AUC must be < 0.65")
        
        # Check docstring-only chains
        by_chain = {}
        for r in records:
            by_chain.setdefault(r["chain_id"], []).append(r)
            
        doc_only_mal = [
            cid for cid, steps in by_chain.items()
            if any(s["gold_label"] == "MALICIOUS" for s in steps) and
            all(len(s["metrics_evaluator_metadata"]["adjacent_params_added"]) == 0 for s in steps)
        ]
        self.assertGreaterEqual(len(doc_only_mal), 5, "V4 must contain pure docstring-only malicious erosion chains")
        
        # Check server disjointness
        cal_servers = set(r["server_id"] for r in records if r["metrics_evaluator_metadata"]["split"] == "calibration")
        test_servers = set(r["server_id"] for r in records if r["metrics_evaluator_metadata"]["split"] == "held_out_test")
        self.assertEqual(len(cal_servers.intersection(test_servers)), 0, "Calibration and test servers must be completely disjoint")

if __name__ == "__main__":
    unittest.main()
