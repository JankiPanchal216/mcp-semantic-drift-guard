"""
tests/test_hash_pinning_v4.py - Unit tests verifying Hash Pinning semantics and split calibration isolation.
"""

import json
import unittest
from pathlib import Path
from experiments.evaluate_v4_baselines import run_all_baselines

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestHashPinningV4(unittest.TestCase):
    def test_hash_pinning_flags_all_modified_chains(self):
        results = run_all_baselines()
        pinning = results["baselines_test_results"]["exact_hash_pinning"]
        self.assertEqual(pinning["salami_only"]["rate"], 1.0, f"Expected 100% Salami recall for pinning, got {pinning['salami_only']['rate']}")
        self.assertEqual(pinning["fast_jump"]["rate"], 1.0, f"Expected 100% Fast-jump recall for pinning, got {pinning['fast_jump']['rate']}")
        self.assertEqual(pinning["all_malicious"]["rate"], 1.0, f"Expected 100% Malicious recall for pinning, got {pinning['all_malicious']['rate']}")
        self.assertEqual(pinning["benign_fpr"]["rate"], 1.0, f"Expected 100% Benign FPR for pinning, got {pinning['benign_fpr']['rate']}")
        self.assertEqual(pinning["salami_only"]["mean_exposure"], 0.0)

    def test_threshold_calibration_split_isolation(self):
        p = ROOT_DIR / "results" / "baselines_v4" / "baselines_summary.json"
        self.assertTrue(p.exists())
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        cal_ids = set(data["calibration_split"]["benign_chain_ids"])
        test_ids = set(data["held_out_test_split"]["test_chain_ids"])
        
        # Assert disjointness
        overlap = cal_ids.intersection(test_ids)
        self.assertEqual(len(overlap), 0, f"Data leakage detected! Calibration and test split overlap on: {overlap}")
        self.assertEqual(data["threshold_calibration_split"], "calibration (N=19 benign chains)")


if __name__ == "__main__":
    unittest.main()
