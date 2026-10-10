"""
tests/test_make_tables.py - Unit test to ensure make_tables.py runs cleanly and reproduces paper numbers.
"""

import unittest
from pathlib import Path
import json
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.make_tables import (
    wilson_score_interval,
    parse_predictions_jsonl,
    generate_table_1_taxonomy,
    generate_table_2_held_out,
    generate_table_4_v3_transitions,
    generate_table_5_v3_chains
)


class TestMakeTables(unittest.TestCase):
    
    def test_wilson_ci_bounds(self):
        low, high = wilson_score_interval(33, 33)
        self.assertAlmostEqual(high, 1.0, places=4)
        self.assertGreater(low, 0.89)

    def test_parse_hash_predictions(self):
        pred_path = ROOT_DIR / "results" / "main_test_hash" / "predictions.jsonl"
        res = parse_predictions_jsonl(pred_path)
        self.assertEqual(res["tp"], 33)
        self.assertEqual(res["tn"], 0)
        self.assertEqual(res["fp"], 23)
        self.assertEqual(res["fn"], 0)
        self.assertAlmostEqual(res["recall"], 1.0, places=4)
        self.assertAlmostEqual(res["precision"], 33 / 56, places=3)

    def test_table_generation_non_empty(self):
        t1 = generate_table_1_taxonomy()
        self.assertIn("Exact Cryptographic Pinning", t1)
        self.assertIn("MCP Semantic Drift Guard", t1)

    def test_table_4_and_5_generation(self):
        audit_path = ROOT_DIR / "results" / "DECISION_RULE_AUDIT_DATA.json"
        with open(audit_path, "r", encoding="utf-8") as f:
            audit_data = json.load(f)
        t4 = generate_table_4_v3_transitions(audit_data)
        t5 = generate_table_5_v3_chains(audit_data)
        self.assertIn("Rule (b): Primary Deployed Policy", t4)
        self.assertIn("Rule (b): Primary Deployed Policy", t5)
        self.assertIn("93.8% (15/16)", t5)


if __name__ == "__main__":
    unittest.main()

