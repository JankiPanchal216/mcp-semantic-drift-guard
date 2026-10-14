"""
tests/test_v4h_dataset.py - Asserts schema and structural integrity of data/history_necessary_v4h.jsonl.
"""

import json
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestV4HDataset(unittest.TestCase):
    def setUp(self):
        self.v4h_path = ROOT_DIR / "data" / "history_necessary_v4h.jsonl"
        self.assertTrue(self.v4h_path.exists(), f"Missing {self.v4h_path}")
        with open(self.v4h_path, "r", encoding="utf-8") as f:
            self.records = [json.loads(line) for line in f if line.strip()]

    def test_record_counts(self):
        self.assertEqual(len(self.records), 72, "V4-H must contain exactly 72 transition records (24 chains x 3 steps)")
        chains = {}
        for r in self.records:
            chains.setdefault(r["chain_id"], []).append(r)
        self.assertEqual(len(chains), 24, "V4-H must contain exactly 24 chains")

        attack_chains = [c for c, steps in chains.items() if steps[-1]["gold_label"] == "MALICIOUS"]
        benign_chains = [c for c, steps in chains.items() if steps[-1]["gold_label"] == "BENIGN"]
        self.assertEqual(len(attack_chains), 12, "V4-H must have exactly 12 attack chains")
        self.assertEqual(len(benign_chains), 12, "V4-H must have exactly 12 benign control chains")

    def test_schema_fields_and_provenance(self):
        required_fields = [
            "item_id", "chain_id", "category", "attack_family", "step_index",
            "total_steps", "server_id", "tool_name", "gold_label",
            "intended_semantic_change", "benchmark_version", "generator_version",
            "provenance", "root_tool_definition", "previous_tool_definition",
            "tool_definition", "metrics_evaluator_metadata"
        ]
        for r in self.records:
            for field in required_fields:
                self.assertIn(field, r, f"Record {r.get('item_id')} missing field {field}")
            self.assertTrue(r["provenance"], f"Record {r.get('item_id')} has empty provenance")
            self.assertEqual(r["category"], "H", f"Record {r.get('item_id')} category must be 'H'")
            self.assertEqual(r["metrics_evaluator_metadata"]["split"], "history_necessary_test")

    def test_step_sequence_and_labels(self):
        chains = {}
        for r in self.records:
            chains.setdefault(r["chain_id"], []).append(r)

        for cid, steps in chains.items():
            self.assertEqual(len(steps), 3, f"Chain {cid} must have exactly 3 steps")
            steps.sort(key=lambda x: x["step_index"])
            indices = [s["step_index"] for s in steps]
            self.assertEqual(indices, [1, 2, 3], f"Chain {cid} step indices must be [1, 2, 3]")

            is_attack = (steps[-1]["gold_label"] == "MALICIOUS")
            if is_attack:
                self.assertEqual(steps[0]["gold_label"], "BENIGN", f"Chain {cid} step 1 must be BENIGN")
                self.assertEqual(steps[1]["gold_label"], "BENIGN", f"Chain {cid} step 2 must be BENIGN")
                self.assertEqual(steps[2]["gold_label"], "MALICIOUS", f"Chain {cid} step 3 must be MALICIOUS")
                self.assertEqual(steps[2]["attack_onset_step"], 3, f"Chain {cid} onset must be 3")
            else:
                for s in steps:
                    self.assertEqual(s["gold_label"], "BENIGN", f"Benign chain {cid} step {s['step_index']} must be BENIGN")
                    self.assertIsNone(s.get("attack_onset_step"), f"Benign chain {cid} must have null onset")


if __name__ == "__main__":
    unittest.main()
