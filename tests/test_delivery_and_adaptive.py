"""
tests/test_delivery_and_adaptive.py - Validates integrity of Phase 4 and Phase 5 result artifacts.
"""

import json
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestDeliveryAndAdaptive(unittest.TestCase):
    def test_adaptive_summary_integrity(self):
        p = ROOT_DIR / "results" / "adaptive_attacker" / "adaptive_summary.json"
        self.assertTrue(p.exists(), "adaptive_summary.json must exist")
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("results", data)
        self.assertIn("MCP Semantic Drift Guard (Adjacent, Rule b)", data["results"])
        self.assertEqual(data["results"]["MCP Semantic Drift Guard (Adjacent, Rule b)"]["n_chains"], 24)
        self.assertEqual(data["results"]["MCP Semantic Drift Guard (Adjacent, Rule b)"]["evaded_chains"], 2)

    def test_delivery_summary_integrity(self):
        p = ROOT_DIR / "results" / "delivery_layer" / "delivery_summary.json"
        self.assertTrue(p.exists(), "delivery_summary.json must exist")
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("all_tests_passed", data)
        self.assertTrue(data["all_tests_passed"])
        self.assertEqual(data["total_unvetted_delivered_before"], 5)
        self.assertEqual(data["total_unvetted_delivered_after"], 0)


if __name__ == "__main__":
    unittest.main()
