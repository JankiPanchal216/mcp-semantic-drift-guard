"""
Test Cross-Validation Server Leakage and Integrity.
Asserts:
1. All 370 benchmark items across train, dev, and test are partitioned with zero server overlap.
2. Exactly 19 unique servers exist across the dataset.
3. Every server belongs to exactly one fold.
4. paper.md Section 7.4 accurately states the number of unique servers (19).
"""

import re
import unittest
from pathlib import Path
from typing import Set

from experiments.cross_validate import load_all_benchmark_data, compute_server_group_kfolds


class TestCVLeakage(unittest.TestCase):

    def setUp(self):
        self.root = Path(__file__).resolve().parent.parent
        self.data_dir = self.root / "data"
        self.paper_path = self.root / "paper.md"
        self.items = load_all_benchmark_data(self.data_dir)
        self.folds = compute_server_group_kfolds(self.items, n_splits=5)

    def test_total_items_and_splits(self):
        self.assertEqual(len(self.items), 370, f"Expected 370 total benchmark items, got {len(self.items)}")

    def test_unique_server_count(self):
        all_servers = set(x.get("server_id") for x in self.items)
        self.assertEqual(len(all_servers), 19, f"Expected 19 unique servers, got {len(all_servers)}")

    def test_zero_server_leakage_across_folds(self):
        assigned_servers: Set[str] = set()
        for f in self.folds:
            f_servers = set(f["servers"])
            overlap = assigned_servers.intersection(f_servers)
            self.assertEqual(len(overlap), 0, f"Server leakage detected in Fold {f['fold']}: {overlap}")
            assigned_servers.update(f_servers)

        # Confirm all 19 unique servers are assigned
        all_servers = set(x.get("server_id") for x in self.items)
        self.assertEqual(assigned_servers, all_servers)

    def test_total_items_sum_across_folds(self):
        total_fold_items = sum(f["n_total"] for f in self.folds)
        self.assertEqual(total_fold_items, 370)

    def test_paper_mentions_correct_unique_server_count(self):
        with open(self.paper_path, "r", encoding="utf-8") as f:
            paper_text = f.read()

        # Check section 7.4 mentions 19 unique servers
        match = re.search(r"(\d+)\s+unique servers", paper_text)
        self.assertIsNotNone(match, "Could not find '<N> unique servers' in paper.md")
        stated_count = int(match.group(1))
        self.assertEqual(stated_count, 19, f"paper.md states {stated_count} unique servers, expected 19")


if __name__ == "__main__":
    unittest.main()
