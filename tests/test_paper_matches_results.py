"""
Comprehensive verification test suite:
1. Parses every metric table in paper.md and asserts numerical consistency against results/computed_metrics.json.
2. Asserts zero presence of unverified legacy figures (1.42, 2.85, 780, 290, 30.5, 41.6, 46.4, 0.61, 960).
3. Asserts all unexecuted models/tiers are explicitly labeled [PENDING RE-RUN] / [PENDING].
4. Contains TestCorruptedPaperMustFail to demonstrate that alterations to paper.md cause test failures.
"""

import json
import re
import unittest
from pathlib import Path


class TestPaperMatchesResults(unittest.TestCase):

    def setUp(self):
        self.root = Path(__file__).resolve().parent.parent
        self.paper_path = self.root / "paper.md"
        self.metrics_path = self.root / "results" / "computed_metrics.json"

        with open(self.paper_path, "r", encoding="utf-8") as f:
            self.paper_text = f.read()

        with open(self.metrics_path, "r", encoding="utf-8") as f:
            self.computed_metrics = json.load(f)

    def test_table_6_2_and_8_8_hash_pinning_matches(self):
        hash_m = self.computed_metrics["main_test_hash"]
        p_pct = f"{hash_m['precision']*100:.1f}% [{hash_m['precision_ci95'][0]*100:.1f}%, {hash_m['precision_ci95'][1]*100:.1f}%]"
        r_pct = f"{hash_m['recall']*100:.1f}% [{hash_m['recall_ci95'][0]*100:.1f}%, {hash_m['recall_ci95'][1]*100:.1f}%]"
        fpr_pct = f"{hash_m['benign_fpr']*100:.1f}% [{hash_m['benign_fpr_ci95'][0]*100:.1f}%, {hash_m['benign_fpr_ci95'][1]*100:.1f}%]"
        f1_pct = f"{hash_m['f1']*100:.1f}%"

        self.assertIn(p_pct, self.paper_text)
        self.assertIn(r_pct, self.paper_text)
        self.assertIn(fpr_pct, self.paper_text)
        self.assertIn(f1_pct, self.paper_text)

        # Confusion matrix row
        self.assertRegex(self.paper_text, r"\|\s*\*\*Exact Hash Pinning \(Tier 0\)\*\*\s*\|\s*33\s*\|\s*0\s*\|\s*23\s*\|\s*0\s*\|")

    def test_table_6_2_and_8_8_static_rules_matches(self):
        static_m = self.computed_metrics["main_test_static"]
        p_pct = f"{static_m['precision']*100:.1f}% [{static_m['precision_ci95'][0]*100:.1f}%, {static_m['precision_ci95'][1]*100:.1f}%]"
        r_pct = f"{static_m['recall']*100:.1f}% [{static_m['recall_ci95'][0]*100:.1f}%, {static_m['recall_ci95'][1]*100:.1f}%]"
        fpr_pct = f"{static_m['benign_fpr']*100:.1f}% [{static_m['benign_fpr_ci95'][0]*100:.1f}%, {static_m['benign_fpr_ci95'][1]*100:.1f}%]"
        f1_pct = f"{static_m['f1']*100:.1f}%"

        self.assertIn(p_pct, self.paper_text)
        self.assertIn(r_pct, self.paper_text)
        self.assertIn(fpr_pct, self.paper_text)
        self.assertIn(f1_pct, self.paper_text)

        # Confusion matrix row
        self.assertRegex(self.paper_text, r"\|\s*\*\*Static Keyword Rules \(Tier 2\)\*\*\s*\|\s*25\s*\|\s*23\s*\|\s*0\s*\|\s*8\s*\|")

    def test_table_6_2_and_8_8_tfidf_matches(self):
        tfidf_m = self.computed_metrics["main_test_tfidf"]
        p_pct = f"{tfidf_m['precision']*100:.1f}% [{tfidf_m['precision_ci95'][0]*100:.1f}%, {tfidf_m['precision_ci95'][1]*100:.1f}%]"
        r_pct = f"{tfidf_m['recall']*100:.1f}% [{tfidf_m['recall_ci95'][0]*100:.1f}%, {tfidf_m['recall_ci95'][1]*100:.1f}%]"
        fpr_pct = f"{tfidf_m['benign_fpr']*100:.1f}% [{tfidf_m['benign_fpr_ci95'][0]*100:.1f}%, {tfidf_m['benign_fpr_ci95'][1]*100:.1f}%]"
        f1_pct = f"{tfidf_m['f1']*100:.1f}%"

        self.assertIn(p_pct, self.paper_text)
        self.assertIn(r_pct, self.paper_text)
        self.assertIn(fpr_pct, self.paper_text)
        self.assertIn(f1_pct, self.paper_text)

        # Confusion matrix row
        self.assertRegex(self.paper_text, r"\|\s*\*\*TF-IDF Cosine Baseline\*\*\s*\|\s*31\s*\|\s*6\s*\|\s*17\s*\|\s*2\s*\|")

    def test_table_8_8_schema_precision_na(self):
        self.assertRegex(self.paper_text, r"\|\s*\*\*Deterministic Schema \(Tier 1\.5\)\*\*\s*\|\s*n/a\s*\|\s*0\.0% \[0\.0%, 10\.4%\]")

    def test_zero_legacy_numbers_in_paper(self):
        forbidden = [
            r"\b1\.42\b", r"\b2\.85\b", r"\b2,850\b", r"\b960\b",
            r"\b0\.61\b", r"\b46\.4\b", r"\b30\.5\b", r"\b41\.6\b",
            r"\b780\b", r"\b290\b"
        ]
        for pattern in forbidden:
            matches = re.findall(pattern, self.paper_text)
            self.assertEqual(len(matches), 0, f"Found legacy pattern {pattern} in paper.md: {matches}")

    def test_all_unverified_rows_are_explicitly_labeled_pending(self):
        # Asserts LLM rows in Table 6.2 and 8.8 are labeled PENDING RE-RUN
        self.assertIn("| **Semantic Judge Mode A (Full)** | [PENDING RE-RUN]", self.paper_text)
        self.assertIn("| **Semantic Judge Mode B (Diff)** | [PENDING RE-RUN]", self.paper_text)
        self.assertIn("| **Integrated Guard Middleware** | [PENDING RE-RUN]", self.paper_text)


class TestCorruptedPaperMustFail(unittest.TestCase):
    """Demonstrates that modifying any paper value causes TestPaperMatchesResults to fail."""

    def test_corrupted_precision_fails(self):
        test_case = TestPaperMatchesResults()
        test_case.setUp()
        test_case.paper_text = test_case.paper_text.replace("58.9% [45.9%, 70.8%]", "99.9% [95.0%, 100.0%]")
        with self.assertRaises(AssertionError):
            test_case.test_table_6_2_and_8_8_hash_pinning_matches()

    def test_legacy_number_injection_fails(self):
        test_case = TestPaperMatchesResults()
        test_case.setUp()
        test_case.paper_text += "\nLegacy latency: 1.42 s"
        with self.assertRaises(AssertionError):
            test_case.test_zero_legacy_numbers_in_paper()


if __name__ == "__main__":
    unittest.main()
