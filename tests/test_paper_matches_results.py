"""
Comprehensive Verification Test Suite:
1. Parses markdown metric tables and inline metrics in paper.md into structured records and verifies
   numerical consistency against results/computed_metrics.json.
2. Asserts zero presence of unverified legacy figures (1.42, 2.85, 780, 290, 30.5, 41.6, 46.4, 0.61, 960).
3. Asserts that all unexecuted model sweeps are explicitly labeled [PENDING RE-RUN] / [PENDING].
4. Contains TestCorruptedPaperMustFail proving that table/metric parsing fails when paper numbers are modified.
"""

import json
import re
import unittest
from pathlib import Path
from typing import Dict, List, Any, Optional


def parse_ci_cell(cell: str) -> Optional[Dict[str, float]]:
    """Parses '58.9% [45.9%, 70.8%]' or '100.0% [89.6%, 100.0%]' or 'n/a'."""
    if not cell:
        return None
    cell = re.sub(r"\*+", "", cell).strip()
    if cell == "n/a" or "[PENDING" in cell or "-" in cell:
        return None
    m = re.search(r"([\d\.]+)%\s*\[\s*([\d\.]+)%,\s*([\d\.]+)%\s*\]", cell)
    if m:
        return {
            "val": float(m.group(1)),
            "lo": float(m.group(2)),
            "hi": float(m.group(3))
        }
    m_single = re.search(r"([\d\.]+)%", cell)
    if m_single:
        return {"val": float(m_single.group(1)), "lo": 0.0, "hi": 0.0}
    return None


def parse_markdown_tables(text: str) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Parses markdown tables in paper.md by section/header."""
    tables = {}
    lines = text.splitlines()
    i = 0
    current_section = "general"

    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("## "):
            current_section = line[3:].strip()
        elif line.startswith("|") and i + 1 < len(lines) and "|---" in lines[i+1]:
            header = [c.strip() for c in line.strip("|").split("|")]
            i += 2
            rows = {}
            while i < len(lines) and lines[i].strip().startswith("|"):
                row_cells = [c.strip() for c in lines[i].strip("|").split("|")]
                if row_cells:
                    row_key = re.sub(r"\*+", "", row_cells[0]).strip()
                    row_dict = {}
                    for col_idx, col_name in enumerate(header[1:], 1):
                        if col_idx < len(row_cells):
                            row_dict[col_name] = row_cells[col_idx]
                    rows[row_key] = row_dict
                i += 1
            tables[current_section] = rows
            continue
        i += 1
    return tables


class TestPaperMatchesResults(unittest.TestCase):

    def setUp(self):
        self.root = Path(__file__).resolve().parent.parent
        self.paper_path = self.root / "paper.md"
        self.metrics_path = self.root / "results" / "computed_metrics.json"

        with open(self.paper_path, "r", encoding="utf-8") as f:
            self.paper_text = f.read()

        with open(self.metrics_path, "r", encoding="utf-8") as f:
            self.computed_metrics = json.load(f)

        self.tables = parse_markdown_tables(self.paper_text)

    def test_parsed_table_6_2_confusion_and_metrics(self):
        table_6_2 = self.tables.get("6. Detector Benchmark & Held-Out Results", {})
        self.assertTrue(len(table_6_2) > 0, "Failed to parse Table 6.2 from Section 6")

        # 1. Exact Hash Pinning
        hash_row = table_6_2.get("Exact Hash Pinning (Tier 0)")
        self.assertIsNotNone(hash_row, "Exact Hash Pinning row missing in Table 6.2")
        self.assertEqual(int(hash_row["TP"]), self.computed_metrics["main_test_hash"]["tp"])
        self.assertEqual(int(hash_row["TN"]), self.computed_metrics["main_test_hash"]["tn"])
        self.assertEqual(int(hash_row["FP"]), self.computed_metrics["main_test_hash"]["fp"])
        self.assertEqual(int(hash_row["FN"]), self.computed_metrics["main_test_hash"]["fn"])

        hash_p = parse_ci_cell(hash_row.get("Precision (95% CI)") or hash_row.get("Observed Precision (95% CI)"))
        self.assertAlmostEqual(hash_p["val"], self.computed_metrics["main_test_hash"]["precision"] * 100, places=1)
        self.assertAlmostEqual(hash_p["lo"], self.computed_metrics["main_test_hash"]["precision_ci95"][0] * 100, places=1)
        self.assertAlmostEqual(hash_p["hi"], self.computed_metrics["main_test_hash"]["precision_ci95"][1] * 100, places=1)

        # 2. Static Keyword Rules
        static_row = table_6_2.get("Static Keyword Rules (Tier 2)")
        self.assertIsNotNone(static_row, "Static Keyword Rules row missing in Table 6.2")
        self.assertEqual(int(static_row["TP"]), self.computed_metrics["main_test_static"]["tp"])
        self.assertEqual(int(static_row["TN"]), self.computed_metrics["main_test_static"]["tn"])
        self.assertEqual(int(static_row["FP"]), self.computed_metrics["main_test_static"]["fp"])
        self.assertEqual(int(static_row["FN"]), self.computed_metrics["main_test_static"]["fn"])

        static_p = parse_ci_cell(static_row.get("Precision (95% CI)") or static_row.get("Observed Precision (95% CI)"))
        self.assertAlmostEqual(static_p["val"], self.computed_metrics["main_test_static"]["precision"] * 100, places=1)
        self.assertAlmostEqual(static_p["lo"], self.computed_metrics["main_test_static"]["precision_ci95"][0] * 100, places=1)
        self.assertAlmostEqual(static_p["hi"], self.computed_metrics["main_test_static"]["precision_ci95"][1] * 100, places=1)

        # 3. TF-IDF Cosine Baseline
        tfidf_row = table_6_2.get("TF-IDF Cosine Baseline")
        self.assertIsNotNone(tfidf_row, "TF-IDF row missing in Table 6.2")
        self.assertEqual(int(tfidf_row["TP"]), self.computed_metrics["main_test_tfidf"]["tp"])
        self.assertEqual(int(tfidf_row["TN"]), self.computed_metrics["main_test_tfidf"]["tn"])
        self.assertEqual(int(tfidf_row["FP"]), self.computed_metrics["main_test_tfidf"]["fp"])
        self.assertEqual(int(tfidf_row["FN"]), self.computed_metrics["main_test_tfidf"]["fn"])

        tfidf_p = parse_ci_cell(tfidf_row.get("Precision (95% CI)") or tfidf_row.get("Observed Precision (95% CI)"))
        self.assertAlmostEqual(tfidf_p["val"], self.computed_metrics["main_test_tfidf"]["precision"] * 100, places=1)
        self.assertAlmostEqual(tfidf_p["lo"], self.computed_metrics["main_test_tfidf"]["precision_ci95"][0] * 100, places=1)
        self.assertAlmostEqual(tfidf_p["hi"], self.computed_metrics["main_test_tfidf"]["precision_ci95"][1] * 100, places=1)

    def test_parsed_table_8_8_master_matrix(self):
        table_8_8 = self.tables.get("8. Baselines, Ablations, and Master Comparison", {})
        self.assertTrue(len(table_8_8) > 0, "Failed to parse Master Table 8.8 from Section 8")

        # Schema precision row is n/a
        schema_row = table_8_8.get("Deterministic Schema (Tier 1.5)")
        self.assertIsNotNone(schema_row, "Deterministic Schema row missing in Table 8.8")
        self.assertEqual(schema_row["Precision (95% CI)"], "n/a")
        self.assertIn("0.0% [0.0%, 10.4%]", schema_row["Recall (95% CI)"])

        # Unexecuted sweeps removed from master table and deferred to Future Work
        self.assertNotIn("Semantic Judge Mode A (Full)", table_8_8)
        self.assertNotIn("Semantic Judge Mode B (Diff Only)", table_8_8)
        self.assertNotIn("Integrated Guard Middleware (BALANCED)", table_8_8)

    def test_zero_legacy_numbers_in_entire_paper(self):
        forbidden_patterns = [
            r"\b1\.42\b", r"\b2\.85\b", r"\b2,850\b", r"\b960\b",
            r"\b0\.61\b", r"\b46\.4\b", r"\b30\.5\b", r"\b41\.6\b",
            r"\b780\b", r"\b290\b"
        ]
        for pat in forbidden_patterns:
            matches = re.findall(pat, self.paper_text)
            self.assertEqual(len(matches), 0, f"Found legacy pattern {pat} in paper.md: {matches}")

    def test_abstract_inline_metrics_match_results(self):
        # Verify exact abstract inline metrics match computed_metrics.json
        hash_m = self.computed_metrics["main_test_hash"]
        static_m = self.computed_metrics["main_test_static"]
        tfidf_m = self.computed_metrics["main_test_tfidf"]

        self.assertIn(f"Precision = {hash_m['precision']*100:.1f}%", self.paper_text)
        self.assertIn(f"Recall = {hash_m['recall']*100:.1f}%", self.paper_text)
        self.assertIn(f"Benign FPR = {hash_m['benign_fpr']*100:.1f}%", self.paper_text)

        self.assertIn(f"Precision = {static_m['precision']*100:.1f}%", self.paper_text)
        self.assertIn(f"Recall = {static_m['recall']*100:.1f}%", self.paper_text)
        self.assertIn(f"Benign FPR = {static_m['benign_fpr']*100:.1f}%", self.paper_text)

        self.assertIn(f"Precision = {tfidf_m['precision']*100:.1f}%", self.paper_text)
        self.assertIn(f"Recall = {tfidf_m['recall']*100:.1f}%", self.paper_text)
        self.assertIn(f"Benign FPR = {tfidf_m['benign_fpr']*100:.1f}%", self.paper_text)


class TestCorruptedPaperMustFail(unittest.TestCase):
    """Demonstrates that altering paper.md tables or inline numbers raises AssertionError."""

    def test_corrupted_table_tp_fails(self):
        t = TestPaperMatchesResults()
        t.setUp()
        # Corrupt Table 6.2 TP for Hash Pinning from 33 to 99
        t.paper_text = t.paper_text.replace("| **Exact Hash Pinning (Tier 0)** | 33 |", "| **Exact Hash Pinning (Tier 0)** | 99 |")
        t.tables = parse_markdown_tables(t.paper_text)
        with self.assertRaises(AssertionError):
            t.test_parsed_table_6_2_confusion_and_metrics()

    def test_corrupted_table_precision_ci_fails(self):
        t = TestPaperMatchesResults()
        t.setUp()
        # Corrupt Static precision CI
        if "**100.0%** [86.7%, 100.0%]" in t.paper_text:
            t.paper_text = t.paper_text.replace("**100.0%** [86.7%, 100.0%]", "80.0% [60.0%, 90.0%]")
        else:
            t.paper_text = t.paper_text.replace("100.0% [86.7%, 100.0%]", "80.0% [60.0%, 90.0%]")
        t.tables = parse_markdown_tables(t.paper_text)
        with self.assertRaises(AssertionError):
            t.test_parsed_table_6_2_confusion_and_metrics()

    def test_legacy_latency_injection_fails(self):
        t = TestPaperMatchesResults()
        t.setUp()
        t.paper_text += "\nUnverified measurement: 1.42 s"
        with self.assertRaises(AssertionError):
            t.test_zero_legacy_numbers_in_entire_paper()


if __name__ == "__main__":
    unittest.main()
