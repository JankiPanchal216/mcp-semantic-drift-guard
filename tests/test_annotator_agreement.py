"""
tests/test_annotator_agreement.py

Unit tests for scripts/compute_annotator_agreement.py.
Tests agreement calculations on synthetic annotation sheets without altering production data.
"""

import unittest
import csv
import tempfile
from pathlib import Path

from scripts.compute_annotator_agreement import (
    compute_agreement,
    compute_cohens_kappa,
    load_author_gold_labels,
    DEFAULT_V4H_PATH
)


class TestAnnotatorAgreement(unittest.TestCase):

    def setUp(self):
        self.gold_data = load_author_gold_labels(DEFAULT_V4H_PATH)
        self.assertEqual(len(self.gold_data), 24)

    def test_blank_annotation_sheet(self):
        """Blank annotation sheet returns UNLABELED status with 24 unlabeled rows."""
        sheet_path = Path("paper/annotation/v4h_annotation_sheet.csv")
        self.assertTrue(sheet_path.exists())
        res = compute_agreement(sheet_path)
        self.assertEqual(res["status"], "UNLABELED")
        self.assertEqual(res["unlabeled_count"], 24)
        self.assertEqual(res["total_annotated"], 0)

    def test_synthetic_perfect_agreement(self):
        """Synthetic sheet perfectly matching author gold labels yields kappa=1.0 and 100% agreement."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", newline="", encoding="utf-8") as tmp:
            writer = csv.DictWriter(tmp, fieldnames=["chain_id", "tool_name", "annotator_label", "annotator_notes"])
            writer.writeheader()
            for cid, info in self.gold_data.items():
                writer.writerow({
                    "chain_id": cid,
                    "tool_name": info["tool_name"],
                    "annotator_label": info["gold_label"],
                    "annotator_notes": "Synthetic perfect match test"
                })
            tmp_path = Path(tmp.name)

        try:
            res = compute_agreement(tmp_path)
            self.assertEqual(res["status"], "COMPLETED")
            self.assertEqual(res["total_annotated"], 24)
            self.assertEqual(res["percent_agreement"], 100.0)
            self.assertEqual(res["cohens_kappa"], 1.0)
            self.assertEqual(res["disagreement_count"], 0)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_synthetic_partial_agreement_and_disagreements(self):
        """Synthetic sheet with known injected disagreements computes correct kappa and enumerates disagreements."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", newline="", encoding="utf-8") as tmp:
            writer = csv.DictWriter(tmp, fieldnames=["chain_id", "tool_name", "annotator_label", "annotator_notes"])
            writer.writeheader()
            injected_disagreements = 0
            for i, (cid, info) in enumerate(self.gold_data.items()):
                # Flip 4 chains (2 attacks -> BENIGN, 2 benign -> ATTACK)
                if i < 4:
                    flipped = "BENIGN" if info["gold_label"] == "ATTACK" else "ATTACK"
                    label = flipped
                    injected_disagreements += 1
                else:
                    label = info["gold_label"]

                writer.writerow({
                    "chain_id": cid,
                    "tool_name": info["tool_name"],
                    "annotator_label": label,
                    "annotator_notes": f"Synthetic test row {i}"
                })
            tmp_path = Path(tmp.name)

        try:
            res = compute_agreement(tmp_path)
            self.assertEqual(res["status"], "COMPLETED")
            self.assertEqual(res["total_annotated"], 24)
            self.assertEqual(res["disagreement_count"], 4)
            self.assertAlmostEqual(res["percent_agreement"], (20 / 24) * 100.0, places=2)
            self.assertGreater(res["cohens_kappa"], 0.6)  # High agreement kappa
            self.assertEqual(len(res["disagreements"]), 4)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_synthetic_unsure_handling(self):
        """Synthetic sheet with UNSURE labels records them in unsure_count."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", newline="", encoding="utf-8") as tmp:
            writer = csv.DictWriter(tmp, fieldnames=["chain_id", "tool_name", "annotator_label", "annotator_notes"])
            writer.writeheader()
            for i, (cid, info) in enumerate(self.gold_data.items()):
                label = "UNSURE" if i == 0 else info["gold_label"]
                writer.writerow({
                    "chain_id": cid,
                    "tool_name": info["tool_name"],
                    "annotator_label": label,
                    "annotator_notes": "Synthetic unsure test"
                })
            tmp_path = Path(tmp.name)

        try:
            res = compute_agreement(tmp_path)
            self.assertEqual(res["status"], "COMPLETED")
            self.assertEqual(res["unsure_count"], 1)
            self.assertEqual(res["disagreement_count"], 1)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


if __name__ == "__main__":
    unittest.main()
