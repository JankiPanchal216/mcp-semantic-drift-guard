"""
tests/test_annotator_agreement.py

Unit tests for scripts/compute_annotator_agreement.py and verification of the
Benchmark V4-H annotation package for label leakage.
"""

import unittest
import csv
import re
import tempfile
from pathlib import Path

from scripts.compute_annotator_agreement import (
    compute_agreement,
    load_private_key,
    load_author_gold_labels,
    DEFAULT_V4H_PATH,
    DEFAULT_KEY_PATH
)


class TestAnnotatorAgreement(unittest.TestCase):

    def setUp(self):
        self.key_data = load_private_key(DEFAULT_KEY_PATH)
        self.gold_data = load_author_gold_labels(DEFAULT_V4H_PATH)
        self.assertEqual(len(self.key_data), 24)
        self.assertEqual(len(self.gold_data), 24)

    def test_sheet_no_label_leaks(self):
        """Fails if any chain_id or column in v4h_annotation_sheet.csv leaks gold labels or attack/benign hints."""
        sheet_path = Path("paper/annotation/v4h_annotation_sheet.csv")
        self.assertTrue(sheet_path.exists(), "v4h_annotation_sheet.csv must exist")

        leak_patterns = [r"\batk\b", r"\battack\b", r"\battacks\b", r"\bbenign\b", r"\bmalicious\b"]

        with open(sheet_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []

            # Check column headers for label/hint leaks
            for col in fieldnames:
                for pat in [r"gold", r"label", r"attack", r"benign", r"malicious", r"family"]:
                    if re.search(pat, col, re.I) and col not in ("annotator_label", "annotator_notes"):
                        self.fail(f"Column header '{col}' leaks label or hint pattern '{pat}'")

            rows = list(reader)
            self.assertEqual(len(rows), 24, "Annotation sheet must have exactly 24 rows")

            seen_ids = set()
            for idx, r in enumerate(rows, 1):
                cid = r["chain_id"]
                seen_ids.add(cid)

                # 1. Check anonymous chain ID format C01..C24
                self.assertRegex(
                    cid,
                    r"^C(0[1-9]|1[0-9]|2[0-4])$",
                    f"Row {idx} chain_id '{cid}' is not an anonymous C01..C24 identifier"
                )

                # 2. Check tool_name for leak patterns
                tname = r["tool_name"].lower()
                for pat in ["atk", "benign", "attack", "malicious"]:
                    self.assertNotIn(
                        pat, tname,
                        f"Row {idx} tool_name '{tname}' leaks pattern '{pat}'"
                    )

                # 3. Check definitions for explicit leak keywords
                for def_col in ("step_1_definition", "step_2_definition", "step_3_definition"):
                    def_text = r[def_col].lower()
                    for pat in ["atk", "benign", "attack", "malicious"]:
                        self.assertNotIn(
                            pat, def_text,
                            f"Row {idx} {def_col} contains leaking term '{pat}'"
                        )

            self.assertEqual(len(seen_ids), 24, "All 24 anonymous chain IDs must be unique")
            expected_ids = {f"C{i:02d}" for i in range(1, 25)}
            self.assertEqual(seen_ids, expected_ids, "Anonymous IDs must be C01..C24")

    def test_private_key_mapping_integrity(self):
        """Verifies _private_key.csv contains exactly 24 balanced mappings without missing keys."""
        self.assertTrue(DEFAULT_KEY_PATH.exists())
        self.assertEqual(len(self.key_data), 24)

        attacks = sum(1 for v in self.key_data.values() if v["gold_label"] == "ATTACK")
        benigns = sum(1 for v in self.key_data.values() if v["gold_label"] == "BENIGN")
        self.assertEqual(attacks, 12, "Private key must map exactly 12 attack chains")
        self.assertEqual(benigns, 12, "Private key must map exactly 12 benign chains")

    def test_blank_annotation_sheet(self):
        """Blank annotation sheet returns UNLABELED status with 24 unlabeled rows."""
        sheet_path = Path("paper/annotation/v4h_annotation_sheet.csv")
        self.assertTrue(sheet_path.exists())
        res = compute_agreement(sheet_path, DEFAULT_KEY_PATH)
        self.assertEqual(res["status"], "UNLABELED")
        self.assertEqual(res["unlabeled_count"], 24)
        self.assertEqual(res["total_annotated"], 0)

    def test_synthetic_perfect_agreement(self):
        """Synthetic sheet with C01..C24 matching private key yields kappa=1.0 and 100% agreement."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", newline="", encoding="utf-8") as tmp:
            writer = csv.DictWriter(tmp, fieldnames=["chain_id", "tool_name", "annotator_label", "annotator_notes"])
            writer.writeheader()
            for aid, info in sorted(self.key_data.items()):
                writer.writerow({
                    "chain_id": aid,
                    "tool_name": info["tool_name"],
                    "annotator_label": info["gold_label"],
                    "annotator_notes": "Synthetic perfect match test"
                })
            tmp_path = Path(tmp.name)

        try:
            res = compute_agreement(tmp_path, DEFAULT_KEY_PATH)
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
            for i, (aid, info) in enumerate(sorted(self.key_data.items())):
                # Invert label on first 4 chains
                if i < 4:
                    label = "BENIGN" if info["gold_label"] == "ATTACK" else "ATTACK"
                else:
                    label = info["gold_label"]

                writer.writerow({
                    "chain_id": aid,
                    "tool_name": info["tool_name"],
                    "annotator_label": label,
                    "annotator_notes": f"Synthetic test row {i}"
                })
            tmp_path = Path(tmp.name)

        try:
            res = compute_agreement(tmp_path, DEFAULT_KEY_PATH)
            self.assertEqual(res["status"], "COMPLETED")
            self.assertEqual(res["total_annotated"], 24)
            self.assertEqual(res["disagreement_count"], 4)
            self.assertAlmostEqual(res["percent_agreement"], (20 / 24) * 100.0, places=2)
            self.assertGreater(res["cohens_kappa"], 0.6)
            self.assertEqual(len(res["disagreements"]), 4)
            # Verify real_chain_id is populated in disagreement report
            for d in res["disagreements"]:
                self.assertTrue(d["real_chain_id"].startswith("v4h_chain_"))
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_synthetic_unsure_handling(self):
        """Synthetic sheet with UNSURE labels records them in unsure_count."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", newline="", encoding="utf-8") as tmp:
            writer = csv.DictWriter(tmp, fieldnames=["chain_id", "tool_name", "annotator_label", "annotator_notes"])
            writer.writeheader()
            for i, (aid, info) in enumerate(sorted(self.key_data.items())):
                label = "UNSURE" if i == 0 else info["gold_label"]
                writer.writerow({
                    "chain_id": aid,
                    "tool_name": info["tool_name"],
                    "annotator_label": label,
                    "annotator_notes": "Synthetic unsure test"
                })
            tmp_path = Path(tmp.name)

        try:
            res = compute_agreement(tmp_path, DEFAULT_KEY_PATH)
            self.assertEqual(res["status"], "COMPLETED")
            self.assertEqual(res["unsure_count"], 1)
            self.assertEqual(res["disagreement_count"], 1)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


if __name__ == "__main__":
    unittest.main()
