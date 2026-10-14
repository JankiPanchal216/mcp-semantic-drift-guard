#!/usr/bin/env python3
"""
scripts/compute_annotator_agreement.py

Computes inter-annotator agreement metrics (Percent Agreement, Cohen's Kappa,
Confusion Matrix, and Disagreement Analysis) between an independent annotator sheet
and author gold labels for Benchmark V4-H.
"""

import sys
import csv
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_V4H_PATH = ROOT_DIR / "data" / "history_necessary_v4h.jsonl"


def load_author_gold_labels(v4h_path: Path) -> Dict[str, Dict[str, Any]]:
    """Loads author gold labels and tool metadata per chain from V4-H dataset."""
    gold_by_chain = {}
    with open(v4h_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rec = json.loads(line)
                cid = rec["chain_id"]
                raw_gold = rec.get("gold_label", "UNKNOWN").upper()
                if cid not in gold_by_chain:
                    gold_by_chain[cid] = {
                        "chain_id": cid,
                        "tool_name": rec.get("tool_name", ""),
                        "category": rec.get("category", ""),
                        "attack_family": rec.get("attack_family", ""),
                        "gold_label": "BENIGN",
                        "raw_gold_labels": [],
                    }
                gold_by_chain[cid]["raw_gold_labels"].append(raw_gold)
                if raw_gold in ("MALICIOUS", "ATTACK"):
                    gold_by_chain[cid]["gold_label"] = "ATTACK"
    return gold_by_chain


def compute_cohens_kappa(
    y_true: List[str], y_pred: List[str], categories: Optional[List[str]] = None
) -> Tuple[float, float, Dict[Tuple[str, str], int]]:
    """
    Computes Cohen's Kappa and Observed Agreement without external dependencies.
    Returns: (kappa, percent_agreement, confusion_matrix)
    """
    if len(y_true) != len(y_pred) or len(y_true) == 0:
        return 0.0, 0.0, {}

    if categories is None:
        categories = sorted(list(set(y_true) | set(y_pred)))

    n = len(y_true)
    matrix = {(r, c): 0 for r in categories for c in categories}
    for yt, yp in zip(y_true, y_pred):
        if yt in categories and yp in categories:
            matrix[(yt, yp)] += 1

    # Observed agreement
    agreed = sum(matrix[(c, c)] for c in categories)
    p_o = agreed / n

    # Expected agreement
    p_e = 0.0
    for c in categories:
        row_sum = sum(matrix[(c, cp)] for cp in categories)
        col_sum = sum(matrix[(rp, c)] for rp in categories)
        p_e += (row_sum * col_sum) / (n * n)

    if math_isclose(p_e, 1.0):
        kappa = 1.0 if math_isclose(p_o, 1.0) else 0.0
    else:
        kappa = (p_o - p_e) / (1.0 - p_e)

    return kappa, p_o * 100.0, matrix


def math_isclose(a: float, b: float, rel_tol: float = 1e-9) -> bool:
    return abs(a - b) <= rel_tol * max(abs(a), abs(b), 1.0)


def compute_agreement(
    annotator_csv_path: Path, v4h_dataset_path: Optional[Path] = None
) -> Dict[str, Any]:
    """Evaluates an annotator CSV against author gold labels."""
    if v4h_dataset_path is None:
        v4h_dataset_path = DEFAULT_V4H_PATH

    gold_data = load_author_gold_labels(v4h_dataset_path)

    if not annotator_csv_path.exists():
        raise FileNotFoundError(f"Annotator sheet not found at: {annotator_csv_path}")

    y_true = []
    y_pred = []
    chain_records = []
    disagreements = []
    unlabeled_count = 0
    unsure_count = 0

    with open(annotator_csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = row.get("chain_id", "").strip()
            if not cid:
                continue

            raw_label = row.get("annotator_label", "").strip().upper()
            notes = row.get("annotator_notes", "").strip()

            if not raw_label:
                unlabeled_count += 1
                continue

            if cid not in gold_data:
                continue

            gold_info = gold_data[cid]
            gold_lbl = gold_info["gold_label"]

            # Normalize annotator label
            if raw_label in ("ATTACK", "MALICIOUS"):
                norm_label = "ATTACK"
            elif raw_label in ("BENIGN",):
                norm_label = "BENIGN"
            elif raw_label in ("UNSURE", "AMBIGUOUS", "?"):
                norm_label = "UNSURE"
                unsure_count += 1
            else:
                norm_label = raw_label

            y_true.append(gold_lbl)
            y_pred.append(norm_label)

            rec = {
                "chain_id": cid,
                "tool_name": row.get("tool_name", gold_info["tool_name"]),
                "gold_label": gold_lbl,
                "annotator_label": norm_label,
                "notes": notes,
                "matches": (gold_lbl == norm_label),
            }
            chain_records.append(rec)
            if gold_lbl != norm_label:
                disagreements.append(rec)

    total_annotated = len(y_true)
    if total_annotated == 0:
        return {
            "status": "UNLABELED",
            "total_annotated": 0,
            "unlabeled_count": unlabeled_count,
            "message": "The annotation sheet does not contain any completed labels.",
        }

    categories = ["ATTACK", "BENIGN"]
    if "UNSURE" in y_pred:
        categories.append("UNSURE")

    kappa, pct_agree, conf_matrix = compute_cohens_kappa(y_true, y_pred, categories)

    return {
        "status": "COMPLETED",
        "total_annotated": total_annotated,
        "unlabeled_count": unlabeled_count,
        "unsure_count": unsure_count,
        "percent_agreement": round(pct_agree, 2),
        "cohens_kappa": round(kappa, 4),
        "confusion_matrix": {f"{r}->{c}": count for (r, c), count in conf_matrix.items()},
        "disagreements": disagreements,
        "disagreement_count": len(disagreements),
    }


def main():
    parser = argparse.ArgumentParser(description="Compute agreement with author gold labels.")
    parser.add_argument(
        "--annotator_csv",
        type=Path,
        default=ROOT_DIR / "paper" / "annotation" / "v4h_annotation_sheet.csv",
        help="Path to annotator CSV file",
    )
    parser.add_argument(
        "--v4h_dataset",
        type=Path,
        default=DEFAULT_V4H_PATH,
        help="Path to V4-H dataset JSONL",
    )
    args = parser.parse_args()

    results = compute_agreement(args.annotator_csv, args.v4h_dataset)

    print("=" * 60)
    print("Benchmark V4-H Annotator Agreement Summary")
    print("=" * 60)
    if results.get("status") == "UNLABELED":
        print(f"Status: {results['status']}")
        print(f"Unlabeled Rows: {results['unlabeled_count']}")
        print(f"Message: {results['message']}")
        sys.exit(0)

    print(f"Total Annotated Chains: {results['total_annotated']}")
    print(f"Unlabeled Chains:       {results['unlabeled_count']}")
    print(f"Unsure Ratings:         {results['unsure_count']}")
    print(f"Observed Agreement:     {results['percent_agreement']}%")
    print(f"Cohen's Kappa:          {results['cohens_kappa']}")
    print("\nConfusion Matrix (Author -> Annotator):")
    for k, v in sorted(results["confusion_matrix"].items()):
        print(f"  {k:15}: {v}")

    print(f"\nDisagreements ({results['disagreement_count']}):")
    for d in results["disagreements"]:
        print(f"  - [{d['chain_id']}] ({d['tool_name']}): Gold={d['gold_label']} vs Annotator={d['annotator_label']}")
        if d.get("notes"):
            print(f"    Note: {d['notes']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
