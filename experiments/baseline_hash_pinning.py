"""
Baseline 1: Exact Hash Pinning Evaluator
Reproduces the Phase 1B cryptographic tool pinning baseline.
Evaluates normalized SHA-256 hash comparison across the Phase 3 dataset.
"""

import json
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Tuple


def normalize_def(tool_def: Dict[str, Any]) -> str:
    """Canonical JSON serialization for hashing."""
    if tool_def is None:
        return "__NONE__"
    return json.dumps(tool_def, sort_keys=True, separators=(',', ':'))


def compute_sha256(canonical_str: str) -> str:
    return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()


def evaluate_hash_pinning_example(example: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates exact hash pinning on a single change example.
    Returns prediction ('CHANGE' or 'NO_CHANGE') and classification mapping.
    """
    old_def = example.get("old_definition")
    new_def = example.get("new_definition")

    old_norm = normalize_def(old_def)
    new_norm = normalize_def(new_def)

    hash_old = compute_sha256(old_norm)
    hash_new = compute_sha256(new_norm)

    has_changed = (hash_old != hash_new)
    prediction = "CHANGE" if has_changed else "NO_CHANGE"
    
    # In pinning policy: CHANGE triggers alarm (classified as alert/flagged).
    # Expected label: BENIGN or MALICIOUS.
    expected = example.get("expected_label", "BENIGN")
    
    # If treated as binary classifier (CHANGE = positive alarm):
    # - True Positive (TP): MALICIOUS and CHANGE
    # - False Positive (FP): BENIGN and CHANGE (legitimate update falsely flagged!)
    # - True Negative (TN): BENIGN and NO_CHANGE
    # - False Negative (FN): MALICIOUS and NO_CHANGE
    
    return {
        "example_id": example.get("example_id"),
        "prediction": prediction,
        "expected_label": expected,
        "is_flagged": has_changed,
        "hash_old": hash_old,
        "hash_new": hash_new,
        "is_tp": (expected == "MALICIOUS" and has_changed),
        "is_fp": (expected == "BENIGN" and has_changed),
        "is_tn": (expected == "BENIGN" and not has_changed),
        "is_fn": (expected == "MALICIOUS" and not has_changed)
    }


def run_hash_pinning_evaluation(dataset_path: Path) -> Dict[str, Any]:
    """Evaluates hash pinning over an entire dataset split."""
    results = []
    with open(dataset_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                ex = json.loads(line)
                results.append(evaluate_hash_pinning_example(ex))

    tp = sum(1 for r in results if r["is_tp"])
    fp = sum(1 for r in results if r["is_fp"])
    tn = sum(1 for r in results if r["is_tn"])
    fn = sum(1 for r in results if r["is_fn"])

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    benign_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    malicious_fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "detector": "Exact Hash Pinning",
        "dataset": dataset_path.name,
        "total_examples": len(results),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "benign_fpr": benign_fpr,
        "malicious_fnr": malicious_fnr,
        "predictions": results
    }


if __name__ == "__main__":
    test_path = Path(__file__).resolve().parent.parent / "data" / "drift_test.jsonl"
    if test_path.exists():
        metrics = run_hash_pinning_evaluation(test_path)
        print("Hash Pinning Baseline Test Metrics:")
        print(f"  Total: {metrics['total_examples']}")
        print(f"  TP: {metrics['tp']}, FP: {metrics['fp']}, TN: {metrics['tn']}, FN: {metrics['fn']}")
        print(f"  Precision: {metrics['precision']:.4f}, Recall: {metrics['recall']:.4f}, F1: {metrics['f1']:.4f}")
        print(f"  Benign FPR: {metrics['benign_fpr']:.4f} ({metrics['fp']}/{metrics['fp']+metrics['tn']})")
