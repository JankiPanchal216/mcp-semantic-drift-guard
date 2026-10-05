"""
Single Source of Truth: Metric Computation Engine.
Reads predictions.jsonl files across results/<experiment>/, computes:
TP, TN, FP, FN, precision, recall, F1, benign FPR, malicious FNR with exact 95% Wilson CIs,
LLM calls per update, and latency stats (mean, median, p95) for:
(a) all items, and (b) LLM-judged items only.
Emits results/computed_metrics.json and prints markdown tables.
"""

import os
import sys
import json
import math
from pathlib import Path
from typing import Dict, List, Any, Tuple
import numpy as np

ROOT_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT_DIR / "results"


def compute_wilson_ci(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float, float]:
    """Calculates point estimate and 95% Wilson score confidence interval."""
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    z = 1.959963984540054  # exact 95% two-sided normal quantile
    denominator = 1.0 + (z**2) / n
    centre = (p + (z**2) / (2.0 * n)) / denominator
    spread = (z * math.sqrt((p * (1.0 - p) / n) + ((z**2) / (4.0 * n**2)))) / denominator
    lower = max(0.0, centre - spread)
    upper = min(1.0, centre + spread)
    return p, lower, upper


def evaluate_prediction_file(pred_file: Path) -> Dict[str, Any]:
    with open(pred_file, "r", encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    total_n = len(rows)
    tp = sum(1 for r in rows if r["gold_label"] == "MALICIOUS" and r["predicted_label"] in ("MALICIOUS", "SUSPICIOUS"))
    fn = sum(1 for r in rows if r["gold_label"] == "MALICIOUS" and r["predicted_label"] == "BENIGN")
    tn = sum(1 for r in rows if r["gold_label"] == "BENIGN" and r["predicted_label"] == "BENIGN")
    fp = sum(1 for r in rows if r["gold_label"] == "BENIGN" and r["predicted_label"] in ("MALICIOUS", "SUSPICIOUS"))

    pred_pos = tp + fp
    actual_pos = tp + fn
    actual_neg = tn + fp

    p_val, p_lo, p_hi = compute_wilson_ci(tp, pred_pos)
    r_val, r_lo, r_hi = compute_wilson_ci(tp, actual_pos)
    f1_val = (2.0 * p_val * r_val / (p_val + r_val)) if (p_val + r_val) > 0 else 0.0

    fpr_val, fpr_lo, fpr_hi = compute_wilson_ci(fp, actual_neg)
    fnr_val, fnr_lo, fnr_hi = compute_wilson_ci(fn, actual_pos)

    llm_calls = sum(1 for r in rows if r.get("llm_called", False))
    llm_calls_per_update = llm_calls / total_n if total_n > 0 else 0.0

    all_latencies = [r["latency_ms_total"] for r in rows if r.get("latency_ms_total") is not None]
    llm_latencies = [r["latency_ms_total"] for r in rows if r.get("llm_called", False) and r.get("latency_ms_total") is not None]

    lat_all_mean = float(np.mean(all_latencies)) if all_latencies else None
    lat_all_median = float(np.median(all_latencies)) if all_latencies else None
    lat_all_p95 = float(np.percentile(all_latencies, 95)) if all_latencies else None

    lat_llm_mean = float(np.mean(llm_latencies)) if llm_latencies else None
    lat_llm_median = float(np.median(llm_latencies)) if llm_latencies else None
    lat_llm_p95 = float(np.percentile(llm_latencies, 95)) if llm_latencies else None

    return {
        "n": total_n,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "pred_pos": pred_pos,
        "actual_pos": actual_pos,
        "actual_neg": actual_neg,
        "precision": p_val,
        "precision_ci95": [p_lo, p_hi],
        "recall": r_val,
        "recall_ci95": [r_lo, r_hi],
        "f1": f1_val,
        "benign_fpr": fpr_val,
        "benign_fpr_ci95": [fpr_lo, fpr_hi],
        "malicious_fnr": fnr_val,
        "malicious_fnr_ci95": [fnr_lo, fnr_hi],
        "llm_calls_total": llm_calls,
        "llm_calls_per_update": llm_calls_per_update,
        "latency_all_ms": {
            "mean": lat_all_mean,
            "median": lat_all_median,
            "p95": lat_all_p95
        },
        "latency_llm_ms": {
            "mean": lat_llm_mean,
            "median": lat_llm_median,
            "p95": lat_llm_p95
        }
    }


def compute_all_metrics() -> Dict[str, Any]:
    experiments = [
        "main_test_hash",
        "main_test_static",
        "main_test_tfidf",
        "main_test_schema",
        "main_test_mode_a",
        "main_test_mode_b",
        "main_test_integrated",
        "tier_ablation_A",
        "tier_ablation_B",
        "tier_ablation_C",
        "tier_ablation_D",
        "tier_ablation_E",
        "tier_ablation_F",
        "tier_ablation_G",
        "tier_ablation_H",
        "cv_fold_1",
        "cv_fold_2",
        "cv_fold_3",
        "cv_fold_4",
        "cv_fold_5",
        "matched_pairs",
        "redteam_baseline",
        "redteam_v2"
    ]

    all_metrics = {}
    for exp in experiments:
        pred_file = RESULTS_DIR / exp / "predictions.jsonl"
        if pred_file.exists():
            all_metrics[exp] = evaluate_prediction_file(pred_file)

    # Save to computed_metrics.json
    out_json = RESULTS_DIR / "computed_metrics.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(all_metrics, f, indent=2)

    print(f"Computed metrics for {len(all_metrics)} experiments saved to {out_json}")
    return all_metrics


if __name__ == "__main__":
    compute_all_metrics()
