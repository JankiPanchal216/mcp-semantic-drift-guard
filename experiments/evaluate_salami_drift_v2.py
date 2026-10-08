"""
Salami Drift Benchmark v2 Evaluation Engine.
Evaluates 24 multi-step chains (88 transitions) across:
  1. Strategy = Adjacent (Per-Step: V_{i-1} -> V_i)
  2. Strategy = Cumulative (Origin-Anchored: V_1 -> V_i)
  3. Strategy = Dual (Conservative Higher-Risk Decision)

Calculates:
  - Step-level confusion matrix & Wilson 95% CIs
  - Chain-level detection rate & Benign Chain FPR
  - Exposure Window metrics (mean, median, min, max)
  - Paired comparisons: McNemar's test & Wilcoxon signed-rank test
  - Per-item prediction traces with full provenance

Exports to:
  - results/salami_drift_v2_per_step/predictions.jsonl
  - results/salami_drift_v2_cumulative/predictions.jsonl
  - results/salami_drift_v2_dual/predictions.jsonl
  - results/salami_drift_v2/computed_metrics.json
  - results/salami_drift_v2/run_manifest.json
"""

import os
import sys
import json
import time
import shutil
import tempfile
import argparse
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from guard.config import GuardConfig
from guard.baseline_store import BaselineStore
from guard.middleware import MCPGuardMiddleware

DATA_FILE = ROOT_DIR / "data" / "salami_drift_benchmark_v2.jsonl"
RESULTS_DIR = ROOT_DIR / "results"
V2_RESULTS_DIR = RESULTS_DIR / "salami_drift_v2"
GIT_COMMIT = "381125b09dee2d05f23e170e32762a71f815305d"
HARDWARE_INFO = "Local GPU/CPU Environment (Windows x86_64)"


def wilson_ci(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    """Calculates Wilson score interval."""
    if n == 0:
        return 0.0, 0.0
    z = 1.959963984540054
    p = k / n
    denom = 1.0 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    spread = (z * np.sqrt((p * (1.0 - p) + z**2 / (4 * n)) / n)) / denom
    return max(0.0, float(center - spread)), min(1.0, float(center + spread))


def mcnemar_exact_test(table: Tuple[int, int, int, int]) -> float:
    """
    Computes two-tailed exact binomial p-value for 2x2 paired contingency table.
    table = (a, b, c, d) where b is (Method 1 Yes, Method 2 No) and c is (Method 1 No, Method 2 Yes).
    """
    import math
    a, b, c, d = table
    n_discordant = b + c
    if n_discordant == 0:
        return 1.0
    k = min(b, c)
    # Cumulative binomial under p=0.5
    cum_prob = sum(math.comb(n_discordant, i) * (0.5**n_discordant) for i in range(k + 1))
    return min(1.0, 2.0 * cum_prob)


def wilcoxon_signed_rank(diffs: List[float]) -> Tuple[float, float]:
    """
    Calculates Wilcoxon signed-rank test statistic and approximate p-value for paired differences.
    """
    import math
    nonzero_diffs = [d for d in diffs if d != 0]
    n = len(nonzero_diffs)
    if n == 0:
        return 0.0, 1.0
    
    ranks = sorted(range(n), key=lambda i: abs(nonzero_diffs[i]))
    rank_values = [0.0] * n
    for r_idx, orig_idx in enumerate(ranks, 1):
        rank_values[orig_idx] = float(r_idx)
        
    w_pos = sum(rank_values[i] for i in range(n) if nonzero_diffs[i] > 0)
    w_neg = sum(rank_values[i] for i in range(n) if nonzero_diffs[i] < 0)
    stat = min(w_pos, w_neg)
    
    # Normal approximation for n >= 5
    if n >= 5:
        mean_w = n * (n + 1) / 4.0
        var_w = n * (n + 1) * (2 * n + 1) / 24.0
        z = (stat - mean_w) / math.sqrt(var_w)
        # Standard normal CDF approximation
        p_val = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(z) / math.sqrt(2.0))))
    else:
        p_val = 1.0
    return float(stat), float(p_val)


def load_benchmark_v2_chains() -> Dict[str, List[Dict[str, Any]]]:
    if not DATA_FILE.exists():
        raise FileNotFoundError(f"Benchmark v2 file not found: {DATA_FILE}")

    records = []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    chains: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        cid = r["chain_id"]
        chains.setdefault(cid, []).append(r)

    for cid in chains:
        chains[cid].sort(key=lambda x: x["step_index"])

    return chains


def run_strategy_evaluation(
    chains: Dict[str, List[Dict[str, Any]]],
    strategy: str,
    policy_mode: str = "BALANCED",
    model_name: str = "qwen2.5:1.5b",
    mock_mode: bool = False
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Dict[str, Any]]]:
    """
    Evaluates Benchmark v2 under a specific anchor mode.
    Returns (predictions, summary_metrics, per_chain_outcomes).
    """
    print(f"\n--- Evaluating Salami Drift Benchmark v2: Strategy = {strategy.upper()} ---")
    predictions: List[Dict[str, Any]] = []
    per_chain_outcomes: Dict[str, Dict[str, Any]] = {}

    for chain_id, steps in chains.items():
        temp_dir = tempfile.mkdtemp(prefix=f"salami_v2_{strategy}_{chain_id}_")
        db_path = Path(temp_dir) / "baseline.db"
        audit_path = Path(temp_dir) / "audit.jsonl"

        config = GuardConfig(
            policy_mode=policy_mode,
            anchor_mode=strategy,
            model_name=model_name,
            baseline_db_path=db_path,
            audit_log_path=audit_path
        )
        guard = MCPGuardMiddleware(config)

        first_step = steps[0]
        server_id = first_step["server_id"]
        tool_name = first_step["tool_name"]
        root_def = first_step["root_tool_definition"]

        # Register V1
        guard.baseline_store.update_trusted_baseline(
            server_id=server_id,
            tool_name=tool_name,
            tool_def=root_def,
            reason="INITIAL_TRUSTED_BASELINE_V1"
        )

        chain_step_preds: List[Dict[str, Any]] = []
        if not mock_mode:
            print(f"  [{strategy}] Evaluating chain: {chain_id} ({len(steps)} steps)...")

        for step in steps:
            step_idx = step["step_index"]
            tot_steps = step["total_steps"]
            gold_label = step["gold_label"]
            cand_def = step["tool_definition"]
            category = step["category"]

            mock_resp = None
            if mock_mode:
                mock_resp = {"label": gold_label, "confidence": 0.95}

            t0 = time.time()
            decision = guard.evaluate_tool_update(
                server_id=server_id,
                new_tool_def=cand_def,
                mock_judge_response=mock_resp,
                anchor_mode=strategy
            )
            lat_ms = (time.time() - t0) * 1000

            action = decision.get("action", "ALLOW")
            verdict = decision.get("verdict", "BENIGN")
            pred_label = "MALICIOUS" if verdict in ("MALICIOUS", "SUSPICIOUS") else "BENIGN"

            deciding_tier = 3
            llm_called = True
            audit_rec = decision.get("audit_record", {})
            if not audit_rec.get("change_detected", True):
                deciding_tier = 0
                llm_called = False
            elif audit_rec.get("semantic_judge_result", {}).get("skipped", False):
                reason = audit_rec.get("semantic_judge_result", {}).get("reason", "")
                if "Schema security" in reason:
                    deciding_tier = 1.5
                    llm_called = False
                elif "static rule" in reason:
                    deciding_tier = 2
                    llm_called = False

            pred_item = {
                "item_id": step["item_id"],
                "chain_id": chain_id,
                "category": category,
                "step_index": step_idx,
                "total_steps": tot_steps,
                "server_id": server_id,
                "tool_name": tool_name,
                "gold_label": gold_label,
                "predicted_label": pred_label,
                "deciding_tier": deciding_tier,
                "llm_called": llm_called,
                "latency_ms_total": round(lat_ms, 3),
                "run_id": f"salami_v2_{strategy}",
                "model": model_name if llm_called else "none",
                "policy": policy_mode,
                "anchor_mode": strategy,
                "hardware": HARDWARE_INFO,
                "source_file": "data/salami_drift_benchmark_v2.jsonl",
                "git_commit": GIT_COMMIT,
                "export_commit": GIT_COMMIT,
                "benchmark_version": "v2",
                "action": action,
                "verdict": verdict,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            predictions.append(pred_item)
            chain_step_preds.append(pred_item)

        shutil.rmtree(temp_dir, ignore_errors=True)

        # Chain-level outcome calculation
        mal_steps = [s for s in chain_step_preds if s["gold_label"] == "MALICIOUS"]
        is_mal = len(mal_steps) > 0
        first_mal_idx = mal_steps[0]["step_index"] if is_mal else None
        first_det_idx = next((s["step_index"] for s in chain_step_preds if s["action"] != "ALLOW" or s["predicted_label"] == "MALICIOUS"), None)

        if is_mal:
            is_detected = first_det_idx is not None
            exp_win = (first_det_idx - first_mal_idx) if is_detected else len(mal_steps)
            exp_win = max(0, exp_win)
        else:
            is_detected = False
            is_fp_chain = first_det_idx is not None
            exp_win = 0

        per_chain_outcomes[chain_id] = {
            "chain_id": chain_id,
            "category": steps[0]["category"],
            "is_malicious": is_mal,
            "detected": is_detected if is_mal else False,
            "false_alarm": is_fp_chain if not is_mal else False,
            "first_mal_step": first_mal_idx,
            "first_det_step": first_det_idx,
            "exposure_window": exp_win,
            "total_steps": len(steps)
        }

    # Step-level confusion matrix
    tp = sum(1 for p in predictions if p["gold_label"] == "MALICIOUS" and p["predicted_label"] == "MALICIOUS")
    tn = sum(1 for p in predictions if p["gold_label"] == "BENIGN" and p["predicted_label"] == "BENIGN")
    fp = sum(1 for p in predictions if p["gold_label"] == "BENIGN" and p["predicted_label"] == "MALICIOUS")
    fn = sum(1 for p in predictions if p["gold_label"] == "MALICIOUS" and p["predicted_label"] == "BENIGN")

    prec = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    rec = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = (fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    p_lo, p_hi = wilson_ci(tp, tp + fp)
    r_lo, r_hi = wilson_ci(tp, tp + fn)
    fpr_lo, fpr_hi = wilson_ci(fp, fp + tn)

    # Chain-level aggregations
    mal_chains = [c for c in per_chain_outcomes.values() if c["is_malicious"]]
    ben_chains = [c for c in per_chain_outcomes.values() if not c["is_malicious"]]

    det_mal_count = sum(1 for c in mal_chains if c["detected"])
    fp_ben_count = sum(1 for c in ben_chains if c["false_alarm"])
    chain_det_rate = det_mal_count / len(mal_chains) if mal_chains else 0.0
    ben_chain_fpr = fp_ben_count / len(ben_chains) if ben_chains else 0.0

    exp_windows = [c["exposure_window"] for c in mal_chains]
    first_step_dets = sum(1 for c in mal_chains if c["detected"] and c["first_det_step"] == c["first_mal_step"])
    pre_payload_dets = sum(1 for c in mal_chains if c["detected"] and c["first_det_step"] < c["total_steps"])
    never_dets = sum(1 for c in mal_chains if not c["detected"])

    summary_metrics = {
        "strategy": strategy,
        "n_transitions": len(predictions),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": prec, "precision_ci95": [p_lo, p_hi],
        "recall": rec, "recall_ci95": [r_lo, r_hi],
        "f1": f1,
        "benign_fpr": fpr, "benign_fpr_ci95": [fpr_lo, fpr_hi],
        "malicious_fnr": fnr,
        "chain_metrics": {
            "total_chains": len(per_chain_outcomes),
            "malicious_chains": len(mal_chains),
            "benign_chains": len(ben_chains),
            "malicious_chains_detected": det_mal_count,
            "benign_chains_false_alarm": fp_ben_count,
            "chain_detection_rate": chain_det_rate,
            "benign_chain_fpr": ben_chain_fpr,
            "mean_exposure_window": float(np.mean(exp_windows)) if exp_windows else 0.0,
            "median_exposure_window": float(np.median(exp_windows)) if exp_windows else 0.0,
            "max_exposure_window": int(np.max(exp_windows)) if exp_windows else 0,
            "min_exposure_window": int(np.min(exp_windows)) if exp_windows else 0,
            "first_malicious_step_detection_rate": first_step_dets / len(mal_chains) if mal_chains else 0.0,
            "detected_before_final_payload_rate": pre_payload_dets / len(mal_chains) if mal_chains else 0.0,
            "never_detected_rate": never_dets / len(mal_chains) if mal_chains else 0.0
        }
    }

    return predictions, summary_metrics, per_chain_outcomes


def main():
    parser = argparse.ArgumentParser(description="Evaluate Salami Drift Benchmark v2")
    parser.add_argument("--model", type=str, default="qwen2.5:1.5b", help="Model name for Tier 3 semantic judge")
    parser.add_argument("--policy", type=str, default="BALANCED", help="Policy mode (BALANCED, STRICT, AUDIT)")
    parser.add_argument("--mock", action="store_true", help="Run fast simulation mode for test verification")
    args = parser.parse_args()

    chains = load_benchmark_v2_chains()
    print(f"Loaded {len(chains)} chains (88 transitions) from {DATA_FILE}")

    # Compute dataset hash
    with open(DATA_FILE, "rb") as f:
        data_hash = hashlib.sha256(f.read()).hexdigest()

    strategies = ["adjacent", "cumulative", "dual"]
    all_strategy_preds = {}
    all_strategy_summaries = {}
    all_chain_outcomes = {}

    for strat in strategies:
        preds, summary, c_outcomes = run_strategy_evaluation(
            chains=chains,
            strategy=strat,
            policy_mode=args.policy,
            model_name=args.model,
            mock_mode=args.mock
        )
        all_strategy_preds[strat] = preds
        all_strategy_summaries[strat] = summary
        all_chain_outcomes[strat] = c_outcomes

        # Write per-strategy predictions.jsonl
        out_dir = RESULTS_DIR / f"salami_drift_v2_{'per_step' if strat == 'adjacent' else strat}"
        out_dir.mkdir(parents=True, exist_ok=True)
        pred_file = out_dir / "predictions.jsonl"
        with open(pred_file, "w", encoding="utf-8") as f:
            for p in preds:
                f.write(json.dumps(p) + "\n")
        print(f"Wrote {len(preds)} traces to {pred_file}")

    # Statistical Comparison Calculations
    # 1. McNemar's exact test on paired binary chain detection (Malicious chains N=16)
    mal_cids = [cid for cid, c in all_chain_outcomes["adjacent"].items() if c["is_malicious"]]
    
    # Adjacent vs Cumulative
    b_adj_cum = sum(1 for cid in mal_cids if all_chain_outcomes["adjacent"][cid]["detected"] and not all_chain_outcomes["cumulative"][cid]["detected"])
    c_adj_cum = sum(1 for cid in mal_cids if not all_chain_outcomes["adjacent"][cid]["detected"] and all_chain_outcomes["cumulative"][cid]["detected"])
    p_mcnemar_adj_cum = mcnemar_exact_test((0, b_adj_cum, c_adj_cum, 0))

    # Adjacent vs Dual
    b_adj_dual = sum(1 for cid in mal_cids if all_chain_outcomes["adjacent"][cid]["detected"] and not all_chain_outcomes["dual"][cid]["detected"])
    c_adj_dual = sum(1 for cid in mal_cids if not all_chain_outcomes["adjacent"][cid]["detected"] and all_chain_outcomes["dual"][cid]["detected"])
    p_mcnemar_adj_dual = mcnemar_exact_test((0, b_adj_dual, c_adj_dual, 0))

    # Cumulative vs Dual
    b_cum_dual = sum(1 for cid in mal_cids if all_chain_outcomes["cumulative"][cid]["detected"] and not all_chain_outcomes["dual"][cid]["detected"])
    c_cum_dual = sum(1 for cid in mal_cids if not all_chain_outcomes["cumulative"][cid]["detected"] and all_chain_outcomes["dual"][cid]["detected"])
    p_mcnemar_cum_dual = mcnemar_exact_test((0, b_cum_dual, c_cum_dual, 0))

    # 2. Wilcoxon signed-rank test on paired exposure windows
    exp_adj = [all_chain_outcomes["adjacent"][cid]["exposure_window"] for cid in mal_cids]
    exp_cum = [all_chain_outcomes["cumulative"][cid]["exposure_window"] for cid in mal_cids]
    exp_dual = [all_chain_outcomes["dual"][cid]["exposure_window"] for cid in mal_cids]

    w_stat_adj_cum, p_wilcoxon_adj_cum = wilcoxon_signed_rank([exp_adj[i] - exp_cum[i] for i in range(len(mal_cids))])
    w_stat_adj_dual, p_wilcoxon_adj_dual = wilcoxon_signed_rank([exp_adj[i] - exp_dual[i] for i in range(len(mal_cids))])

    # Differences
    delta_det_cum_adj = all_strategy_summaries["cumulative"]["chain_metrics"]["chain_detection_rate"] - all_strategy_summaries["adjacent"]["chain_metrics"]["chain_detection_rate"]
    delta_det_dual_adj = all_strategy_summaries["dual"]["chain_metrics"]["chain_detection_rate"] - all_strategy_summaries["adjacent"]["chain_metrics"]["chain_detection_rate"]
    delta_exp_adj_cum = all_strategy_summaries["adjacent"]["chain_metrics"]["mean_exposure_window"] - all_strategy_summaries["cumulative"]["chain_metrics"]["mean_exposure_window"]
    delta_exp_adj_dual = all_strategy_summaries["adjacent"]["chain_metrics"]["mean_exposure_window"] - all_strategy_summaries["dual"]["chain_metrics"]["mean_exposure_window"]

    statistical_report = {
        "sample_size_malicious_chains": len(mal_cids),
        "sample_size_benign_chains": len([cid for cid, c in all_chain_outcomes["adjacent"].items() if not c["is_malicious"]]),
        "paired_chain_detection_differences": {
            "cumulative_minus_adjacent": delta_det_cum_adj,
            "dual_minus_adjacent": delta_det_dual_adj,
            "mcnemar_p_value_adjacent_vs_cumulative": p_mcnemar_adj_cum,
            "mcnemar_p_value_adjacent_vs_dual": p_mcnemar_adj_dual,
            "mcnemar_p_value_cumulative_vs_dual": p_mcnemar_cum_dual
        },
        "paired_exposure_window_reductions": {
            "adjacent_minus_cumulative": delta_exp_adj_cum,
            "adjacent_minus_dual": delta_exp_adj_dual,
            "wilcoxon_adjacent_vs_cumulative": {"statistic": w_stat_adj_cum, "p_value": p_wilcoxon_adj_cum},
            "wilcoxon_adjacent_vs_dual": {"statistic": w_stat_adj_dual, "p_value": p_wilcoxon_adj_dual}
        }
    }

    # Consolidated computed_metrics.json for V2
    v2_computed_metrics = {
        "salami_drift_v2_per_step": all_strategy_summaries["adjacent"],
        "salami_drift_v2_cumulative": all_strategy_summaries["cumulative"],
        "salami_drift_v2_dual": all_strategy_summaries["dual"],
        "statistical_comparisons": statistical_report
    }

    V2_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    metrics_file = V2_RESULTS_DIR / "computed_metrics.json"
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(v2_computed_metrics, f, indent=2)

    # Write Run Manifest
    manifest = {
        "benchmark_version": "v2",
        "benchmark_file": "data/salami_drift_benchmark_v2.jsonl",
        "dataset_sha256": data_hash,
        "model": args.model,
        "policy": args.policy,
        "anchor_modes": strategies,
        "git_commit": GIT_COMMIT,
        "hardware": HARDWARE_INFO,
        "total_chains": len(chains),
        "malicious_chains": len(mal_cids),
        "benign_chains": len(chains) - len(mal_cids),
        "total_transitions": sum(len(s) for s in chains.values()),
        "categories": {
            "A_adjacent_evasive": 4,
            "B_adjacent_detectable": 3,
            "C_benign_long_drift": 4,
            "C_std_benign_control": 4,
            "D_param_drift": 3,
            "E_instruction_erosion": 2,
            "F_capability_combination": 2,
            "G_low_signal_drift": 2
        },
        "execution_status": "COMPLETED",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    manifest_file = V2_RESULTS_DIR / "run_manifest.json"
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nSaved Benchmark v2 metrics to: {metrics_file}")
    print(f"Saved Benchmark v2 manifest to: {manifest_file}")


if __name__ == "__main__":
    main()
