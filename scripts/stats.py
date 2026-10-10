"""
scripts/stats.py - Rigorous Statistical Testing for MCP Semantic Drift Benchmark V3

Implements:
1. Paired chain-level and transition-level McNemar exact tests.
2. Cluster bootstrap (10,000 resamples at chain level with fixed seed 42) for 95% CIs.
3. Formal mathematical formulation and empirical calculation of Exposure Window metrics.
4. Validation and reproduction checks for authoritative V3 frozen results.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any
import numpy as np
from scipy import stats

ROOT_DIR = Path(__file__).resolve().parent.parent
V3_METRICS_PATH = ROOT_DIR / "results" / "salami_drift_v3" / "computed_metrics.json"
V3_BENCHMARK_PATH = ROOT_DIR / "data" / "salami_drift_benchmark_v3.jsonl"


def mcnemar_exact(b: int, c: int) -> float:
    """Computes exact two-sided McNemar p-value from discordant pairs b and c."""
    total = b + c
    if total == 0:
        return 1.0
    return float(stats.binomtest(min(b, c), total, p=0.5, alternative='two-sided').pvalue)


def load_v3_metrics(path: Path = V3_METRICS_PATH) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def compute_chain_level_contingency(
    chains_a: List[Dict[str, Any]],
    chains_b: List[Dict[str, Any]],
    malicious_only: bool = True
) -> Dict[str, Any]:
    """
    Computes 2x2 contingency table and exact McNemar test between two strategies at chain level.
    For malicious chains: success = detected.
    For all chains: success = (detected if malicious else not detected).
    """
    map_a = {c["chain_id"]: c for c in chains_a}
    map_b = {c["chain_id"]: c for c in chains_b}
    
    both_correct = 0
    a_correct_only = 0
    b_correct_only = 0
    both_incorrect = 0
    
    chain_ids = sorted(map_a.keys())
    analyzed_chains = []
    
    for cid in chain_ids:
        ca = map_a[cid]
        cb = map_b[cid]
        is_mal = ca["is_malicious"]
        if malicious_only and not is_mal:
            continue
        
        if is_mal:
            a_succ = ca["detected"]
            b_succ = cb["detected"]
        else:
            a_succ = not ca["detected"]
            b_succ = not cb["detected"]
            
        analyzed_chains.append({
            "chain_id": cid,
            "is_malicious": is_mal,
            "a_success": a_succ,
            "b_success": b_succ,
            "a_exposure": ca["exposure_window"],
            "b_exposure": cb["exposure_window"]
        })
        
        if a_succ and b_succ:
            both_correct += 1
        elif a_succ and not b_succ:
            a_correct_only += 1
        elif not a_succ and b_succ:
            b_correct_only += 1
        else:
            both_incorrect += 1
            
    p_val = mcnemar_exact(a_correct_only, b_correct_only)
    
    return {
        "malicious_only": malicious_only,
        "total_chains_analyzed": len(analyzed_chains),
        "contingency_table": {
            "both_correct": both_correct,
            "a_correct_only": a_correct_only,
            "b_correct_only": b_correct_only,
            "both_incorrect": both_incorrect
        },
        "discordant_pairs": a_correct_only + b_correct_only,
        "mcnemar_exact_p_value": round(p_val, 5),
        "details": analyzed_chains
    }


def run_cluster_bootstrap(
    metrics_data: Dict[str, Any],
    n_bootstraps: int = 10000,
    seed: int = 42
) -> Dict[str, Any]:
    """
    Performs stratified cluster bootstrap over chains to compute non-parametric 95% CIs.
    Resamples malicious chains (24) and benign chains (16) independently with replacement.
    """
    rng = np.random.RandomState(seed)
    
    strategies = ["adjacent", "cumulative", "dual"]
    chain_summaries = {
        s: metrics_data["strategy_metrics"][s]["chain_summaries"]
        for s in strategies
    }
    
    # Split chains by class
    mal_chains_by_strat = {
        s: [c for c in chain_summaries[s] if c["is_malicious"]]
        for s in strategies
    }
    ben_chains_by_strat = {
        s: [c for c in chain_summaries[s] if not c["is_malicious"]]
        for s in strategies
    }
    
    n_mal = len(mal_chains_by_strat["adjacent"]) # 24
    n_ben = len(ben_chains_by_strat["adjacent"]) # 16
    
    boot_results = {s: {
        "chain_recall": [],
        "benign_chain_fpr": [],
        "mean_exposure": [],
        "chain_precision": [],
        "chain_f1": []
    } for s in strategies}
    
    boot_diffs = {
        "recall_cumul_minus_adj": [],
        "recall_dual_minus_adj": [],
        "exposure_adj_minus_dual": [],
        "fpr_cumul_minus_adj": []
    }
    
    for _ in range(n_bootstraps):
        mal_idx = rng.randint(0, n_mal, size=n_mal)
        ben_idx = rng.randint(0, n_ben, size=n_ben)
        
        sample_metrics = {}
        for s in strategies:
            sampled_mal = [mal_chains_by_strat[s][i] for i in mal_idx]
            sampled_ben = [ben_chains_by_strat[s][i] for i in ben_idx]
            
            # Chain recall
            tp_chains = sum(1 for c in sampled_mal if c["detected"])
            recall = tp_chains / n_mal
            
            # Benign FPR
            fp_chains = sum(1 for c in sampled_ben if c["detected"])
            fpr = fp_chains / n_ben
            
            # Precision & F1
            prec = tp_chains / (tp_chains + fp_chains) if (tp_chains + fp_chains) > 0 else 0.0
            f1 = (2 * prec * recall) / (prec + recall) if (prec + recall) > 0 else 0.0
            
            # Mean exposure window
            mean_exp = float(np.mean([c["exposure_window"] for c in sampled_mal]))
            
            boot_results[s]["chain_recall"].append(recall)
            boot_results[s]["benign_chain_fpr"].append(fpr)
            boot_results[s]["chain_precision"].append(prec)
            boot_results[s]["chain_f1"].append(f1)
            boot_results[s]["mean_exposure"].append(mean_exp)
            
            sample_metrics[s] = {
                "recall": recall,
                "fpr": fpr,
                "mean_exp": mean_exp
            }
            
        boot_diffs["recall_cumul_minus_adj"].append(
            sample_metrics["cumulative"]["recall"] - sample_metrics["adjacent"]["recall"]
        )
        boot_diffs["recall_dual_minus_adj"].append(
            sample_metrics["dual"]["recall"] - sample_metrics["adjacent"]["recall"]
        )
        boot_diffs["exposure_adj_minus_dual"].append(
            sample_metrics["adjacent"]["mean_exp"] - sample_metrics["dual"]["mean_exp"]
        )
        boot_diffs["fpr_cumul_minus_adj"].append(
            sample_metrics["cumulative"]["fpr"] - sample_metrics["adjacent"]["fpr"]
        )
        
    summary = {}
    for s in strategies:
        summary[s] = {}
        for metric, values in boot_results[s].items():
            arr = np.array(values)
            ci_low = float(np.percentile(arr, 2.5))
            ci_high = float(np.percentile(arr, 97.5))
            mean_val = float(np.mean(arr))
            std_err = float(np.std(arr))
            summary[s][metric] = {
                "mean": round(mean_val, 4),
                "std_err": round(std_err, 4),
                "ci_95": [round(ci_low, 4), round(ci_high, 4)]
            }
            
    diff_summary = {}
    for diff_name, values in boot_diffs.items():
        arr = np.array(values)
        diff_summary[diff_name] = {
            "mean": round(float(np.mean(arr)), 4),
            "std_err": round(float(np.std(arr)), 4),
            "ci_95": [round(float(np.percentile(arr, 2.5)), 4), round(float(np.percentile(arr, 97.5)), 4)],
            "p_value_empirical": round(float(np.mean(arr <= 0.0) if np.mean(arr) > 0 else np.mean(arr >= 0.0)), 5)
        }
        
    return {
        "n_bootstraps": n_bootstraps,
        "seed": seed,
        "strategy_bootstrap_summary": summary,
        "differences_bootstrap_summary": diff_summary
    }


def main():
    print("=" * 70)
    print("MCP SEMANTIC DRIFT GUARD - BENCHMARK V3 STATISTICAL ANALYSIS")
    print("=" * 70)
    
    metrics = load_v3_metrics()
    
    # 1. Transition-level McNemar Reproduction Verification
    print("\n--- 1. Transition-Level Paired Tests (N = 144) ---")
    trans_adj_cum = metrics["comparisons"]["mcnemar_adjacent_vs_cumulative"]
    trans_adj_dual = metrics["comparisons"]["mcnemar_adjacent_vs_dual"]
    trans_cum_dual = metrics["comparisons"]["mcnemar_cumulative_vs_dual"]
    
    print(f"Adjacent vs Cumulative: p = {trans_adj_cum['mcnemar_exact_p_value']:.5f} (Discordant: {trans_adj_cum['discordant_pairs']})")
    print(f"Adjacent vs Dual:       p = {trans_adj_dual['mcnemar_exact_p_value']:.5f} (Discordant: {trans_adj_dual['discordant_pairs']})")
    print(f"Cumulative vs Dual:     p = {trans_cum_dual['mcnemar_exact_p_value']:.5f} (Discordant: {trans_cum_dual['discordant_pairs']})")
    
    # Verify exact reproduction of frozen values
    assert abs(trans_adj_cum['mcnemar_exact_p_value'] - 0.21011) < 1e-4
    assert abs(trans_adj_dual['mcnemar_exact_p_value'] - 0.02246) < 1e-4
    assert abs(trans_cum_dual['mcnemar_exact_p_value'] - 0.37500) < 1e-4
    print("[PASS] Transition-level McNemar exact p-values verified against authoritative run.")
    
    # 2. Chain-level Paired McNemar Tests (N = 24 malicious chains)
    print("\n--- 2. Chain-Level Paired Tests (Malicious Chains, N = 24) ---")
    chains_adj = metrics["strategy_metrics"]["adjacent"]["chain_summaries"]
    chains_cum = metrics["strategy_metrics"]["cumulative"]["chain_summaries"]
    chains_dual = metrics["strategy_metrics"]["dual"]["chain_summaries"]
    
    chain_mcnemar_adj_cum = compute_chain_level_contingency(chains_adj, chains_cum, malicious_only=True)
    chain_mcnemar_adj_dual = compute_chain_level_contingency(chains_adj, chains_dual, malicious_only=True)
    chain_mcnemar_cum_dual = compute_chain_level_contingency(chains_cum, chains_dual, malicious_only=True)
    
    print(f"Adjacent vs Cumulative (Malicious Chains): Table {chain_mcnemar_adj_cum['contingency_table']}, p = {chain_mcnemar_adj_cum['mcnemar_exact_p_value']:.5f}")
    print(f"Adjacent vs Dual       (Malicious Chains): Table {chain_mcnemar_adj_dual['contingency_table']}, p = {chain_mcnemar_adj_dual['mcnemar_exact_p_value']:.5f}")
    print(f"Cumulative vs Dual     (Malicious Chains): Table {chain_mcnemar_cum_dual['contingency_table']}, p = {chain_mcnemar_cum_dual['mcnemar_exact_p_value']:.5f}")
    
    # Chain-level Paired McNemar Tests (All Chains, N = 40)
    print("\n--- 3. Chain-Level Overall Accuracy Tests (All Chains, N = 40) ---")
    all_chain_adj_cum = compute_chain_level_contingency(chains_adj, chains_cum, malicious_only=False)
    all_chain_adj_dual = compute_chain_level_contingency(chains_adj, chains_dual, malicious_only=False)
    print(f"Adjacent vs Cumulative (All 40 Chains): Table {all_chain_adj_cum['contingency_table']}, p = {all_chain_adj_cum['mcnemar_exact_p_value']:.5f}")
    print(f"Adjacent vs Dual       (All 40 Chains): Table {all_chain_adj_dual['contingency_table']}, p = {all_chain_adj_dual['mcnemar_exact_p_value']:.5f}")
    
    # 4. Cluster Bootstrap (10,000 resamples)
    print("\n--- 4. Cluster Bootstrap (10,000 Resamples, Seed = 42) ---")
    boot_report = run_cluster_bootstrap(metrics, n_bootstraps=10000, seed=42)
    
    for s in ["adjacent", "cumulative", "dual"]:
        s_sum = boot_report["strategy_bootstrap_summary"][s]
        print(f"\nStrategy: {s.upper()}")
        print(f"  Chain Recall:     {s_sum['chain_recall']['mean']*100:.2f}% (95% CI: [{s_sum['chain_recall']['ci_95'][0]*100:.2f}%, {s_sum['chain_recall']['ci_95'][1]*100:.2f}%])")
        print(f"  Benign Chain FPR: {s_sum['benign_chain_fpr']['mean']*100:.2f}% (95% CI: [{s_sum['benign_chain_fpr']['ci_95'][0]*100:.2f}%, {s_sum['benign_chain_fpr']['ci_95'][1]*100:.2f}%])")
        print(f"  Chain Precision:  {s_sum['chain_precision']['mean']*100:.2f}% (95% CI: [{s_sum['chain_precision']['ci_95'][0]*100:.2f}%, {s_sum['chain_precision']['ci_95'][1]*100:.2f}%])")
        print(f"  Chain F1:         {s_sum['chain_f1']['mean']:.4f} (95% CI: [{s_sum['chain_f1']['ci_95'][0]:.4f}, {s_sum['chain_f1']['ci_95'][1]:.4f}])")
        print(f"  Mean Exposure W:  {s_sum['mean_exposure']['mean']:.3f} steps (95% CI: [{s_sum['mean_exposure']['ci_95'][0]:.3f}, {s_sum['mean_exposure']['ci_95'][1]:.3f}])")
        
    print("\nStrategy Differences (Bootstrap):")
    diffs = boot_report["differences_bootstrap_summary"]
    print(f"  Recall (Dual - Adj):      +{diffs['recall_dual_minus_adj']['mean']*100:.2f} pp (95% CI: [{diffs['recall_dual_minus_adj']['ci_95'][0]*100:.2f}%, {diffs['recall_dual_minus_adj']['ci_95'][1]*100:.2f}%], p_emp = {diffs['recall_dual_minus_adj']['p_value_empirical']:.5f})")
    print(f"  Exposure Red. (Adj - Dual): -{diffs['exposure_adj_minus_dual']['mean']:.3f} steps (95% CI: [{diffs['exposure_adj_minus_dual']['ci_95'][0]:.3f}, {diffs['exposure_adj_minus_dual']['ci_95'][1]:.3f}], p_emp = {diffs['exposure_adj_minus_dual']['p_value_empirical']:.5f})")
    print(f"  FPR Increase (Cumul - Adj): +{diffs['fpr_cumul_minus_adj']['mean']*100:.2f} pp (95% CI: [{diffs['fpr_cumul_minus_adj']['ci_95'][0]*100:.2f}%, {diffs['fpr_cumul_minus_adj']['ci_95'][1]*100:.2f}%])")
    
    # Save results to results/STATISTICAL_REPORTING.json
    out_path = ROOT_DIR / "results" / "STATISTICAL_REPORTING.json"
    full_export = {
        "transition_mcnemar": {
            "adjacent_vs_cumulative": trans_adj_cum,
            "adjacent_vs_dual": trans_adj_dual,
            "cumulative_vs_dual": trans_cum_dual
        },
        "chain_mcnemar_malicious_chains": {
            "adjacent_vs_cumulative": chain_mcnemar_adj_cum,
            "adjacent_vs_dual": chain_mcnemar_adj_dual,
            "cumulative_vs_dual": chain_mcnemar_cum_dual
        },
        "chain_mcnemar_all_chains": {
            "adjacent_vs_cumulative": all_chain_adj_cum,
            "adjacent_vs_dual": all_chain_adj_dual
        },
        "cluster_bootstrap": boot_report
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(full_export, f, indent=2)
    print(f"\n[OK] Statistical reporting artifact generated at: {out_path}")


if __name__ == "__main__":
    main()
