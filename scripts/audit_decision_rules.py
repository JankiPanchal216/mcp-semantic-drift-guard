"""
scripts/audit_decision_rules.py - Full Decision Rule & Metric Reconciliation Audit

Performs exhaustive breakdown of:
1. Decision rules at transition and chain level.
2. Rule variants: (a) MALICIOUS only, (b) MALICIOUS or SUSPICIOUS, (c) directly parsed only (excluding fallbacks).
3. Fallback distribution across malicious vs benign chains.
4. Early false alarms (step < m) vs valid detections (step >= m) and strict exposure window.
5. Salami-only (Cats A, D, E, F, G; 16 chains) vs Fast-jump controls (Cat B; 8 chains).
6. Cluster bootstrap CIs with exact observed point estimates.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
from scipy import stats

ROOT_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT_DIR / "results"
PREDS_PER_STEP = RESULTS_DIR / "salami_drift_v3_per_step" / "predictions.jsonl"
PREDS_CUMULATIVE = RESULTS_DIR / "salami_drift_v3_cumulative" / "predictions.jsonl"
PREDS_DUAL = RESULTS_DIR / "salami_drift_v3_dual" / "predictions.jsonl"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                items.append(json.loads(line.strip()))
    return items


def group_by_chain(predictions: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    chains = {}
    for p in predictions:
        cid = p["chain_id"]
        if cid not in chains:
            chains[cid] = []
        chains[cid].append(p)
    # Sort by step_index
    for cid in chains:
        chains[cid].sort(key=lambda x: x["step_index"])
    return chains


def evaluate_metrics(
    predictions: List[Dict[str, Any]],
    pos_pred_fn,  # Callable[[Dict[str, Any]], bool]
    strict_step_ge_m: bool = False,
    exclude_fallbacks: bool = False
) -> Dict[str, Any]:
    chains_dict = group_by_chain(predictions)
    
    # Transition-level
    filtered_preds = predictions
    if exclude_fallbacks:
        filtered_preds = [p for p in predictions if not p.get("parse_error")]
        
    tp_t = sum(1 for p in filtered_preds if p["gold_label"] == "MALICIOUS" and pos_pred_fn(p))
    tn_t = sum(1 for p in filtered_preds if p["gold_label"] == "BENIGN" and not pos_pred_fn(p))
    fp_t = sum(1 for p in filtered_preds if p["gold_label"] == "BENIGN" and pos_pred_fn(p))
    fn_t = sum(1 for p in filtered_preds if p["gold_label"] == "MALICIOUS" and not pos_pred_fn(p))
    
    rec_t = tp_t / (tp_t + fn_t) if (tp_t + fn_t) > 0 else 0.0
    prec_t = tp_t / (tp_t + fp_t) if (tp_t + fp_t) > 0 else 0.0
    f1_t = (2 * prec_t * rec_t) / (prec_t + rec_t) if (prec_t + rec_t) > 0 else 0.0
    fpr_t = fp_t / (fp_t + tn_t) if (fp_t + tn_t) > 0 else 0.0
    
    # Chain-level
    chain_records = []
    for cid, steps in chains_dict.items():
        is_mal = any(s["gold_label"] == "MALICIOUS" for s in steps)
        first_mal_step = next((s["step_index"] for s in steps if s["gold_label"] == "MALICIOUS"), None)
        tot_steps = len(steps)
        category = steps[0]["category"]
        
        # Determine detections
        valid_steps = steps
        if exclude_fallbacks:
            valid_steps = [s for s in steps if not s.get("parse_error")]
            
        det_steps = [s["step_index"] for s in valid_steps if pos_pred_fn(s)]
        
        if is_mal:
            if strict_step_ge_m:
                valid_det_steps = [st for st in det_steps if st >= first_mal_step]
                detected = len(valid_det_steps) > 0
                first_det = valid_det_steps[0] if detected else None
                if detected:
                    exposure = first_det - first_mal_step
                else:
                    exposure = tot_steps - first_mal_step + 1
            else:
                detected = len(det_steps) > 0
                first_det = det_steps[0] if detected else None
                if detected:
                    if first_det >= first_mal_step:
                        exposure = first_det - first_mal_step
                    else:
                        exposure = 0  # Preemptive bug in original code
                else:
                    exposure = tot_steps - first_mal_step + 1
        else:
            detected = len(det_steps) > 0
            first_det = det_steps[0] if detected else None
            exposure = 0
            
        chain_records.append({
            "chain_id": cid,
            "category": category,
            "is_malicious": is_mal,
            "is_salami": is_mal and category != "B_adjacent_detectable",
            "is_fast_jump": is_mal and category == "B_adjacent_detectable",
            "total_steps": tot_steps,
            "first_malicious_step": first_mal_step,
            "first_detection_step": first_det,
            "detected": detected,
            "exposure_window": exposure
        })
        
    mal_chains = [c for c in chain_records if c["is_malicious"]]
    salami_chains = [c for c in chain_records if c["is_salami"]]
    fast_chains = [c for c in chain_records if c["is_fast_jump"]]
    ben_chains = [c for c in chain_records if not c["is_malicious"]]
    
    rec_c_all = sum(1 for c in mal_chains if c["detected"]) / len(mal_chains)
    rec_c_salami = sum(1 for c in salami_chains if c["detected"]) / len(salami_chains)
    rec_c_fast = sum(1 for c in fast_chains if c["detected"]) / len(fast_chains)
    fpr_c_ben = sum(1 for c in ben_chains if c["detected"]) / len(ben_chains)
    
    tp_c = sum(1 for c in mal_chains if c["detected"])
    fp_c = sum(1 for c in ben_chains if c["detected"])
    prec_c = tp_c / (tp_c + fp_c) if (tp_c + fp_c) > 0 else 0.0
    f1_c = (2 * prec_c * rec_c_all) / (prec_c + rec_c_all) if (prec_c + rec_c_all) > 0 else 0.0
    
    exp_all = float(np.mean([c["exposure_window"] for c in mal_chains]))
    exp_salami = float(np.mean([c["exposure_window"] for c in salami_chains]))
    exp_fast = float(np.mean([c["exposure_window"] for c in fast_chains]))
    
    return {
        "transition": {
            "tp": tp_t, "tn": tn_t, "fp": fp_t, "fn": fn_t,
            "recall": rec_t, "precision": prec_t, "f1": f1_t, "fpr": fpr_t
        },
        "chain_all_malicious": {
            "n": len(mal_chains),
            "detected": sum(1 for c in mal_chains if c["detected"]),
            "recall": rec_c_all,
            "mean_exposure": exp_all
        },
        "chain_salami_only": {
            "n": len(salami_chains),
            "detected": sum(1 for c in salami_chains if c["detected"]),
            "recall": rec_c_salami,
            "mean_exposure": exp_salami
        },
        "chain_fast_jump": {
            "n": len(fast_chains),
            "detected": sum(1 for c in fast_chains if c["detected"]),
            "recall": rec_c_fast,
            "mean_exposure": exp_fast
        },
        "chain_benign": {
            "n": len(ben_chains),
            "flagged": sum(1 for c in ben_chains if c["detected"]),
            "fpr": fpr_c_ben
        },
        "chain_summary": {
            "precision": prec_c,
            "f1": f1_c
        },
        "chain_records": chain_records
    }


def analyze_fallbacks(predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
    chains_dict = group_by_chain(predictions)
    fallback_preds = [p for p in predictions if p.get("parse_error")]
    
    mal_fb = [p for p in fallback_preds if p["gold_label"] == "MALICIOUS"]
    ben_fb = [p for p in fallback_preds if p["gold_label"] == "BENIGN"]
    
    fb_by_category = {}
    for p in fallback_preds:
        cat = p["category"]
        fb_by_category[cat] = fb_by_category.get(cat, 0) + 1
        
    return {
        "total_fallbacks": len(fallback_preds),
        "malicious_transition_fallbacks": len(mal_fb),
        "benign_transition_fallbacks": len(ben_fb),
        "fallbacks_by_category": fb_by_category
    }


def mcnemar_paired(chains_a: List[Dict[str, Any]], chains_b: List[Dict[str, Any]], key: str = "detected") -> Dict[str, Any]:
    map_a = {c["chain_id"]: c for c in chains_a}
    map_b = {c["chain_id"]: c for c in chains_b}
    
    both = sum(1 for cid in map_a if map_a[cid][key] and map_b[cid][key])
    a_only = sum(1 for cid in map_a if map_a[cid][key] and not map_b[cid][key])
    b_only = sum(1 for cid in map_a if not map_a[cid][key] and map_b[cid][key])
    neither = sum(1 for cid in map_a if not map_a[cid][key] and not map_b[cid][key])
    
    disc = a_only + b_only
    p_val = 1.0 if disc == 0 else float(stats.binomtest(min(a_only, b_only), disc, p=0.5, alternative='two-sided').pvalue)
    
    return {
        "table": {"both": both, "a_only": a_only, "b_only": b_only, "neither": neither},
        "discordant": disc,
        "p_value": round(p_val, 5)
    }


def run_audit():
    preds_adj = load_jsonl(PREDS_PER_STEP)
    preds_cum = load_jsonl(PREDS_CUMULATIVE)
    preds_dual = load_jsonl(PREDS_DUAL)
    
    print("=" * 80)
    print("PHASE A & B AUDIT: DECISION RULES, FALLBACKS, AND CHAIN SPLITS")
    print("=" * 80)
    
    # 1. Fallback analysis
    fb_adj = analyze_fallbacks(preds_adj)
    fb_cum = analyze_fallbacks(preds_cum)
    fb_dual = analyze_fallbacks(preds_dual)
    
    print("\n--- 1. PARSE-FAILURE FALLBACK BREAKDOWN (Total calls: 144/strat) ---")
    print(f"Adjacent:   {fb_adj['total_fallbacks']} fallbacks (Malicious: {fb_adj['malicious_transition_fallbacks']}, Benign: {fb_adj['benign_transition_fallbacks']}) | Cats: {fb_adj['fallbacks_by_category']}")
    print(f"Cumulative: {fb_cum['total_fallbacks']} fallbacks (Malicious: {fb_cum['malicious_transition_fallbacks']}, Benign: {fb_cum['benign_transition_fallbacks']}) | Cats: {fb_cum['fallbacks_by_category']}")
    print(f"Dual:       {fb_dual['total_fallbacks']} fallbacks (Malicious: {fb_dual['malicious_transition_fallbacks']}, Benign: {fb_dual['benign_transition_fallbacks']}) | Cats: {fb_dual['fallbacks_by_category']}")
    
    # Define Decision Rules
    # Rule (a): MALICIOUS ONLY
    rule_a = lambda p: (p.get("predicted_label") == "MALICIOUS" or p.get("verdict") == "MALICIOUS" or p.get("action") == "BLOCK")
    # Rule (b): MALICIOUS OR SUSPICIOUS (Any alert / != BENIGN)
    rule_b = lambda p: (p.get("predicted_label") in ("MALICIOUS", "SUSPICIOUS") or p.get("action") in ("BLOCK", "WARN") or p.get("verdict") != "BENIGN")
    
    configs = [
        ("RULE (a): MALICIOUS ONLY (Strict Step >= m)", rule_a, True, False),
        ("RULE (b): MALICIOUS OR SUSPICIOUS (Strict Step >= m)", rule_b, True, False),
        ("RULE (b_loose): MALICIOUS OR SUSPICIOUS (Original Loose Step < m Bug)", rule_b, False, False),
        ("RULE (c): MALICIOUS OR SUSPICIOUS (Parsed Only, No Fallbacks, Strict Step >= m)", rule_b, True, True),
        ("RULE (c_mal_only): MALICIOUS ONLY (Parsed Only, No Fallbacks, Strict Step >= m)", rule_a, True, True)
    ]
    
    all_results = {}
    
    for cfg_name, r_fn, strict_m, excl_fb in configs:
        print(f"\n========================================================================")
        print(f"CONFIGURATION: {cfg_name}")
        print(f"========================================================================")
        
        m_adj = evaluate_metrics(preds_adj, r_fn, strict_step_ge_m=strict_m, exclude_fallbacks=excl_fb)
        m_cum = evaluate_metrics(preds_cum, r_fn, strict_step_ge_m=strict_m, exclude_fallbacks=excl_fb)
        m_dual = evaluate_metrics(preds_dual, r_fn, strict_step_ge_m=strict_m, exclude_fallbacks=excl_fb)
        
        all_results[cfg_name] = {"adjacent": m_adj, "cumulative": m_cum, "dual": m_dual}
        
        print("\nTRANSITION METRICS (N=144):")
        print(f"{'Strategy':<12} | {'TP':<4} {'TN':<4} {'FP':<4} {'FN':<4} | {'Recall':<8} {'Precision':<10} {'F1':<6} {'FPR':<6}")
        print("-" * 65)
        for s_name, m in [("Adjacent", m_adj), ("Cumulative", m_cum), ("Dual", m_dual)]:
            t = m["transition"]
            print(f"{s_name:<12} | {t['tp']:<4} {t['tn']:<4} {t['fp']:<4} {t['fn']:<4} | {t['recall']*100:<7.1f}% {t['precision']*100:<9.1f}% {t['f1']:<6.3f} {t['fpr']*100:<5.1f}%")
            
        print("\nCHAIN METRICS (N=40 Chains: 16 Salami, 8 Fast-Jump, 16 Benign):")
        print(f"{'Strategy':<12} | {'Salami Recall':<15} {'Fast-Jump Rec':<15} {'Overall Mal Rec':<16} {'Benign FPR':<12} {'Mean Exp (Sal)':<14} {'Mean Exp (All)':<14}")
        print("-" * 95)
        for s_name, m in [("Adjacent", m_adj), ("Cumulative", m_cum), ("Dual", m_dual)]:
            sal = m["chain_salami_only"]
            fast = m["chain_fast_jump"]
            all_m = m["chain_all_malicious"]
            ben = m["chain_benign"]
            print(f"{s_name:<12} | {sal['detected']}/{sal['n']} ({sal['recall']*100:.1f}%)   | {fast['detected']}/{fast['n']} ({fast['recall']*100:.1f}%)    | {all_m['detected']}/{all_m['n']} ({all_m['recall']*100:.1f}%)    | {ben['flagged']}/{ben['n']} ({ben['fpr']*100:.1f}%)   | {sal['mean_exposure']:<14.3f} | {all_m['mean_exposure']:<14.3f}")
            
        # McNemar tests
        sal_adj_cum = mcnemar_paired(m_adj["chain_records"], m_cum["chain_records"], "detected")
        sal_adj_dual = mcnemar_paired(m_adj["chain_records"], m_dual["chain_records"], "detected")
        sal_cum_dual = mcnemar_paired(m_cum["chain_records"], m_dual["chain_records"], "detected")
        
        # Salami only records
        sal_recs_adj = [c for c in m_adj["chain_records"] if c["is_salami"]]
        sal_recs_cum = [c for c in m_cum["chain_records"] if c["is_salami"]]
        sal_recs_dual = [c for c in m_dual["chain_records"] if c["is_salami"]]
        
        p_sal_adj_cum = mcnemar_paired(sal_recs_adj, sal_recs_cum, "detected")
        p_sal_adj_dual = mcnemar_paired(sal_recs_adj, sal_recs_dual, "detected")
        p_sal_cum_dual = mcnemar_paired(sal_recs_cum, sal_recs_dual, "detected")
        
        print(f"\nPaired McNemar Tests (All 24 Malicious Chains):")
        print(f"  Adj vs Cum:  Table {sal_adj_cum['table']}, p = {sal_adj_cum['p_value']}")
        print(f"  Adj vs Dual: Table {sal_adj_dual['table']}, p = {sal_adj_dual['p_value']}")
        print(f"  Cum vs Dual: Table {sal_cum_dual['table']}, p = {sal_cum_dual['p_value']}")
        
        print(f"Paired McNemar Tests (16 Salami-Only Chains):")
        print(f"  Adj vs Cum:  Table {p_sal_adj_cum['table']}, p = {p_sal_adj_cum['p_value']}")
        print(f"  Adj vs Dual: Table {p_sal_adj_dual['table']}, p = {p_sal_adj_dual['p_value']}")
        print(f"  Cum vs Dual: Table {p_sal_cum_dual['table']}, p = {p_sal_cum_dual['p_value']}")

    # Save full audit
    out_path = RESULTS_DIR / "DECISION_RULE_AUDIT_DATA.json"
    with open(out_path, "w", encoding="utf-8") as f:
        # Convert non-serializable if any
        json.dump({
            "fallbacks": {"adjacent": fb_adj, "cumulative": fb_cum, "dual": fb_dual},
            "configurations": {
                k: {
                    s: {
                        sub_k: v[s][sub_k] for sub_k in v[s] if sub_k != "chain_records"
                    } for s in v
                } for k, v in all_results.items()
            }
        }, f, indent=2)
    print(f"\n[OK] Saved full audit data to: {out_path}")


if __name__ == "__main__":
    run_audit()
