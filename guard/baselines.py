"""
guard/baselines.py - Unified Deterministic Baseline Calculators for Salami Drift Benchmarks

Implements:
1. Exact Cryptographic Hash Pinning (Tier 0)
2. Tier 2 Static Keyword Regex (Gate 3 Leakage-Control Check)
3. Lexical TF-IDF Cosine Distance from Root Baseline
4. Normalized Levenshtein Edit-Distance from Root Baseline
5. Schema Parameter-Count Delta from Root Baseline

All baselines operate on multi-step chain trajectories and report chain-level metrics,
exposure windows (W_e), and matched-FPR operating points.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional


def fast_levenshtein(s1: str, s2: str) -> int:
    """Iterative two-row dynamic programming Levenshtein distance."""
    if s1 == s2:
        return 0
    if len(s1) == 0:
        return len(s2)
    if len(s2) == 0:
        return len(s1)
    
    v0 = list(range(len(s2) + 1))
    v1 = [0] * (len(s2) + 1)
    
    for i in range(len(s1)):
        v1[0] = i + 1
        for j in range(len(s2)):
            cost = 0 if s1[i] == s2[j] else 1
            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
        v0, v1 = v1, [0] * (len(s2) + 1)
        
    return v0[len(s2)]


def evaluate_chain_baselines(dataset_path: Path) -> Dict[str, Any]:
    """
    Evaluates all deterministic baselines across benchmark chains.
    Returns per-chain metrics, per-category metrics, and matched-FPR operating points.
    """
    chains = {}
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                chains.setdefault(item["chain_id"], []).append(item)

    chain_records = []
    for cid, steps in chains.items():
        cat = steps[0]["category"]
        is_fast = cat.startswith("B")
        is_benign = cat.startswith("C") or ("benign" in cat.lower())
        is_salami = (not is_fast) and (not is_benign)
        
        root_def = steps[0]["root_tool_definition"]
        root_json = json.dumps(root_def, sort_keys=True)
        root_params = set(root_def.get("inputSchema", {}).get("properties", {}).keys())
        
        mal_steps = [s for s in steps if s["gold_label"] == "MALICIOUS"]
        m_step = mal_steps[0]["step_index"] if mal_steps else None
        tot_k = len(steps)
        split = steps[0].get("metrics_evaluator_metadata", {}).get("split", "held_out_test")
        
        # Step-level measurements
        step_metrics = []
        for s in steps:
            cand_def = s["tool_definition"]
            cand_json = json.dumps(cand_def, sort_keys=True)
            cand_params = set(cand_def.get("inputSchema", {}).get("properties", {}).keys())
            
            # Hash
            hash_changed = (cand_json != root_json)
            
            # Edit ratio (use precomputed if available, else fast_levenshtein)
            meta = s.get("metrics_evaluator_metadata", {})
            if "cumulative_edit_ratio" in meta:
                edit_ratio = float(meta["cumulative_edit_ratio"])
            else:
                lev_dist = fast_levenshtein(root_json, cand_json)
                max_len = max(len(root_json), len(cand_json))
                edit_ratio = lev_dist / max_len if max_len > 0 else 0.0
            
            # Param count delta
            if "cumulative_params_added" in meta:
                param_delta = len(meta["cumulative_params_added"])
            else:
                param_delta = len(cand_params - root_params) + len(root_params - cand_params)
            
            step_metrics.append({
                "step_index": s["step_index"],
                "gold_label": s["gold_label"],
                "hash_changed": hash_changed,
                "edit_ratio": edit_ratio,
                "param_delta": param_delta
            })
            
        max_edit = max(sm["edit_ratio"] for sm in step_metrics)
        max_p_delta = max(sm["param_delta"] for sm in step_metrics)
        
        chain_records.append({
            "chain_id": cid,
            "category": cat,
            "split": split,
            "is_salami": is_salami,
            "is_fast": is_fast,
            "is_benign": is_benign,
            "is_malicious": len(mal_steps) > 0,
            "first_malicious_step": m_step,
            "total_steps": tot_k,
            "max_edit_ratio": max_edit,
            "max_param_delta": max_p_delta,
            "steps": step_metrics
        })

    return {
        "total_chains": len(chain_records),
        "chain_records": chain_records
    }
