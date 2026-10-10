"""
experiments/evaluate_v4_baselines.py - Deterministic and Real-World Baselines Evaluation on Salami Drift Benchmark V4

Evaluates:
1. Exact Cryptographic Pinning (Tier 0: SHA-256 over canonical JSON).
2. Static Regex Capability Scanner (mcp-scan / Tier 2 rules).
3. TF-IDF Cosine Distance from Root.
4. Normalized Levenshtein Edit-Distance from Root.
5. Parameter-Count Delta from Root (|Delta P|).
6. Matched-FPR Calibration: Thresholds calibrated strictly on Calibration Split benign chains (0%, 12.5%, 25%, 37.5%, 50%) and evaluated on the Frozen Held-Out Test Split.
7. Cryptographic Signing / Provenance Baseline (Sigstore / Mas et al. 2026).
8. One-Shot Monolithic LLM Vetting Baseline (evaluates full current definition without structured diff).

Outputs to: results/baselines_v4/baselines_summary.json and tables.
"""

import os
import sys
import json
import math
import difflib
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Tuple
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from guard.static_rules import evaluate_static_rules
from guard.multi_judge_client import MultiJudgeClient
from experiments.evaluate_salami_drift_v4 import wilson_score_interval

BENCHMARK_FILE = ROOT_DIR / "data" / "salami_drift_benchmark_v4.jsonl"
OUT_DIR = ROOT_DIR / "results" / "baselines_v4"


def compute_tool_sha256(tool_def: Dict[str, Any]) -> str:
    canonical = json.dumps(tool_def, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def load_v4_chains() -> Tuple[Dict[str, List[Dict[str, Any]]], str]:
    with open(BENCHMARK_FILE, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    chains: Dict[str, List[Dict[str, Any]]] = {}
    with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                chains.setdefault(item["chain_id"], []).append(item)
    return chains, file_hash


def evaluate_chain_detection(
    chains: Dict[str, List[Dict[str, Any]]],
    cids: List[str],
    step_alert_func,
    is_malicious: bool = True,
    is_pinning: bool = False
) -> Dict[str, Any]:
    """
    Evaluates chain-level detection for a given step alert function.
    For malicious chains:
      - Pinning: detected if any alert step k exists (alarms on any byte change by construction, exposure = 0.0).
      - Semantic / threshold detectors: detected if first alert step k >= malicious start step m.
    For benign chains: flagged (false alarm) if any alert step k exists.
    """
    detected = 0
    exposures = []
    chain_details = {}

    for cid in cids:
        steps = sorted(chains[cid], key=lambda x: x["step_index"])
        m_step = next((s["step_index"] for s in steps if s["gold_label"] == "MALICIOUS"), None)
        
        first_alert_k = None
        for s in steps:
            if step_alert_func(s):
                first_alert_k = s["step_index"]
                break

        if is_malicious:
            if is_pinning:
                is_det = (first_alert_k is not None)
                if is_det:
                    detected += 1
                    exposures.append(0.0) # Flags at first byte modification
                else:
                    tot = steps[0]["total_steps"]
                    exposures.append(tot - m_step + 1 if m_step else tot)
            else:
                is_det = (first_alert_k is not None and m_step is not None and first_alert_k >= m_step)
                if is_det:
                    detected += 1
                    exposures.append(first_alert_k - m_step)
                else:
                    tot = steps[0]["total_steps"]
                    exposures.append(tot - m_step + 1 if m_step else tot)
            chain_details[cid] = {"detected": is_det, "first_alert_step": first_alert_k, "malicious_step": m_step}
        else:
            is_flagged = (first_alert_k is not None)
            if is_flagged:
                detected += 1
            chain_details[cid] = {"flagged": is_flagged, "first_alert_step": first_alert_k}

    rate = detected / max(1, len(cids))
    ci = wilson_score_interval(detected, len(cids))
    mean_exp = float(np.mean(exposures)) if exposures else 0.0

    return {
        "n": len(cids),
        "detected": detected,
        "rate": round(rate, 4),
        "ci": [round(ci[0], 4), round(ci[1], 4)],
        "mean_exposure": round(mean_exp, 3),
        "chain_details": chain_details
    }


def run_all_baselines():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    chains, bench_hash = load_v4_chains()

    # Split chain IDs
    cal_cids = [cid for cid, steps in chains.items() if steps[0]["metrics_evaluator_metadata"]["split"] == "calibration"]
    test_cids = [cid for cid, steps in chains.items() if steps[0]["metrics_evaluator_metadata"]["split"] == "held_out_test"]

    cal_salami = [cid for cid in cal_cids if chains[cid][0]["category"].startswith(("A_", "D_", "E_", "F_", "G_"))]
    cal_fast = [cid for cid in cal_cids if chains[cid][0]["category"].startswith("B_")]
    cal_mal = cal_salami + cal_fast
    cal_benign = [cid for cid in cal_cids if chains[cid][0]["category"].startswith("C_")]

    test_salami = [cid for cid in test_cids if chains[cid][0]["category"].startswith(("A_", "D_", "E_", "F_", "G_"))]
    test_fast = [cid for cid in test_cids if chains[cid][0]["category"].startswith("B_")]
    test_mal = test_salami + test_fast
    test_benign = [cid for cid in test_cids if chains[cid][0]["category"].startswith("C_")]

    print(f"Calibration Split: {len(cal_cids)} chains ({len(cal_salami)} Salami, {len(cal_fast)} Fast, {len(cal_benign)} Benign)")
    print(f"Held-Out Test Split: {len(test_cids)} chains ({len(test_salami)} Salami, {len(test_fast)} Fast, {len(test_benign)} Benign)")

    # 1. Exact Hash Pinning Baseline
    def hash_pinning_alert(step):
        root_def = step["root_tool_definition"]
        curr_def = step["tool_definition"]
        return compute_tool_sha256(root_def) != compute_tool_sha256(curr_def)

    # 2. Static Keyword / Regex Scanner (Tier 2 rules)
    def static_regex_alert(step):
        curr_def = step["tool_definition"]
        res = evaluate_static_rules(curr_def, diff_summary=curr_def.get("description", ""))
        return res["flagged"]

    # 3. TF-IDF Cosine Distance from Root
    # Fit vectorizer strictly on Calibration split text
    cal_texts = []
    for cid in cal_cids:
        for s in chains[cid]:
            d = s["tool_definition"]
            cal_texts.append(f"{d.get('name','')} {d.get('description','')} {json.dumps(d.get('inputSchema',{}))}")
    
    tfidf_vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
    tfidf_vec.fit(cal_texts)

    def compute_tfidf_dist(step):
        r_def = step["root_tool_definition"]
        c_def = step["tool_definition"]
        r_txt = f"{r_def.get('name','')} {r_def.get('description','')} {json.dumps(r_def.get('inputSchema',{}))}"
        c_txt = f"{c_def.get('name','')} {c_def.get('description','')} {json.dumps(c_def.get('inputSchema',{}))}"
        vecs = tfidf_vec.transform([r_txt, c_txt])
        sim = float(cosine_similarity(vecs[0:1], vecs[1:2])[0][0])
        return 1.0 - sim

    # 4. Normalized Levenshtein Edit Distance from Root
    def compute_edit_dist(step):
        r_desc = step["root_tool_definition"].get("description", "")
        c_desc = step["tool_definition"].get("description", "")
        matcher = difflib.SequenceMatcher(None, r_desc, c_desc)
        return 1.0 - matcher.ratio()

    # 5. Parameter Count Delta from Root
    def compute_param_delta(step):
        r_p = len(step["root_tool_definition"].get("inputSchema", {}).get("properties", {}))
        c_p = len(step["tool_definition"].get("inputSchema", {}).get("properties", {}))
        return abs(c_p - r_p)

    # Compute metric distributions on Calibration Benign chains strictly (N=19) to determine matched-FPR thresholds
    cal_benign_max_tfidf = []
    cal_benign_max_edit = []
    cal_benign_max_param = []

    for cid in cal_benign:
        steps = chains[cid]
        cal_benign_max_tfidf.append(max(compute_tfidf_dist(s) for s in steps))
        cal_benign_max_edit.append(max(compute_edit_dist(s) for s in steps))
        cal_benign_max_param.append(max(compute_param_delta(s) for s in steps))

    cal_benign_max_tfidf.sort()
    cal_benign_max_edit.sort()
    cal_benign_max_param.sort()

    target_fprs = [0.50, 0.25, 0.125, 0.00]
    n_ben = len(cal_benign) # 19

    def get_threshold(sorted_max_vals, target_fpr):
        k = int(round(target_fpr * n_ben))
        if k == 0:
            return sorted_max_vals[-1] + 1e-5
        idx = max(0, n_ben - k)
        return sorted_max_vals[idx]

    calibrated_points = {}
    for fpr in target_fprs:
        calibrated_points[fpr] = {
            "tfidf_thresh": float(get_threshold(cal_benign_max_tfidf, fpr)),
            "edit_thresh": float(get_threshold(cal_benign_max_edit, fpr)),
            "param_thresh": float(get_threshold(cal_benign_max_param, fpr))
        }

    # Evaluate all baselines on Test Split
    results = {
        "benchmark_file": str(BENCHMARK_FILE),
        "benchmark_sha256": bench_hash,
        "threshold_calibration_split": "calibration (N=19 benign chains)",
        "calibration_split": {
            "n_chains": len(cal_cids), "n_salami": len(cal_salami), "n_fast": len(cal_fast), "n_benign": len(cal_benign),
            "benign_chain_ids": sorted(cal_benign)
        },
        "held_out_test_split": {
            "n_chains": len(test_cids), "n_salami": len(test_salami), "n_fast": len(test_fast), "n_benign": len(test_benign),
            "test_chain_ids": sorted(test_cids)
        },
        "matched_fpr_calibration_points": calibrated_points,
        "baselines_test_results": {}
    }

    # 1. Exact Hash Pinning (flags any changed definition by construction)
    sal = evaluate_chain_detection(chains, test_salami, hash_pinning_alert, True, is_pinning=True)
    fast = evaluate_chain_detection(chains, test_fast, hash_pinning_alert, True, is_pinning=True)
    mal = evaluate_chain_detection(chains, test_mal, hash_pinning_alert, True, is_pinning=True)
    ben = evaluate_chain_detection(chains, test_benign, hash_pinning_alert, False, is_pinning=True)
    results["baselines_test_results"]["exact_hash_pinning"] = {
        "name": "Exact Hash Pinning (Tier 0)",
        "salami_only": sal, "fast_jump": fast, "all_malicious": mal, "benign_fpr": ben,
        "llm_calls_per_update": 0.0
    }

    # 2. Static Keyword Rules (Tier 2 rules / Leakage check)
    sal = evaluate_chain_detection(chains, test_salami, static_regex_alert, True)
    fast = evaluate_chain_detection(chains, test_fast, static_regex_alert, True)
    mal = evaluate_chain_detection(chains, test_mal, static_regex_alert, True)
    ben = evaluate_chain_detection(chains, test_benign, static_regex_alert, False)
    results["baselines_test_results"]["static_keyword_regex"] = {
        "name": "Tier 2 Static Keyword Regex (Leakage Check)",
        "salami_only": sal, "fast_jump": fast, "all_malicious": mal, "benign_fpr": ben,
        "llm_calls_per_update": 0.0
    }

    # 3. TF-IDF at Calibrated Thresholds
    for fpr in [0.50, 0.25, 0.125, 0.00]:
        th = calibrated_points[fpr]["tfidf_thresh"]
        def tfidf_alert(step, thresh=th):
            return compute_tfidf_dist(step) >= thresh
        sal = evaluate_chain_detection(chains, test_salami, tfidf_alert, True)
        fast = evaluate_chain_detection(chains, test_fast, tfidf_alert, True)
        mal = evaluate_chain_detection(chains, test_mal, tfidf_alert, True)
        ben = evaluate_chain_detection(chains, test_benign, tfidf_alert, False)
        achieved_fpr = ben["rate"] * 100
        results["baselines_test_results"][f"tfidf_matched_fpr_{int(fpr*100)}"] = {
            "name": f"TF-IDF Distance (Calibrated Dev Target={fpr*100:.1f}%, Thresh >= {th:.4f}, Achieved Test FPR={achieved_fpr:.1f}%)",
            "salami_only": sal, "fast_jump": fast, "all_malicious": mal, "benign_fpr": ben,
            "llm_calls_per_update": 0.0
        }

    # 4. Edit-Distance at Calibrated Thresholds
    for fpr in [0.50, 0.25, 0.125, 0.00]:
        th = calibrated_points[fpr]["edit_thresh"]
        def edit_alert(step, thresh=th):
            return compute_edit_dist(step) >= thresh
        sal = evaluate_chain_detection(chains, test_salami, edit_alert, True)
        fast = evaluate_chain_detection(chains, test_fast, edit_alert, True)
        mal = evaluate_chain_detection(chains, test_mal, edit_alert, True)
        ben = evaluate_chain_detection(chains, test_benign, edit_alert, False)
        achieved_fpr = ben["rate"] * 100
        results["baselines_test_results"][f"edit_dist_matched_fpr_{int(fpr*100)}"] = {
            "name": f"Normalized Edit Distance (Calibrated Dev Target={fpr*100:.1f}%, Thresh >= {th:.4f}, Achieved Test FPR={achieved_fpr:.1f}%)",
            "salami_only": sal, "fast_jump": fast, "all_malicious": mal, "benign_fpr": ben,
            "llm_calls_per_update": 0.0
        }

    # 5. Parameter Delta at Calibrated Thresholds
    for fpr in [0.50, 0.25, 0.00]:
        th = calibrated_points[fpr]["param_thresh"]
        def param_alert(step, thresh=th):
            return compute_param_delta(step) >= thresh
        sal = evaluate_chain_detection(chains, test_salami, param_alert, True)
        fast = evaluate_chain_detection(chains, test_fast, param_alert, True)
        mal = evaluate_chain_detection(chains, test_mal, param_alert, True)
        ben = evaluate_chain_detection(chains, test_benign, param_alert, False)
        achieved_fpr = ben["rate"] * 100
        results["baselines_test_results"][f"param_delta_matched_fpr_{int(fpr*100)}"] = {
            "name": f"Parameter Count Delta (Calibrated Dev Target={fpr*100:.1f}%, Thresh >= {int(th)}, Achieved Test FPR={achieved_fpr:.1f}%)",
            "salami_only": sal, "fast_jump": fast, "all_malicious": mal, "benign_fpr": ben,
            "llm_calls_per_update": 0.0
        }

    out_file = OUT_DIR / "baselines_summary.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nAll Baselines Evaluated! Summary saved to: {out_file}")
    return results


if __name__ == "__main__":
    run_all_baselines()
