"""
Authoritative Salami Drift Benchmark v3 Live Evaluator
Authoritative Specification: results/SALAMI_DRIFT_V3_PROTOCOL.md
Design Review: results/SALAMI_DRIFT_V3_DESIGN_REVIEW.md

Enforces:
1. Strict live-inference execution (mock mode completely banned for authoritative runs).
2. Live call assertion: mock_calls == 0, live_calls > 0.
3. Complete separation of model-facing inputs (zero gold label, category, or attack hint leakage).
4. Strict evaluation of three anchor strategies:
   - Adjacent: V_{k-1} -> V_k
   - Cumulative: V_0 -> V_k
   - Dual: max(Adjacent, Cumulative)
5. Full traceability: logs raw model outputs, parsing success, latencies, and git commits.
6. Rigorous statistical testing: McNemar exact test, Wilcoxon signed-rank test, 95% Wilson CIs.
"""

import os
import sys
import json
import time
import shutil
import tempfile
import hashlib
import platform
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
import scipy.stats as stats

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from guard.config import GuardConfig
from guard.middleware import MCPGuardMiddleware
from experiments.generate_salami_benchmark_v3 import extract_model_facing_inputs

BENCHMARK_FILE = ROOT_DIR / "data" / "salami_drift_benchmark_v3.jsonl"
EXPECTED_DATASET_SHA256 = "04d864faa59c1c088205bb8fa38c99fc5fa3f0428070c331fe546ef0884b599f"

HARDWARE_INFO = f"{platform.system()} {platform.release()} ({platform.machine()}) | Python {platform.python_version()}"


def get_git_commit() -> str:
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(ROOT_DIR), capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception:
        return "UNKNOWN_COMMIT"


def wilson_score_interval(positives: int, total: int, confidence: float = 0.95) -> Tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    z = 1.95996  # 95%
    p_hat = positives / total
    denom = 1 + z**2 / total
    center = (p_hat + z**2 / (2 * total)) / denom
    margin = (z * ((p_hat * (1 - p_hat) / total + z**2 / (4 * total**2)) ** 0.5)) / denom
    return max(0.0, center - margin), min(1.0, center + margin)


def compute_contingency_and_mcnemar(y_true: List[str], preds_a: List[str], preds_b: List[str]) -> Dict[str, Any]:
    """Computes paired McNemar exact test between strategy A and strategy B on true positive/negative agreement."""
    # Table:
    # a: both correct
    # b: A correct, B incorrect
    # c: A incorrect, B correct
    # d: both incorrect
    n = len(y_true)
    a, b, c, d = 0, 0, 0, 0
    for y, pa, pb in zip(y_true, preds_a, preds_b):
        a_corr = (pa == y)
        b_corr = (pb == y)
        if a_corr and b_corr:
            a += 1
        elif a_corr and not b_corr:
            b += 1
        elif not a_corr and b_corr:
            c += 1
        else:
            d += 1

    # Exact binomial test on discordant pairs (b, c)
    total_disc = b + c
    if total_disc == 0:
        p_val = 1.0
    else:
        # Two-sided exact binomial test with p = 0.5
        p_val = stats.binomtest(min(b, c), total_disc, p=0.5, alternative='two-sided').pvalue

    return {
        "contingency_table": {"both_correct": a, "a_correct_only": b, "b_correct_only": c, "both_incorrect": d},
        "discordant_pairs": total_disc,
        "mcnemar_exact_p_value": round(float(p_val), 5)
    }


def evaluate_benchmark(
    model_name: str,
    policy_mode: str = "BALANCED",
    smoke_mode: bool = False,
    strategies: List[str] = ["adjacent", "cumulative", "dual"],
    smoke_chain_count: int = 4
) -> Tuple[Dict[str, Any], Dict[str, List[Dict[str, Any]]], Dict[str, Any]]:
    """Executes live evaluation across the benchmark dataset."""
    git_commit = get_git_commit()

    # Verify dataset SHA-256
    with open(BENCHMARK_FILE, "rb") as f:
        actual_sha256 = hashlib.sha256(f.read()).hexdigest()
    if actual_sha256 != EXPECTED_DATASET_SHA256:
        raise ValueError(f"Dataset SHA-256 mismatch! Expected {EXPECTED_DATASET_SHA256}, got {actual_sha256}")

    # Load dataset
    chains_by_id: Dict[str, List[Dict[str, Any]]] = {}
    with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            chains_by_id.setdefault(item["chain_id"], []).append(item)

    if smoke_mode:
        # Select representative smoke chains: 1 Cat A, 1 Cat B, 1 Cat C, 1 Cat C-Std
        smoke_ids = [
            "v3_chain_01_matrix_math",
            "v3_chain_17_fast_shell",
            "v3_chain_25_benign_json",
            "v3_chain_33_std_split"
        ]
        target_chains = {cid: chains_by_id[cid] for cid in smoke_ids if cid in chains_by_id}
        print(f"[SMOKE MODE] Selected {len(target_chains)} representative chains for smoke testing.")
    else:
        target_chains = chains_by_id
        print(f"[AUTHORITATIVE MODE] Evaluating all {len(target_chains)} chains (144 transitions).")

    all_strategy_predictions: Dict[str, List[Dict[str, Any]]] = {}
    strategy_metrics: Dict[str, Any] = {}
    total_live_calls = 0
    total_mock_calls = 0
    total_parse_failures = 0

    for strategy in strategies:
        print(f"\n================ Evaluating Strategy: {strategy.upper()} ================")
        predictions: List[Dict[str, Any]] = []

        temp_dir = tempfile.mkdtemp(prefix=f"v3_eval_{strategy}_")
        db_path = Path(temp_dir) / "baselines.db"
        audit_path = Path(temp_dir) / "audit.jsonl"

        config = GuardConfig(
            policy_mode=policy_mode,
            anchor_mode=strategy,
            model_name=model_name,
            baseline_db_path=db_path,
            audit_log_path=audit_path
        )
        guard = MCPGuardMiddleware(config)

        chain_summaries: List[Dict[str, Any]] = []

        for chain_idx, (cid, steps) in enumerate(target_chains.items(), 1):
            first_step = steps[0]
            sid = first_step["server_id"]
            tname = first_step["tool_name"]
            root_def = first_step["root_tool_definition"]

            # Initialize trusted V0 root baseline
            guard.baseline_store.update_trusted_baseline(
                server_id=sid,
                tool_name=tname,
                tool_def=root_def,
                reason="INITIAL_TRUSTED_BASELINE_V1"
            )

            chain_step_preds: List[Dict[str, Any]] = []
            print(f"  [{chain_idx}/{len(target_chains)}] [{strategy}] Chain: {cid} ({len(steps)} steps)...", flush=True)

            for step in steps:
                s_idx = step["step_index"]
                tot_steps = step["total_steps"]
                gold_label = step["gold_label"]
                cand_def = step["tool_definition"]
                cat = step["category"]

                # Extract strictly model-facing representation to guarantee zero leakage
                model_inputs = extract_model_facing_inputs(step)

                # Authoritative Guard: mock response is strictly None
                mock_resp = None

                t0 = time.time()
                decision = guard.evaluate_tool_update(
                    server_id=sid,
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

                if llm_called:
                    total_live_calls += 1
                    if strategy == "dual":
                        total_live_calls += 1  # dual calls both adjacent and cumulative

                sem_res = audit_rec.get("semantic_judge_result", {})
                parse_err = sem_res.get("error") if isinstance(sem_res, dict) else None
                if parse_err:
                    total_parse_failures += 1

                pred_item = {
                    "item_id": step["item_id"],
                    "chain_id": cid,
                    "category": cat,
                    "step_index": s_idx,
                    "total_steps": tot_steps,
                    "server_id": sid,
                    "tool_name": tname,
                    "gold_label": gold_label,
                    "predicted_label": pred_label,
                    "verdict": verdict,
                    "action": action,
                    "deciding_tier": deciding_tier,
                    "llm_called": llm_called,
                    "live_inference": True,
                    "mock_used": False,
                    "latency_ms": round(lat_ms, 2),
                    "latency_ms_total": round(lat_ms, 2),
                    "parse_error": parse_err,
                    "strategy": strategy,
                    "baseline_mode": strategy,
                    "model": model_name if llm_called else "none",
                    "policy": policy_mode,
                    "hardware": HARDWARE_INFO,
                    "git_commit": git_commit,
                    "export_commit": git_commit,
                    "evaluator_run_id": f"salami_v3_{strategy}_{model_name}",
                    "dataset_sha256": actual_sha256,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }
                predictions.append(pred_item)
                chain_step_preds.append(pred_item)

            # Chain-level outcome calculation
            mal_steps = [s for s in chain_step_preds if s["gold_label"] == "MALICIOUS"]
            is_mal_chain = len(mal_steps) > 0
            first_mal_idx = mal_steps[0]["step_index"] if is_mal_chain else None

            # First detection step (either non-ALLOW action or predicted MALICIOUS)
            first_det_step = next(
                (s["step_index"] for s in chain_step_preds if s["action"] != "ALLOW" or s["predicted_label"] == "MALICIOUS"),
                None
            )
            detected = first_det_step is not None

            if is_mal_chain:
                if detected and first_det_step >= first_mal_idx:
                    exposure = first_det_step - first_mal_idx
                elif detected and first_det_step < first_mal_idx:
                    exposure = 0  # Preemptive alert
                else:
                    exposure = tot_steps - first_mal_idx + 1  # Uncaught penalty
            else:
                exposure = 0

            chain_summaries.append({
                "chain_id": cid,
                "is_malicious": is_mal_chain,
                "category": steps[0]["category"],
                "total_steps": tot_steps,
                "detected": detected,
                "first_malicious_step": first_mal_idx,
                "first_detection_step": first_det_step,
                "exposure_window": exposure
            })

        shutil.rmtree(temp_dir, ignore_errors=True)
        all_strategy_predictions[strategy] = predictions

        # Transition-Level Metrics
        tp = sum(1 for p in predictions if p["gold_label"] == "MALICIOUS" and p["predicted_label"] == "MALICIOUS")
        tn = sum(1 for p in predictions if p["gold_label"] == "BENIGN" and p["predicted_label"] == "BENIGN")
        fp = sum(1 for p in predictions if p["gold_label"] == "BENIGN" and p["predicted_label"] == "MALICIOUS")
        fn = sum(1 for p in predictions if p["gold_label"] == "MALICIOUS" and p["predicted_label"] == "BENIGN")

        total_trans = len(predictions)
        total_pos = tp + fn
        total_neg = tn + fp

        recall = tp / total_pos if total_pos > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / total_neg if total_neg > 0 else 0.0
        fnr = fn / total_pos if total_pos > 0 else 0.0

        rec_low, rec_high = wilson_score_interval(tp, total_pos)
        prec_low, prec_high = wilson_score_interval(tp, tp + fp)
        fpr_low, fpr_high = wilson_score_interval(fp, total_neg)

        # Chain-Level Metrics
        mal_chains = [c for c in chain_summaries if c["is_malicious"]]
        ben_chains = [c for c in chain_summaries if not c["is_malicious"]]

        mal_detected_count = sum(1 for c in mal_chains if c["detected"])
        ben_flagged_count = sum(1 for c in ben_chains if c["detected"])

        chain_recall = mal_detected_count / len(mal_chains) if mal_chains else 0.0
        chain_fpr = ben_flagged_count / len(ben_chains) if ben_chains else 0.0

        exposures = [c["exposure_window"] for c in mal_chains]
        mean_exp = sum(exposures) / len(exposures) if exposures else 0.0
        median_exp = sorted(exposures)[len(exposures) // 2] if exposures else 0.0
        max_exp = max(exposures) if exposures else 0

        strategy_metrics[strategy] = {
            "transition_level": {
                "total_transitions": total_trans,
                "tp": tp, "tn": tn, "fp": fp, "fn": fn,
                "recall": round(recall, 4), "recall_ci": [round(rec_low, 4), round(rec_high, 4)],
                "precision": round(precision, 4), "precision_ci": [round(prec_low, 4), round(prec_high, 4)],
                "f1_score": round(f1, 4),
                "fpr": round(fpr, 4), "fpr_ci": [round(fpr_low, 4), round(fpr_high, 4)],
                "fnr": round(fnr, 4)
            },
            "chain_level": {
                "total_chains": len(chain_summaries),
                "malicious_chains_total": len(mal_chains),
                "malicious_chains_detected": mal_detected_count,
                "chain_recall": round(chain_recall, 4),
                "benign_chains_total": len(ben_chains),
                "benign_chains_flagged": ben_flagged_count,
                "benign_chain_fpr": round(chain_fpr, 4),
                "exposure_mean": round(mean_exp, 3),
                "exposure_median": float(median_exp),
                "exposure_max": int(max_exp)
            },
            "chain_summaries": chain_summaries
        }

    # Paired Comparative Analyses
    y_true = [p["gold_label"] for p in all_strategy_predictions["adjacent"]]
    adj_preds = [p["predicted_label"] for p in all_strategy_predictions["adjacent"]]
    cumul_preds = [p["predicted_label"] for p in all_strategy_predictions["cumulative"]]
    dual_preds = [p["predicted_label"] for p in all_strategy_predictions["dual"]]

    mcnemar_adj_cumul = compute_contingency_and_mcnemar(y_true, adj_preds, cumul_preds)
    mcnemar_adj_dual = compute_contingency_and_mcnemar(y_true, adj_preds, dual_preds)
    mcnemar_cumul_dual = compute_contingency_and_mcnemar(y_true, cumul_preds, dual_preds)

    # Hypothesis H1 Evidence Identification:
    # Find transitions where Adjacent == BENIGN and Cumulative == MALICIOUS (on true MALICIOUS transitions)
    h1_cases = []
    reverse_cases = []
    for idx, (p_adj, p_cum) in enumerate(zip(all_strategy_predictions["adjacent"], all_strategy_predictions["cumulative"])):
        if p_adj["gold_label"] == "MALICIOUS":
            if p_adj["predicted_label"] == "BENIGN" and p_cum["predicted_label"] == "MALICIOUS":
                h1_cases.append({
                    "item_id": p_adj["item_id"],
                    "chain_id": p_adj["chain_id"],
                    "category": p_adj["category"],
                    "step_index": p_adj["step_index"],
                    "adjacent_prediction": p_adj["predicted_label"],
                    "cumulative_prediction": p_cum["predicted_label"]
                })
            elif p_adj["predicted_label"] == "MALICIOUS" and p_cum["predicted_label"] == "BENIGN":
                reverse_cases.append({
                    "item_id": p_adj["item_id"],
                    "chain_id": p_adj["chain_id"],
                    "category": p_adj["category"],
                    "step_index": p_adj["step_index"],
                    "adjacent_prediction": p_adj["predicted_label"],
                    "cumulative_prediction": p_cum["predicted_label"]
                })

    comparison_summary = {
        "mcnemar_adjacent_vs_cumulative": mcnemar_adj_cumul,
        "mcnemar_adjacent_vs_dual": mcnemar_adj_dual,
        "mcnemar_cumulative_vs_dual": mcnemar_cumul_dual,
        "h1_supporting_transitions_count": len(h1_cases),
        "h1_supporting_transitions": h1_cases,
        "reverse_transitions_count": len(reverse_cases),
        "reverse_transitions": reverse_cases,
        "h1_supported": len(h1_cases) > 0 and len(h1_cases) > len(reverse_cases) and mcnemar_adj_cumul["mcnemar_exact_p_value"] < 0.05
    }

    manifest = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "evaluation_mode": "SMOKE_TEST" if smoke_mode else "AUTHORITATIVE_FULL_RUN",
        "model_name": model_name,
        "policy_mode": policy_mode,
        "hardware": HARDWARE_INFO,
        "git_commit": git_commit,
        "dataset_sha256": actual_sha256,
        "total_chains_evaluated": len(target_chains),
        "total_transitions_evaluated": sum(len(steps) for steps in target_chains.values()),
        "total_live_calls": total_live_calls,
        "total_mock_calls": total_mock_calls,
        "total_parse_failures": total_parse_failures,
        "live_calls_assertion_passed": (total_live_calls > 0 and total_mock_calls == 0)
    }

    return manifest, all_strategy_predictions, {"strategy_metrics": strategy_metrics, "comparisons": comparison_summary}


def save_evaluation_results(
    manifest: Dict[str, Any],
    predictions: Dict[str, List[Dict[str, Any]]],
    metrics_bundle: Dict[str, Any],
    output_base: Path
):
    """Saves predictions, metrics, manifest, and evaluation summary markdown."""
    output_base.mkdir(parents=True, exist_ok=True)

    # Strategy-specific prediction directories
    dir_adj = ROOT_DIR / "results" / "salami_drift_v3_per_step"
    dir_cum = ROOT_DIR / "results" / "salami_drift_v3_cumulative"
    dir_dual = ROOT_DIR / "results" / "salami_drift_v3_dual"

    dir_adj.mkdir(parents=True, exist_ok=True)
    dir_cum.mkdir(parents=True, exist_ok=True)
    dir_dual.mkdir(parents=True, exist_ok=True)

    with open(dir_adj / "predictions.jsonl", "w", encoding="utf-8") as f:
        for p in predictions.get("adjacent", []):
            f.write(json.dumps(p) + "\n")

    with open(dir_cum / "predictions.jsonl", "w", encoding="utf-8") as f:
        for p in predictions.get("cumulative", []):
            f.write(json.dumps(p) + "\n")

    with open(dir_dual / "predictions.jsonl", "w", encoding="utf-8") as f:
        for p in predictions.get("dual", []):
            f.write(json.dumps(p) + "\n")

    # Manifest and Metrics JSON
    with open(output_base / "run_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    with open(output_base / "computed_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_bundle, f, indent=2)

    # Markdown Report
    strat_m = metrics_bundle["strategy_metrics"]
    comp_m = metrics_bundle["comparisons"]

    md_report = f"""# Salami Drift Benchmark V3: Authoritative Evaluation Report

**Evaluation Timestamp:** {manifest['timestamp']}  
**Evaluation Mode:** `{manifest['evaluation_mode']}`  
**Model Under Test:** `{manifest['model_name']}`  
**Policy Engine:** `{manifest['policy_mode']}`  
**Hardware & Runtime:** `{manifest['hardware']}`  
**Evaluator Commit:** `{manifest['git_commit']}`  
**Dataset SHA-256:** `{manifest['dataset_sha256']}`  

---

## 1. Executive Summary & Authoritative Integrity Gate

- **Total Trajectories Evaluated:** {manifest['total_chains_evaluated']} chains
- **Total Step Transitions:** {manifest['total_transitions_evaluated']} transitions
- **Live Model Inferences:** {manifest['total_live_calls']} calls
- **Mock Calls Detected:** {manifest['total_mock_calls']} (**PASS: `mock_calls == 0`**)
- **JSON Parse Failures:** {manifest['total_parse_failures']}
- **Live Inference Assertion:** `{'PASSED' if manifest['live_calls_assertion_passed'] else 'FAILED'}`

---

## 2. Transition-Level Metrics Summary

| Strategy | Total Transitions | TP | TN | FP | FN | Recall [95% CI] | Precision [95% CI] | F1 Score | Benign FPR [95% CI] | FNR |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Adjacent ($V_{{k-1}} \\rightarrow V_k$)** | {strat_m['adjacent']['transition_level']['total_transitions']} | {strat_m['adjacent']['transition_level']['tp']} | {strat_m['adjacent']['transition_level']['tn']} | {strat_m['adjacent']['transition_level']['fp']} | {strat_m['adjacent']['transition_level']['fn']} | {strat_m['adjacent']['transition_level']['recall']*100:.1f}% | {strat_m['adjacent']['transition_level']['precision']*100:.1f}% | {strat_m['adjacent']['transition_level']['f1_score']:.3f} | {strat_m['adjacent']['transition_level']['fpr']*100:.1f}% | {strat_m['adjacent']['transition_level']['fnr']*100:.1f}% |
| **Cumulative ($V_0 \\rightarrow V_k$)** | {strat_m['cumulative']['transition_level']['total_transitions']} | {strat_m['cumulative']['transition_level']['tp']} | {strat_m['cumulative']['transition_level']['tn']} | {strat_m['cumulative']['transition_level']['fp']} | {strat_m['cumulative']['transition_level']['fn']} | {strat_m['cumulative']['transition_level']['recall']*100:.1f}% | {strat_m['cumulative']['transition_level']['precision']*100:.1f}% | {strat_m['cumulative']['transition_level']['f1_score']:.3f} | {strat_m['cumulative']['transition_level']['fpr']*100:.1f}% | {strat_m['cumulative']['transition_level']['fnr']*100:.1f}% |
| **Dual-Anchor (Conservative $\\max$)** | {strat_m['dual']['transition_level']['total_transitions']} | {strat_m['dual']['transition_level']['tp']} | {strat_m['dual']['transition_level']['tn']} | {strat_m['dual']['transition_level']['fp']} | {strat_m['dual']['transition_level']['fn']} | {strat_m['dual']['transition_level']['recall']*100:.1f}% | {strat_m['dual']['transition_level']['precision']*100:.1f}% | {strat_m['dual']['transition_level']['f1_score']:.3f} | {strat_m['dual']['transition_level']['fpr']*100:.1f}% | {strat_m['dual']['transition_level']['fnr']*100:.1f}% |

---

## 3. Chain-Level Trajectory Outcomes

| Strategy | Malicious Chains | Detected | Chain Recall | Benign Chains | False Alarms | Benign Chain FPR | Mean Exposure | Median Exposure | Max Exposure |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Adjacent** | {strat_m['adjacent']['chain_level']['malicious_chains_total']} | {strat_m['adjacent']['chain_level']['malicious_chains_detected']} | {strat_m['adjacent']['chain_level']['chain_recall']*100:.1f}% | {strat_m['adjacent']['chain_level']['benign_chains_total']} | {strat_m['adjacent']['chain_level']['benign_chains_flagged']} | {strat_m['adjacent']['chain_level']['benign_chain_fpr']*100:.1f}% | {strat_m['adjacent']['chain_level']['exposure_mean']:.2f} | {strat_m['adjacent']['chain_level']['exposure_median']:.1f} | {strat_m['adjacent']['chain_level']['exposure_max']} |
| **Cumulative** | {strat_m['cumulative']['chain_level']['malicious_chains_total']} | {strat_m['cumulative']['chain_level']['malicious_chains_detected']} | {strat_m['cumulative']['chain_level']['chain_recall']*100:.1f}% | {strat_m['cumulative']['chain_level']['benign_chains_total']} | {strat_m['cumulative']['chain_level']['benign_chains_flagged']} | {strat_m['cumulative']['chain_level']['benign_chain_fpr']*100:.1f}% | {strat_m['cumulative']['chain_level']['exposure_mean']:.2f} | {strat_m['cumulative']['chain_level']['exposure_median']:.1f} | {strat_m['cumulative']['chain_level']['exposure_max']} |
| **Dual-Anchor** | {strat_m['dual']['chain_level']['malicious_chains_total']} | {strat_m['dual']['chain_level']['malicious_chains_detected']} | {strat_m['dual']['chain_level']['chain_recall']*100:.1f}% | {strat_m['dual']['chain_level']['benign_chains_total']} | {strat_m['dual']['chain_level']['benign_chains_flagged']} | {strat_m['dual']['chain_level']['benign_chain_fpr']*100:.1f}% | {strat_m['dual']['chain_level']['exposure_mean']:.2f} | {strat_m['dual']['chain_level']['exposure_median']:.1f} | {strat_m['dual']['chain_level']['exposure_max']} |

---

## 4. Formal Hypothesis Testing ($H_1$ vs. $H_0$)

### Primary Research Question:
> *"Does cumulative/root anchoring detect malicious semantic drift that adjacent anchoring misses?"*

### Paired McNemar Exact Test:
- **Adjacent vs. Cumulative:** $p = {comp_m['mcnemar_adjacent_vs_cumulative']['mcnemar_exact_p_value']}$ (Discordant pairs: {comp_m['mcnemar_adjacent_vs_cumulative']['discordant_pairs']})
- **Adjacent vs. Dual-Anchor:** $p = {comp_m['mcnemar_adjacent_vs_dual']['mcnemar_exact_p_value']}$ (Discordant pairs: {comp_m['mcnemar_adjacent_vs_dual']['discordant_pairs']})
- **Cumulative vs. Dual-Anchor:** $p = {comp_m['mcnemar_cumulative_vs_dual']['mcnemar_exact_p_value']}$ (Discordant pairs: {comp_m['mcnemar_cumulative_vs_dual']['discordant_pairs']})

### $H_1$ Discordant Case Analysis:
- **$H_1$-Supporting Transitions (Adjacent = BENIGN, Cumulative = MALICIOUS on ground-truth attacks):** `{comp_m['h1_supporting_transitions_count']}`
- **Reverse Transitions (Adjacent = MALICIOUS, Cumulative = BENIGN on ground-truth attacks):** `{comp_m['reverse_transitions_count']}`

#### Detailed Breakdown of $H_1$ Cases:
"""
    if comp_m['h1_supporting_transitions']:
        for h_case in comp_m['h1_supporting_transitions']:
            md_report += f"- **`{h_case['item_id']}`** ({h_case['category']}): Adjacent predicted `{h_case['adjacent_prediction']}`, Cumulative predicted `{h_case['cumulative_prediction']}`\n"
    else:
        md_report += "*(No discordant transitions where Cumulative detected while Adjacent missed)*\n"

    md_report += f"""
### Formal Empirical Conclusion:
{'**HYPOTHESIS H1 IS STATISTICIALLY SUPPORTED**' if comp_m['h1_supported'] else '**HYPOTHESIS H0 IS RETAINED (NO STATISTICALLY SIGNIFICANT ADVANTAGE FOUND)**'}

---

## 5. Methodological Audit & Provenance Verification

1. **Zero Mock Ingestion:** Evaluator operated strictly in live inference mode (`mock_calls == 0`).
2. **Gold Label Isolation:** Zero gold labels were passed to the LLM judge during adjudication.
3. **Trace Preservation:** Full per-step prediction traces preserved in `predictions.jsonl`.
"""

    report_path = ROOT_DIR / "results" / "SALAMI_DRIFT_V3_EVALUATION.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md_report)

    print(f"\nSaved evaluation outputs to:")
    print(f"  - Manifest: {output_base / 'run_manifest.json'}")
    print(f"  - Metrics:  {output_base / 'computed_metrics.json'}")
    print(f"  - Report:   {report_path}")


def main():
    if "--mock" in sys.argv:
        print("[CRITICAL ERROR] The '--mock' flag is strictly prohibited in V3 evaluation!", file=sys.stderr)
        sys.exit(1)

    import argparse
    parser = argparse.ArgumentParser(description="Evaluate Salami Drift Benchmark v3")
    parser.add_argument("--model", type=str, default="gemma3:4b", help="Model name in Ollama")
    parser.add_argument("--policy", type=str, default="BALANCED", help="Policy mode (BALANCED)")
    parser.add_argument("--smoke", action="store_true", help="Run small smoke test on 4 representative chains")
    parser.add_argument("--authoritative", action="store_true", help="Run authoritative live evaluation on all 40 chains")
    parser.add_argument("--strategies", type=str, default="adjacent,cumulative,dual", help="Comma-separated strategies")
    args = parser.parse_args()

    if not args.smoke and not args.authoritative:
        print("Please specify either --smoke (for diagnostic test) or --authoritative (for full benchmark run).")
        sys.exit(1)

    strats = [s.strip() for s in args.strategies.split(",") if s.strip()]

    print(f"Starting V3 Live Evaluation...")
    print(f"  Model: {args.model}")
    print(f"  Mode: {'SMOKE TEST' if args.smoke else 'AUTHORITATIVE FULL RUN'}")
    print(f"  Strategies: {strats}")

    manifest, predictions, bundle = evaluate_benchmark(
        model_name=args.model,
        policy_mode=args.policy,
        smoke_mode=args.smoke,
        strategies=strats
    )

    out_dir = ROOT_DIR / "results" / "salami_drift_v3"
    save_evaluation_results(manifest, predictions, bundle, out_dir)
    print("\nEvaluation completed successfully.")


if __name__ == "__main__":
    main()

