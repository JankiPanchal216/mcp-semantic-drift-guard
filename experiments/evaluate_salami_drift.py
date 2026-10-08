"""
Salami Drift Multi-Chain Benchmark Runner.
Evaluates multi-step tool-definition attack chains across three strategies:
  A. Adjacent / Per-Step (V_{i-1} -> V_i)
  B. Cumulative (V_1 -> V_i)
  C. Dual-Anchor (Conservative combination of adjacent and cumulative)

Calculates per-chain:
  - first detection step k*
  - whether final attack was detected
  - whether attack was ever detected
  - exposure window (number of malicious versions accepted before detection)
  - number of malicious versions accepted
  - latency per step and total chain latency

Exports per-item predictions to:
  - results/salami_drift_per_step/predictions.jsonl
  - results/salami_drift_cumulative/predictions.jsonl
  - results/salami_drift_dual/predictions.jsonl
"""

import os
import sys
import json
import time
import shutil
import tempfile
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from guard.config import GuardConfig
from guard.baseline_store import BaselineStore
from guard.middleware import MCPGuardMiddleware

DATA_FILE = ROOT_DIR / "data" / "salami_drift_benchmark.jsonl"
RESULTS_DIR = ROOT_DIR / "results"
CONFIG_DIR = RESULTS_DIR / "salami_drift"
GIT_COMMIT = "381125b09dee2d05f23e170e32762a71f815305d"
HARDWARE_INFO = "Local GPU/CPU Environment"


def load_benchmark_chains() -> Dict[str, List[Dict[str, Any]]]:
    """Loads benchmark transitions grouped by chain_id in step order."""
    if not DATA_FILE.exists():
        raise FileNotFoundError(f"Benchmark file not found: {DATA_FILE}")

    chains: Dict[str, List[Dict[str, Any]]] = {}
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            cid = rec["chain_id"]
            if cid not in chains:
                chains[cid] = []
            chains[cid].append(rec)

    for cid in chains:
        chains[cid].sort(key=lambda x: x["step_index"])
    return chains


def run_strategy_evaluation(
    chains: Dict[str, List[Dict[str, Any]]],
    strategy: str,
    policy_mode: str = "BALANCED",
    model_name: str = "qwen3:8b",
    mock_mode: bool = False
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Runs evaluation for a specific anchor strategy across all benchmark chains.
    Returns (all_prediction_records, chain_summary_metrics).
    """
    predictions = []
    chain_results = []

    for chain_id, steps in chains.items():
        print(f"  [{strategy}] Evaluating chain: {chain_id} ({len(steps)} steps)...", flush=True)
        # Setup temporary isolated baseline store for this chain
        temp_dir = tempfile.mkdtemp(prefix=f"salami_{chain_id}_")
        temp_db = Path(temp_dir) / "baselines.db"
        temp_log = Path(temp_dir) / "audit.jsonl"

        config = GuardConfig(
            policy_mode=policy_mode,
            anchor_mode=strategy,
            model_name=model_name,
            baseline_db_path=temp_db,
            audit_log_path=temp_log
        )
        guard = MCPGuardMiddleware(config)

        first_step = steps[0]
        server_id = first_step["server_id"]
        tool_name = first_step["tool_name"]
        root_def = first_step["root_tool_definition"]

        # Initialize root baseline V1 into database
        guard.baseline_store.update_trusted_baseline(
            server_id, tool_name, root_def, reason="INITIAL_ROOT_V1"
        )

        chain_step_preds = []
        total_chain_latency = 0.0

        for step in steps:
            step_idx = step["step_index"]
            tot_steps = step["total_steps"]
            gold_label = step["gold_label"]
            cand_def = step["tool_definition"]

            mock_resp = None
            if mock_mode:
                # Deterministic simulation mode for fast verification
                mock_resp = {"label": gold_label, "confidence": 0.95}

            t0 = time.time()
            decision = guard.evaluate_tool_update(
                server_id=server_id,
                new_tool_def=cand_def,
                mock_judge_response=mock_resp,
                anchor_mode=strategy
            )
            lat_ms = (time.time() - t0) * 1000
            total_chain_latency += lat_ms

            action = decision.get("action", "ALLOW")
            verdict = decision.get("verdict", "BENIGN")
            pred_label = "MALICIOUS" if verdict in ("MALICIOUS", "SUSPICIOUS") else "BENIGN"

            # Determine deciding tier
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
                "step_index": step_idx,
                "total_steps": tot_steps,
                "server_id": server_id,
                "tool_name": tool_name,
                "gold_label": gold_label,
                "predicted_label": pred_label,
                "deciding_tier": deciding_tier,
                "llm_called": llm_called,
                "latency_ms_total": round(lat_ms, 3),
                "run_id": f"salami_{strategy}",
                "model": model_name if llm_called else "none",
                "hardware": HARDWARE_INFO,
                "source_file": "data/salami_drift_benchmark.jsonl",
                "git_commit": GIT_COMMIT,
                "export_commit": GIT_COMMIT,
                "action": action,
                "verdict": verdict
            }
            predictions.append(pred_item)
            chain_step_preds.append(pred_item)

        # Cleanup isolated DB
        shutil.rmtree(temp_dir, ignore_errors=True)

        # Compute Chain-Level Metrics
        malicious_steps = [s for s in chain_step_preds if s["gold_label"] == "MALICIOUS"]
        is_malicious_chain = len(malicious_steps) > 0

        first_detection_step = None
        for s in chain_step_preds:
            if s["action"] != "ALLOW" or s["predicted_label"] == "MALICIOUS":
                first_detection_step = s["step_index"]
                break

        ever_detected = (first_detection_step is not None)
        final_step_detected = (chain_step_preds[-1]["action"] != "ALLOW" or chain_step_preds[-1]["predicted_label"] == "MALICIOUS")

        if is_malicious_chain:
            first_mal_idx = malicious_steps[0]["step_index"]
            if first_detection_step is None:
                exposure_window = len(malicious_steps)
                malicious_versions_accepted = len(malicious_steps)
            elif first_detection_step <= first_mal_idx:
                exposure_window = 0
                malicious_versions_accepted = 0
            else:
                # number of malicious steps ALLOWED before first detection
                exposure_window = first_detection_step - first_mal_idx
                malicious_versions_accepted = exposure_window

            first_mal_detected = (first_detection_step == first_mal_idx)
            detected_before_final = (first_detection_step is not None and first_detection_step < chain_step_preds[-1]["step_index"])
        else:
            exposure_window = 0
            malicious_versions_accepted = 0
            first_mal_detected = False
            detected_before_final = False

        chain_results.append({
            "chain_id": chain_id,
            "attack_family": first_step["attack_family"],
            "is_malicious_chain": is_malicious_chain,
            "total_steps": len(steps),
            "first_detection_step": first_detection_step,
            "ever_detected": ever_detected,
            "final_step_detected": final_step_detected,
            "exposure_window": exposure_window,
            "malicious_versions_accepted": malicious_versions_accepted,
            "first_malicious_detected": first_mal_detected,
            "detected_before_final_payload": detected_before_final,
            "total_latency_ms": round(total_chain_latency, 2)
        })

    # Aggregate Strategy Summary
    mal_chains = [c for c in chain_results if c["is_malicious_chain"]]
    ben_chains = [c for c in chain_results if not c["is_malicious_chain"]]

    exp_windows = [c["exposure_window"] for c in mal_chains]
    import numpy as np

    mean_exp = float(np.mean(exp_windows)) if exp_windows else 0.0
    med_exp = float(np.median(exp_windows)) if exp_windows else 0.0
    max_exp = int(max(exp_windows)) if exp_windows else 0
    min_exp = int(min(exp_windows)) if exp_windows else 0

    detection_rate = sum(1 for c in mal_chains if c["ever_detected"]) / len(mal_chains) if mal_chains else 0.0
    first_step_det_rate = sum(1 for c in mal_chains if c["first_malicious_detected"]) / len(mal_chains) if mal_chains else 0.0
    before_final_rate = sum(1 for c in mal_chains if c["detected_before_final_payload"]) / len(mal_chains) if mal_chains else 0.0
    never_detected_rate = sum(1 for c in mal_chains if not c["ever_detected"]) / len(mal_chains) if mal_chains else 0.0

    false_alarm_chains = sum(1 for c in ben_chains if c["ever_detected"])
    benign_chain_fpr = false_alarm_chains / len(ben_chains) if ben_chains else 0.0

    summary = {
        "strategy": strategy,
        "total_chains": len(chain_results),
        "malicious_chains": len(mal_chains),
        "benign_chains": len(ben_chains),
        "detection_rate": detection_rate,
        "benign_chain_fpr": benign_chain_fpr,
        "mean_exposure_window": mean_exp,
        "median_exposure_window": med_exp,
        "max_exposure_window": max_exp,
        "min_exposure_window": min_exp,
        "first_malicious_step_detection_rate": first_step_det_rate,
        "detected_before_final_payload_rate": before_final_rate,
        "never_detected_rate": never_detected_rate,
        "chain_details": chain_results
    }

    return predictions, summary


def run_full_benchmark(mock_mode: bool = False, model_name: str = "qwen3:8b"):
    chains = load_benchmark_chains()
    print(f"Loaded {len(chains)} chains from {DATA_FILE}")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    strategies = {
        "adjacent": RESULTS_DIR / "salami_drift_per_step",
        "cumulative": RESULTS_DIR / "salami_drift_cumulative",
        "dual": RESULTS_DIR / "salami_drift_dual"
    }

    all_summaries = {}

    for strat_name, out_dir in strategies.items():
        out_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n--- Evaluating Salami Drift Benchmark: Strategy = {strat_name.upper()} ---")
        preds, summary = run_strategy_evaluation(
            chains=chains,
            strategy=strat_name,
            model_name=model_name,
            mock_mode=mock_mode
        )
        all_summaries[strat_name] = summary

        # Write per-item predictions.jsonl
        pred_file = out_dir / "predictions.jsonl"
        with open(pred_file, "w", encoding="utf-8") as f:
            for p in preds:
                f.write(json.dumps(p) + "\n")
        print(f"Wrote {len(preds)} per-item prediction traces to {pred_file}")
        print(f"  Detection Rate: {summary['detection_rate']*100:.1f}%, Mean Exposure: {summary['mean_exposure_window']:.2f}, Max Exposure: {summary['max_exposure_window']}")

    # Save run manifest & experiment config
    exp_config = {
        "benchmark_version": "1.0_multi_chain",
        "benchmark_file": str(DATA_FILE),
        "random_seed": 42,
        "detector_configuration": "T0_Hash -> T1_AST -> T1.5_Schema -> T2_Static -> T3_Local_Judge",
        "policy_mode": "BALANCED",
        "tested_anchor_modes": list(strategies.keys()),
        "model": model_name,
        "hardware": HARDWARE_INFO,
        "git_commit": GIT_COMMIT,
        "total_chains": len(chains),
        "total_transitions": sum(len(steps) for steps in chains.values())
    }

    with open(CONFIG_DIR / "experiment_config.json", "w", encoding="utf-8") as f:
        json.dump(exp_config, f, indent=2)

    with open(CONFIG_DIR / "run_manifest.json", "w", encoding="utf-8") as f:
        json.dump(all_summaries, f, indent=2)

    print(f"\nSaved experiment config and run manifest to {CONFIG_DIR}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate Salami Drift Benchmark")
    parser.add_argument("--mock", action="store_true", help="Run with deterministic mock responses")
    parser.add_argument("--model", type=str, default="qwen3:8b", help="Model name for Tier 3 judge")
    args = parser.parse_args()

    run_full_benchmark(mock_mode=args.mock, model_name=args.model)


if __name__ == "__main__":
    main()
