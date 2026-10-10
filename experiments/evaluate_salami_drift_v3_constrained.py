"""
experiments/evaluate_salami_drift_v3_constrained.py - Constrained-JSON Rerun of Salami Drift Benchmark V3

Evaluates Adjacent and Cumulative anchor strategies using Ollama format schema + <= 2 retries on formatting failure.
Preserves identical prompts, chains, judge model (gemma3:4b), temperature (T=0), and seed (42) as V3.
Saves traces and metrics to: results/salami_drift_v3_constrained/ (leaving results/salami_drift_v3 untouched).
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
import urllib.request
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
import scipy.stats as stats

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from guard.config import GuardConfig
from guard.static_rules import evaluate_static_rules
from guard.schema_security_rules import inspect_schema_security_diff
from guard.policy_engine import PolicyEngine
from guard.baseline_store import BaselineStore, normalize_tool_def, compute_sha256
from guard.audit_logger import AuditLogger
from guard.semantic_judge import (
    SYSTEM_PROMPT_SECURITY_WRAPPER,
    build_mode_b_prompt,
    OLLAMA_API_URL,
    TEMPERATURE
)

BENCHMARK_FILE = ROOT_DIR / "data" / "salami_drift_benchmark_v3.jsonl"
EXPECTED_DATASET_SHA256 = "04d864faa59c1c088205bb8fa38c99fc5fa3f0428070c331fe546ef0884b599f"
OUT_DIR = ROOT_DIR / "results" / "salami_drift_v3_constrained"

JUDGE_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "label": {
            "type": "string",
            "enum": ["BENIGN", "SUSPICIOUS", "MALICIOUS"]
        },
        "confidence": {
            "type": "number"
        },
        "reason": {
            "type": "string"
        },
        "evidence": {
            "type": "array",
            "items": {"type": "string"}
        }
    },
    "required": ["label", "confidence", "reason", "evidence"]
}


def get_git_commit() -> str:
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(ROOT_DIR), capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception:
        return "UNKNOWN_COMMIT"


def wilson_score_interval(positives: int, total: int, confidence: float = 0.95) -> Tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    z = 1.95996
    p_hat = positives / total
    denom = 1 + z**2 / total
    center = (p_hat + z**2 / (2 * total)) / denom
    margin = (z * ((p_hat * (1 - p_hat) / total + z**2 / (4 * total**2)) ** 0.5)) / denom
    return max(0.0, center - margin), min(1.0, center + margin)


def compute_contingency_and_mcnemar(y_true: List[str], preds_a: List[str], preds_b: List[str]) -> Dict[str, Any]:
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

    total_disc = b + c
    if total_disc == 0:
        p_val = 1.0
    else:
        p_val = stats.binomtest(min(b, c), total_disc, p=0.5, alternative='two-sided').pvalue

    return {
        "contingency_table": {"both_correct": a, "a_correct_only": b, "b_correct_only": c, "both_incorrect": d},
        "discordant_pairs": total_disc,
        "mcnemar_exact_p_value": round(float(p_val), 5)
    }


def compute_structured_diff(old_def: Optional[Dict[str, Any]], new_def: Dict[str, Any]) -> Dict[str, Any]:
    if not old_def:
        return {
            "is_new_tool": True,
            "params_added": list(new_def.get("inputSchema", {}).get("properties", {}).keys()),
            "params_removed": [],
            "params_modified": [],
            "description_diff_summary": f"Initial discovery: '{new_def.get('name')}'"
        }

    old_schema = old_def.get("inputSchema", {}).get("properties", {})
    new_schema = new_def.get("inputSchema", {}).get("properties", {})

    old_keys = set(old_schema.keys())
    new_keys = set(new_schema.keys())

    added = sorted(list(new_keys - old_keys))
    removed = sorted(list(old_keys - new_keys))
    modified = []
    for k in old_keys & new_keys:
        if old_schema[k] != new_schema[k]:
            modified.append(k)

    old_desc = old_def.get("description", "")
    new_desc = new_def.get("description", "")
    desc_diff = f"Docstring modified: '{old_desc}' -> '{new_desc}'" if old_desc != new_desc else "Docstring unchanged"

    return {
        "is_new_tool": False,
        "params_added": added,
        "params_removed": removed,
        "params_modified": modified,
        "description_diff_summary": desc_diff
    }


def call_ollama_judge_constrained(
    prompt: str,
    system_prompt: str = SYSTEM_PROMPT_SECURITY_WRAPPER,
    model_name: str = "gemma3:4b",
    max_retries: int = 2
) -> Tuple[Optional[Dict[str, Any]], str, Optional[str], float, int, List[str]]:
    retry_log = []
    total_lat_ms = 0.0
    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        "format": JUDGE_JSON_SCHEMA,
        "options": {
            "temperature": TEMPERATURE,
            "seed": 42,
            "num_predict": 256
        },
        "stream": False
    }

    data_bytes = json.dumps(payload).encode("utf-8")

    for attempt in range(1 + max_retries):
        t0 = time.perf_counter()
        try:
            req = urllib.request.Request(
                OLLAMA_API_URL,
                data=data_bytes,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
            lat_ms = (time.perf_counter() - t0) * 1000.0
            total_lat_ms += lat_ms

            raw_text = resp_data.get("message", {}).get("content", "").strip()
            
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict) and "label" in parsed and parsed["label"] in ("BENIGN", "SUSPICIOUS", "MALICIOUS"):
                return parsed, raw_text, None, total_lat_ms, attempt + 1, retry_log
            else:
                err_msg = f"Malformed schema output: {raw_text[:100]}"
                retry_log.append(f"Attempt {attempt+1}: {err_msg}")
        except Exception as e:
            lat_ms = (time.perf_counter() - t0) * 1000.0
            total_lat_ms += lat_ms
            err_msg = str(e)
            retry_log.append(f"Attempt {attempt+1}: Exception {err_msg}")

        time.sleep(0.1)

    return None, raw_text if 'raw_text' in locals() else "", err_msg, total_lat_ms, attempt + 1, retry_log


def evaluate_constrained(model_name: str = "gemma3:4b", strategies: List[str] = ["adjacent", "cumulative"]):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    git_commit = get_git_commit()

    with open(BENCHMARK_FILE, "rb") as f:
        actual_sha256 = hashlib.sha256(f.read()).hexdigest()
    if actual_sha256 != EXPECTED_DATASET_SHA256:
        raise ValueError(f"Dataset SHA-256 mismatch! Expected {EXPECTED_DATASET_SHA256}, got {actual_sha256}")

    chains_by_id: Dict[str, List[Dict[str, Any]]] = {}
    with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                chains_by_id.setdefault(item["chain_id"], []).append(item)

    print(f"Starting Constrained-JSON Rerun for {strategies} on {len(chains_by_id)} chains (144 transitions each)...")

    all_strategy_preds = {}
    all_retries_log = []
    total_calls = 0
    total_retries_triggered = 0
    total_residual_parse_failures = 0
    strategy_metrics = {}

    for strategy in strategies:
        print(f"\n================ Evaluating Strategy: {strategy.upper()} (Constrained JSON) ================")
        predictions = []
        chain_summaries = []

        temp_dir = tempfile.mkdtemp(prefix=f"v3_constrained_{strategy}_")
        db_path = Path(temp_dir) / "baselines.db"
        audit_path = Path(temp_dir) / "audit.jsonl"

        config = GuardConfig(
            policy_mode="BALANCED",
            anchor_mode=strategy,
            model_name=model_name,
            baseline_db_path=db_path,
            audit_log_path=audit_path
        )
        policy_engine = PolicyEngine(mode=config.policy_mode)
        baseline_store = BaselineStore(db_path)
        audit_logger = AuditLogger(audit_path)

        for chain_idx, (cid, steps) in enumerate(chains_by_id.items(), 1):
            first_step = steps[0]
            sid = first_step["server_id"]
            tname = first_step["tool_name"]
            root_def = first_step["root_tool_definition"]

            baseline_store.update_trusted_baseline(
                server_id=sid,
                tool_name=tname,
                tool_def=root_def,
                reason="INITIAL_TRUSTED_BASELINE_V1"
            )

            chain_step_preds = []
            print(f"  [{chain_idx}/{len(chains_by_id)}] [{strategy}] Chain: {cid} ({len(steps)} steps)...", flush=True)

            for step in steps:
                s_idx = step["step_index"]
                tot_steps = step["total_steps"]
                gold_label = step["gold_label"]
                cand_def = step["tool_definition"]
                cat = step["category"]
                item_id = step["item_id"]

                if strategy == "adjacent":
                    old_tool_def, trusted_hash = baseline_store.get_trusted_definition(sid, tname)
                else:
                    old_tool_def, trusted_hash = baseline_store.get_root_definition(sid, tname)

                t_start = time.time()

                # TIER 0: Hash check
                cand_norm = normalize_tool_def(cand_def)
                new_hash = compute_sha256(cand_norm)

                if strategy == "adjacent" and old_tool_def is not None and trusted_hash == new_hash:
                    action, verdict = "ALLOW", "BENIGN"
                    deciding_tier = 0
                    llm_called = False
                    parse_err = None
                    attempts = 0
                    retries = []
                else:
                    # TIER 1: Diff
                    primary_diff = compute_structured_diff(old_tool_def, cand_def)

                    # TIER 1.5: Schema rules
                    old_schema = old_tool_def.get("inputSchema") if isinstance(old_tool_def, dict) else None
                    new_schema = cand_def.get("inputSchema") if isinstance(cand_def, dict) else None
                    findings = inspect_schema_security_diff(old_schema, new_schema)
                    schema_flagged = any(f.get("severity") in ("CRITICAL", "HIGH") for f in findings)

                    if schema_flagged:
                        action, verdict = "BLOCK", "MALICIOUS"
                        deciding_tier = 1.5
                        llm_called = False
                        parse_err = None
                        attempts = 0
                        retries = []
                    else:
                        # TIER 2: Static regex
                        static_res = evaluate_static_rules(cand_def, primary_diff.get("description_diff_summary", ""))
                        if static_res.get("flagged") and static_res.get("severity") == "high":
                            action, verdict = "BLOCK", "MALICIOUS"
                            deciding_tier = 2
                            llm_called = False
                            parse_err = None
                            attempts = 0
                            retries = []
                        else:
                            # TIER 3: Constrained Semantic Judge
                            deciding_tier = 3
                            llm_called = True
                            total_calls += 1

                            mode_b_prompt = build_mode_b_prompt(primary_diff)
                            parsed_json, raw_text, err, judge_lat, attempts, retries = call_ollama_judge_constrained(
                                mode_b_prompt,
                                system_prompt=SYSTEM_PROMPT_SECURITY_WRAPPER,
                                model_name=model_name,
                                max_retries=2
                            )

                            if attempts > 1:
                                total_retries_triggered += (attempts - 1)
                                all_retries_log.append({
                                    "item_id": item_id,
                                    "strategy": strategy,
                                    "attempts": attempts,
                                    "retries": retries,
                                    "success": parsed_json is not None
                                })

                            if err or not parsed_json:
                                total_residual_parse_failures += 1
                                parse_err = err or "JSON parsing failed"
                                verdict = "SUSPICIOUS"  # BALANCED fail-safe
                                action = "WARN"
                            else:
                                parse_err = None
                                verdict = parsed_json.get("label", "BENIGN")
                                confidence = parsed_json.get("confidence", 0.95)
                                action, _ = policy_engine.evaluate_policy(verdict=verdict, confidence=confidence)

                lat_ms = (time.time() - t_start) * 1000.0
                pred_label = "MALICIOUS" if verdict in ("MALICIOUS", "SUSPICIOUS") else "BENIGN"

                if action == "ALLOW":
                    baseline_store.update_trusted_baseline(sid, tname, cand_def, reason="BENIGN_UPDATE_APPLIED")

                pred_item = {
                    "item_id": item_id,
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
                    "latency_ms": round(lat_ms, 2),
                    "parse_error": parse_err,
                    "attempts": attempts,
                    "retries": retries,
                    "strategy": strategy
                }
                predictions.append(pred_item)
                chain_step_preds.append(pred_item)

            mal_steps = [s for s in chain_step_preds if s["gold_label"] == "MALICIOUS"]
            is_mal_chain = len(mal_steps) > 0
            first_mal_idx = mal_steps[0]["step_index"] if is_mal_chain else None

            # Rule (b) detection: verdict in (MALICIOUS, SUSPICIOUS)
            first_det_step_b = next((s["step_index"] for s in chain_step_preds if s["predicted_label"] == "MALICIOUS"), None)
            detected_b = first_det_step_b is not None

            # Rule (a) detection: verdict == MALICIOUS only
            first_det_step_a = next((s["step_index"] for s in chain_step_preds if s["verdict"] == "MALICIOUS"), None)
            detected_a = first_det_step_a is not None

            chain_summaries.append({
                "chain_id": cid,
                "is_malicious": is_mal_chain,
                "category": steps[0]["category"],
                "total_steps": len(steps),
                "first_malicious_step": first_mal_idx,
                "rule_b": {
                    "detected": detected_b,
                    "first_detection_step": first_det_step_b
                },
                "rule_a": {
                    "detected": detected_a,
                    "first_detection_step": first_det_step_a
                }
            })

        shutil.rmtree(temp_dir, ignore_errors=True)
        all_strategy_preds[strategy] = predictions

        # Save predictions jsonl
        out_preds = OUT_DIR / f"predictions_{strategy}.jsonl"
        with open(out_preds, "w", encoding="utf-8") as f:
            for p in predictions:
                f.write(json.dumps(p) + "\n")
        print(f"[OK] Saved {len(predictions)} predictions to: {out_preds}")

        strategy_metrics[strategy] = {
            "chain_summaries": chain_summaries
        }

    # Save retry and run manifest
    with open(OUT_DIR / "retry_log.json", "w", encoding="utf-8") as f:
        json.dump({
            "total_calls": total_calls,
            "total_retries_triggered": total_retries_triggered,
            "total_residual_parse_failures": total_residual_parse_failures,
            "residual_parse_failure_rate": total_residual_parse_failures / total_calls if total_calls > 0 else 0.0,
            "retry_events": all_retries_log
        }, f, indent=2)

    # Save metrics summary
    with open(OUT_DIR / "metrics_summary.json", "w", encoding="utf-8") as f:
        json.dump({
            "model_name": model_name,
            "git_commit": git_commit,
            "total_calls": total_calls,
            "total_retries": total_retries_triggered,
            "total_residual_failures": total_residual_parse_failures,
            "strategies": strategy_metrics
        }, f, indent=2)

    print("\n[SUCCESS] Constrained evaluation run finished.")
    return all_strategy_preds


if __name__ == "__main__":
    evaluate_constrained()
