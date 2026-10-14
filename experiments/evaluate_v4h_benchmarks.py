"""
experiments/evaluate_v4h_benchmarks.py

Evaluates the History-Necessary Benchmark V4-H (24 chains, 72 transitions) across:
1. Mode A (Standalone single-step latest definition, no diff)
2. Plain Adjacent Guard (T(k-1) -> T(k) diff)
3. Plain Cumulative Guard (T(0) -> T(k) diff)
4. Combined Prompt Guard (both Adjacent and Cumulative diffs)

Supports both local open-weight judge (gemma3:4b) and cloud judge (gemini-3.1-flash-lite).
Saves individual predictions to results/history_necessary_v4h/<model>/predictions_<strategy>.jsonl
Computes full summary and Mode-A-blind subset metrics with Wilson CIs and exact McNemar tests.
"""

import os
import sys
import json
import time
import math
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import scipy.stats as stats

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Load .env
env_path = ROOT_DIR / ".env"
if env_path.exists():
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip().strip('"').strip("'")

from guard.multi_judge_client import MultiJudgeClient
from guard.semantic_judge import (
    build_mode_b_prompt,
    SYSTEM_PROMPT_SECURITY_WRAPPER,
    JUDGE_JSON_SCHEMA
)
from guard.static_rules import evaluate_static_rules
from guard.schema_security_rules import inspect_schema_security_diff
from experiments.evaluate_salami_drift_v4 import compute_structured_diff
from experiments.evaluate_combined_prompt import build_combined_prompt
from experiments.evaluate_mode_a_baseline import build_mode_a_prompt, SYSTEM_PROMPT as MODE_A_SYS

BENCHMARK_FILE = ROOT_DIR / "data" / "history_necessary_v4h.jsonl"
OUT_BASE_DIR = ROOT_DIR / "results" / "history_necessary_v4h"


def wilson_ci(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2.0 * n)) / denom
    half = (z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * n)) / n)) / denom
    return max(0.0, center - half) * 100.0, min(1.0, center + half) * 100.0


def mcnemar_exact(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p_val = 2.0 * stats.binom.cdf(k, n, 0.5)
    return min(1.0, float(p_val))


def load_v4h_chains() -> Dict[str, List[Dict[str, Any]]]:
    chains = {}
    with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                chains.setdefault(item["chain_id"], []).append(item)
    for cid in chains:
        chains[cid].sort(key=lambda x: x["step_index"])
    return chains


from datetime import datetime, timezone
try:
    import zoneinfo
    PACIFIC_TZ = zoneinfo.ZoneInfo("America/Los_Angeles")
except Exception:
    from datetime import timedelta
    PACIFIC_TZ = timezone(timedelta(hours=-7))


def get_current_pacific_quota_date():
    """Returns current date in Google API quota timezone (America/Los_Angeles)."""
    return datetime.now(timezone.utc).astimezone(PACIFIC_TZ).date()


def count_gemini_calls_current_quota_day() -> int:
    """Counts total Gemini API calls executed strictly within the current Google quota day (Pacific Time)."""
    current_pt_date = get_current_pacific_quota_date()
    total_calls = 0

    results_dir = ROOT_DIR / "results"
    if not results_dir.exists():
        return 0

    for p in results_dir.rglob("*"):
        if not p.is_file() or "gemini" not in str(p).lower():
            continue

        if p.suffix == ".jsonl":
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        d = json.loads(line)
                        ts = d.get("timestamp")
                        if ts:
                            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            if dt.astimezone(PACIFIC_TZ).date() == current_pt_date:
                                total_calls += d.get("attempts_used", 1)
                    except Exception:
                        pass
        elif p.suffix == ".json":
            try:
                content = json.loads(open(p, "r", encoding="utf-8").read())
                records = content.get("records", []) or content.get("results", [])
                for r in records:
                    ts = r.get("timestamp")
                    if ts:
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if dt.astimezone(PACIFIC_TZ).date() == current_pt_date:
                            total_calls += 1
                    elif "latency_ms" in r and "v4h" in str(p):
                        mtime_dt = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
                        if mtime_dt.astimezone(PACIFIC_TZ).date() == current_pt_date:
                            total_calls += 1
            except Exception:
                pass

    return total_calls


def check_quota_gate(model_name: str, needed_calls: int = 216, hard_cap: int = 450) -> Tuple[bool, int, int]:
    """
    Checks whether running Gemini calls would exceed the daily quota hard cap for the current Pacific quota day.
    Returns: (can_proceed, calls_used_today, remaining_quota)
    """
    if "gemini" not in model_name.lower():
        return True, 0, hard_cap

    calls_today = count_gemini_calls_current_quota_day()
    remaining = max(0, hard_cap - calls_today)
    can_proceed = bool(remaining >= needed_calls)
    return can_proceed, calls_today, remaining


def evaluate_model_on_v4h(model_name: str, pacing_sec: float = 0.0) -> Dict[str, Any]:
    chains = load_v4h_chains()
    model_dir_name = model_name.replace(":", "_").replace("/", "_")
    model_out_dir = OUT_BASE_DIR / model_dir_name
    model_out_dir.mkdir(parents=True, exist_ok=True)

    if "gemini" in model_name.lower():
        can_proceed, used, remaining = check_quota_gate(model_name, needed_calls=216, hard_cap=450)
        current_pt_date = get_current_pacific_quota_date()
        print(f"[{model_name}] Quota Gate Check (Pacific Day: {current_pt_date}): {used}/450 calls used today, {remaining} remaining (need ~216).")
        if not can_proceed:
            print(f"[{model_name}] STOP: Insufficient quota remaining ({remaining} < 216). Halting run to preserve quota.")
            return {
                "status": "STOPPED_QUOTA_GATE",
                "calls_used_today": used,
                "remaining_quota": remaining,
                "quota_day_pacific": str(current_pt_date)
            }

    client = MultiJudgeClient(model_name=model_name, temperature=0.0)
    strategies = ["mode_a", "adjacent", "cumulative", "combined"]
    all_strategy_predictions = {}

    for strat in strategies:
        pred_file = model_out_dir / f"predictions_{strat}.jsonl"
        existing = {}
        if pred_file.exists():
            with open(pred_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        rec = json.loads(line)
                        existing[rec["item_id"]] = rec

        print(f"\n[{model_name}] Starting strategy '{strat}' ({len(existing)}/72 already complete)...")
        results = list(existing.values())

        with open(pred_file, "a", encoding="utf-8") as f_out:
            for cid, steps in sorted(chains.items()):
                root_def = steps[0]["root_tool_definition"]
                for s in steps:
                    item_id = s["item_id"]
                    if item_id in existing:
                        continue

                    curr_def = s["tool_definition"]
                    prev_def = s["previous_tool_definition"]

                    # Build prompt and select system prompt
                    if strat == "mode_a":
                        prompt = build_mode_a_prompt(curr_def)
                        sys_prompt = MODE_A_SYS
                        static_hit = False
                        schema_hit = False
                    elif strat == "adjacent":
                        diff = compute_structured_diff(prev_def, curr_def)
                        prompt = build_mode_b_prompt(diff)
                        sys_prompt = SYSTEM_PROMPT_SECURITY_WRAPPER
                        s_res = evaluate_static_rules(curr_def)
                        sc_res = inspect_schema_security_diff(prev_def, curr_def)
                        static_hit = s_res.get("flagged", False) if isinstance(s_res, dict) else bool(s_res)
                        schema_hit = sc_res.get("flagged", False) if isinstance(sc_res, dict) else bool(sc_res)
                    elif strat == "cumulative":
                        diff = compute_structured_diff(root_def, curr_def)
                        prompt = build_mode_b_prompt(diff)
                        sys_prompt = SYSTEM_PROMPT_SECURITY_WRAPPER
                        s_res = evaluate_static_rules(curr_def)
                        sc_res = inspect_schema_security_diff(root_def, curr_def)
                        static_hit = s_res.get("flagged", False) if isinstance(s_res, dict) else bool(s_res)
                        schema_hit = sc_res.get("flagged", False) if isinstance(sc_res, dict) else bool(sc_res)
                    elif strat == "combined":
                        adj_diff = compute_structured_diff(prev_def, curr_def)
                        cum_diff = compute_structured_diff(root_def, curr_def)
                        prompt = build_combined_prompt(adj_diff, cum_diff)
                        sys_prompt = SYSTEM_PROMPT_SECURITY_WRAPPER
                        s_res = evaluate_static_rules(curr_def)
                        sc_res = inspect_schema_security_diff(prev_def, curr_def)
                        static_hit = s_res.get("flagged", False) if isinstance(s_res, dict) else bool(s_res)
                        schema_hit = sc_res.get("flagged", False) if isinstance(sc_res, dict) else bool(sc_res)

                    t0 = time.time()
                    call_res = client.call_judge(prompt, system_prompt=sys_prompt)
                    lat_ms = (time.time() - t0) * 1000.0

                    parsed = call_res.get("parsed_verdict") or {}
                    verdict = parsed.get("label", "PARSE_ERROR")
                    confidence = parsed.get("confidence", 0.0)
                    reason = parsed.get("reason", "")
                    evidence = parsed.get("evidence", [])

                    rule_a_alert = bool(verdict == "MALICIOUS" or static_hit or schema_hit)
                    rule_b_alert = bool(verdict in ("MALICIOUS", "SUSPICIOUS") or static_hit or schema_hit)

                    record = {
                        "item_id": item_id,
                        "chain_id": cid,
                        "step_index": s["step_index"],
                        "total_steps": s["total_steps"],
                        "category": s["category"],
                        "attack_family": s["attack_family"],
                        "tool_name": s["tool_name"],
                        "server_id": s["server_id"],
                        "gold_label": s["gold_label"],
                        "strategy": strat,
                        "model": model_name,
                        "model_verdict": verdict,
                        "confidence": confidence,
                        "reasoning": reason,
                        "evidence": evidence,
                        "rule_verdicts": {
                            "rule_a_strict": rule_a_alert,
                            "rule_b_balanced": rule_b_alert
                        },
                        "static_hit": static_hit,
                        "schema_hit": schema_hit,
                        "latency_ms": lat_ms,
                        "prompt_tokens": call_res.get("prompt_tokens"),
                        "completion_tokens": call_res.get("completion_tokens")
                    }

                    line_str = json.dumps(record, ensure_ascii=False) + "\n"
                    f_out.write(line_str)
                    f_out.flush()
                    try:
                        os.fsync(f_out.fileno())
                    except Exception:
                        pass

                    existing[item_id] = record
                    results.append(record)

                    if len(results) % 10 == 0 or len(results) == 72:
                        print(f"  [{strat}] {len(results)}/72 | item={item_id} | verdict={verdict} ({confidence:.2f}) | lat={lat_ms:.0f}ms")

                    if pacing_sec > 0:
                        time.sleep(pacing_sec)

        all_strategy_predictions[strat] = list(existing.values())

    # Validity screen: identify Mode-A-blind attack chains
    mode_a_preds_by_item = {p["item_id"]: p for p in all_strategy_predictions["mode_a"]}
    mode_a_flagged_attacks = []
    mode_a_blind_attacks = []

    attack_cids = sorted([cid for cid, steps in chains.items() if steps[-1]["gold_label"] == "MALICIOUS"])
    benign_cids = sorted([cid for cid, steps in chains.items() if steps[-1]["gold_label"] == "BENIGN"])

    for cid in attack_cids:
        final_item_id = f"{cid}_step_03"
        rec = mode_a_preds_by_item.get(final_item_id, {})
        v = rec.get("model_verdict")
        # Under Rule (b) BALANCED
        if v in ("MALICIOUS", "SUSPICIOUS"):
            mode_a_flagged_attacks.append(cid)
        else:
            mode_a_blind_attacks.append(cid)

    print(f"\n[{model_name}] Mode A Validity Screen on 12 Final Attack Definitions (Rule b):")
    print(f"  Mode-A-Flagged: {len(mode_a_flagged_attacks)}/12: {mode_a_flagged_attacks}")
    print(f"  Mode-A-Blind (Headline Subset): {len(mode_a_blind_attacks)}/12: {mode_a_blind_attacks}")

    # Compute metrics for all strategies across:
    # A) All 12 attack chains (full pilot)
    # B) Mode-A-blind subset
    def score_strategy(strat_key: str, target_attacks: List[str], rule_key: str) -> Dict[str, Any]:
        preds_chain = {}
        for p in all_strategy_predictions[strat_key]:
            preds_chain.setdefault(p["chain_id"], []).append(p)
        for cid in preds_chain:
            preds_chain[cid].sort(key=lambda x: x["step_index"])

        strict_det = 0
        any_det = 0
        exp_list = []
        chain_first_alerts = {}

        for cid in target_attacks:
            steps = preds_chain.get(cid, [])
            first_alert = None
            any_after = False
            for s in steps:
                alert = s["rule_verdicts"][rule_key]
                idx = s["step_index"]
                if alert:
                    if first_alert is None:
                        first_alert = idx
                    if idx >= 3:
                        any_after = True

            chain_first_alerts[cid] = first_alert
            if first_alert is not None and first_alert >= 3:
                strict_det += 1
            if any_after:
                any_det += 1

            if first_alert is None:
                exp = 1.0 # L - m + 1 = 3 - 3 + 1 = 1
            else:
                exp = max(0, first_alert - 3)
            exp_list.append(exp)

        # Benign FPR
        ben_alarms = 0
        ben_trans_total = 0
        ben_trans_alarms = 0

        for cid in benign_cids:
            steps = preds_chain.get(cid, [])
            chain_alert = any(s["rule_verdicts"][rule_key] for s in steps)
            if chain_alert:
                ben_alarms += 1
            for s in steps:
                ben_trans_total += 1
                if s["rule_verdicts"][rule_key]:
                    ben_trans_alarms += 1

        # Also add pre-onset steps from target attack chains
        for cid in target_attacks:
            steps = preds_chain.get(cid, [])
            for s in steps:
                if s["step_index"] < 3:
                    ben_trans_total += 1
                    if s["rule_verdicts"][rule_key]:
                        ben_trans_alarms += 1

        n_atk = len(target_attacks)
        n_ben = len(benign_cids)

        strict_ci = wilson_ci(strict_det, n_atk)
        any_ci = wilson_ci(any_det, n_atk)
        ben_ci = wilson_ci(ben_alarms, n_ben)
        trans_ci = wilson_ci(ben_trans_alarms, ben_trans_total)

        return {
            "strict_recall": {
                "detected": strict_det,
                "total": n_atk,
                "rate": round(strict_det / n_atk * 100, 1) if n_atk > 0 else 0.0,
                "ci": [round(strict_ci[0], 1), round(strict_ci[1], 1)]
            },
            "any_recall": {
                "detected": any_det,
                "total": n_atk,
                "rate": round(any_det / n_atk * 100, 1) if n_atk > 0 else 0.0,
                "ci": [round(any_ci[0], 1), round(any_ci[1], 1)]
            },
            "benign_chain_fpr": {
                "alarms": ben_alarms,
                "total": n_ben,
                "rate": round(ben_alarms / n_ben * 100, 1),
                "ci": [round(ben_ci[0], 1), round(ben_ci[1], 1)]
            },
            "benign_transition_alert_rate": {
                "alarms": ben_trans_alarms,
                "total": ben_trans_total,
                "rate": round(ben_trans_alarms / ben_trans_total * 100, 1),
                "ci": [round(trans_ci[0], 1), round(trans_ci[1], 1)]
            },
            "mean_exposure": round(float(np.mean(exp_list)), 3) if exp_list else 0.0,
            "chain_first_alerts": chain_first_alerts
        }

    summary = {
        "model": model_name,
        "n_chains_total": len(chains),
        "n_attacks": len(attack_cids),
        "n_benign": len(benign_cids),
        "mode_a_validity_screen": {
            "rule_b_flagged": mode_a_flagged_attacks,
            "rule_b_blind": mode_a_blind_attacks,
            "blind_count": len(mode_a_blind_attacks),
            "flagged_count": len(mode_a_flagged_attacks)
        },
        "full_pilot_n12": {},
        "mode_a_blind_subset": {}
    }

    for r_key, r_name in [("rule_b_balanced", "rule_b"), ("rule_a_strict", "rule_a")]:
        summary["full_pilot_n12"][r_name] = {}
        for strat in strategies:
            summary["full_pilot_n12"][r_name][strat] = score_strategy(strat, attack_cids, r_key)

        summary["mode_a_blind_subset"][r_name] = {}
        for strat in strategies:
            summary["mode_a_blind_subset"][r_name][strat] = score_strategy(strat, mode_a_blind_attacks, r_key)

    summary_file = model_out_dir / "summary.json"
    with open(summary_file, "w", encoding="utf-8") as f_sum:
        json.dump(summary, f_sum, indent=2)

    print(f"Summary written to: {summary_file}")
    return summary


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="gemma3:4b", help="Model to evaluate (gemma3:4b or gemini-3.1-flash-lite)")
    parser.add_argument("--pacing", type=float, default=0.0, help="Pacing in seconds between calls")
    args = parser.parse_args()
    evaluate_model_on_v4h(args.model, args.pacing)
