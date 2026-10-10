"""
experiments/pilot_api_judge.py

Runs a 50-call pilot evaluation on the V4 Calibration split to:
1. Validate JSON schema parse compliance (target >= 99%).
2. Track prompt tokens, completion tokens, and latency per call.
3. Calculate accurate token averages and cost projections for the full test split (218 transitions) and full benchmark (436 transitions per strategy).
4. Strictly logs model ID, timestamp, temperature, prompt, and raw output without storing or printing API keys.
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from guard.multi_judge_client import MultiJudgeClient
from guard.semantic_judge import build_mode_b_prompt
from experiments.evaluate_salami_drift_v4 import compute_structured_diff

BENCHMARK_FILE = ROOT_DIR / "data" / "salami_drift_benchmark_v4.jsonl"
PILOT_OUTPUT_DIR = ROOT_DIR / "results" / "judge_pilots"

# Standard Pricing per 1M tokens (USD)
PRICING_TABLE = {
    # OpenAI
    "gpt-4o-mini": {"input_per_m": 0.15, "output_per_m": 0.60},
    "gpt-4o": {"input_per_m": 2.50, "output_per_m": 10.00},
    # Anthropic
    "claude-3-5-haiku-20241022": {"input_per_m": 0.80, "output_per_m": 4.00},
    "claude-3-5-sonnet-20241022": {"input_per_m": 3.00, "output_per_m": 15.00},
    # Google
    "gemini-2.5-flash": {"input_per_m": 0.075, "output_per_m": 0.30},
    "gemini-1.5-pro": {"input_per_m": 1.25, "output_per_m": 5.00},
    # Local Ollama
    "gemma3:4b": {"input_per_m": 0.0, "output_per_m": 0.0},
    "qwen3:8b": {"input_per_m": 0.0, "output_per_m": 0.0},
    "qwen2.5:1.5b": {"input_per_m": 0.0, "output_per_m": 0.0}
}


def run_pilot(model_name: str, n_calls: int = 50, strategy: str = "adjacent") -> Dict[str, Any]:
    PILOT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model_slug = model_name.replace(":", "_").replace("/", "_")
    pilot_file = PILOT_OUTPUT_DIR / f"pilot_{model_slug}_{strategy}_{n_calls}calls.jsonl"

    client = MultiJudgeClient(model_name=model_name, temperature=0.0)

    # Load calibration split items
    calibration_items = []
    with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                if item["metrics_evaluator_metadata"]["split"] == "calibration":
                    calibration_items.append(item)

    if len(calibration_items) < n_calls:
        raise ValueError(f"Not enough calibration items (found {len(calibration_items)}, requested {n_calls})")

    selected_items = calibration_items[:n_calls]

    print(f"Starting {n_calls}-call pilot for model: '{model_name}' (Provider: {client.provider}) on Calibration split...")
    print(f"Strategy: {strategy}")

    records = []
    total_prompt_tokens = 0
    total_completion_tokens = 0
    parse_failures = 0
    retries_used = 0
    latencies = []

    with open(pilot_file, "w", encoding="utf-8") as f_out:
        for idx, item in enumerate(selected_items, 1):
            curr_def = item["tool_definition"]
            if strategy == "adjacent":
                anchor_def = item["previous_tool_definition"]
            else:
                anchor_def = item["root_tool_definition"]

            diff_struct = compute_structured_diff(anchor_def, curr_def)
            prompt = build_mode_b_prompt(diff_struct)

            call_res = client.call_judge(prompt)

            record = {
                "pilot_call_index": idx,
                "item_id": item["item_id"],
                "chain_id": item["chain_id"],
                "category": item["category"],
                "gold_label": item["gold_label"],
                "strategy": strategy,
                "model": model_name,
                "provider": client.provider,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "parsed_verdict": call_res["parsed_verdict"],
                "raw_response": call_res["raw_response"],
                "parse_error": call_res["parse_error"],
                "attempts_used": call_res["attempts_used"],
                "latency_ms": call_res["latency_ms"],
                "prompt_tokens": call_res["prompt_tokens"],
                "completion_tokens": call_res["completion_tokens"],
                "retry_log": call_res["retry_log"]
            }

            f_out.write(json.dumps(record, ensure_ascii=False) + "\n")
            f_out.flush()

            records.append(record)
            total_prompt_tokens += call_res["prompt_tokens"]
            total_completion_tokens += call_res["completion_tokens"]
            latencies.append(call_res["latency_ms"])
            if call_res["parse_error"] is not None:
                parse_failures += 1
            if call_res["attempts_used"] > 1:
                retries_used += 1

            if idx % 10 == 0 or idx == n_calls:
                print(f"  [{idx}/{n_calls}] Latency: {call_res['latency_ms']:.1f}ms | Verdict: {call_res['parsed_verdict']['label'] if call_res['parsed_verdict'] else 'FAIL'}")

    avg_p_tok = total_prompt_tokens / n_calls
    avg_c_tok = total_completion_tokens / n_calls
    avg_lat_ms = sum(latencies) / n_calls

    # Pricing calculations
    pricing = PRICING_TABLE.get(model_name, {"input_per_m": 0.50, "output_per_m": 2.00})
    cost_per_call = (avg_p_tok * pricing["input_per_m"] / 1e6) + (avg_c_tok * pricing["output_per_m"] / 1e6)
    
    # Frozen test set: 218 transitions per strategy
    cost_test_set_one_strat = cost_per_call * 218
    cost_test_set_both_strats = cost_per_call * 436
    cost_full_benchmark_both_strats = cost_per_call * 872

    summary = {
        "model_name": model_name,
        "provider": client.provider,
        "pilot_calls": n_calls,
        "strategy": strategy,
        "parse_failures": parse_failures,
        "parse_failure_rate": round(parse_failures / n_calls, 4),
        "parse_success_rate": round(1.0 - (parse_failures / n_calls), 4),
        "calls_requiring_retry": retries_used,
        "avg_prompt_tokens": round(avg_p_tok, 1),
        "avg_completion_tokens": round(avg_c_tok, 1),
        "avg_total_tokens": round(avg_p_tok + avg_c_tok, 1),
        "avg_latency_ms": round(avg_lat_ms, 2),
        "pricing_per_1m": pricing,
        "estimated_cost_per_call_usd": round(cost_per_call, 6),
        "estimated_cost_frozen_test_set_single_strategy_usd": round(cost_test_set_one_strat, 4),
        "estimated_cost_frozen_test_set_both_strategies_usd": round(cost_test_set_both_strats, 4),
        "estimated_cost_full_benchmark_both_strategies_usd": round(cost_full_benchmark_both_strats, 4),
        "pilot_records_file": str(pilot_file)
    }

    summary_file = PILOT_OUTPUT_DIR / f"summary_{model_slug}_{strategy}_{n_calls}calls.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\nPilot Complete for {model_name}!")
    print(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=str, default="qwen3:8b", help="Model identifier")
    parser.add_argument("--calls", type=int, default=50, help="Number of pilot calls")
    parser.add_argument("--strategy", type=str, default="adjacent", choices=["adjacent", "cumulative"])
    args = parser.parse_args()

    run_pilot(model_name=args.model, n_calls=args.calls, strategy=args.strategy)
