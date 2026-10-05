"""
Phase 3 Evaluation Suite & Policy Optimizer
Evaluates:
- Mode A: Semantic Judge (Full Description)
- Mode B: Semantic Judge (Diff Only)
- Integrated: Multi-Tier MCP Guard Middleware (BALANCED Policy)
- Baseline Hash & Static Rules

Supports per-item trace export with unified schema, real execution timings, and git commit hash.
"""

import os
import sys
import json
import time
import tempfile
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
RESULTS_DIR = ROOT_DIR / "results"

sys.path.insert(0, str(ROOT_DIR))
from guard.config import GuardConfig
from guard.middleware import MCPGuardMiddleware
from guard.static_rules import evaluate_static_rules_example, evaluate_static_rules
from guard.schema_security_rules import evaluate_schema_security_example
from guard.semantic_judge import evaluate_semantic_judge_example
from experiments.baseline_hash_pinning import evaluate_hash_pinning_example
from experiments.trace_exporter import TraceWriter


def run_evaluation(
    split_path: Path,
    mode: str = "mode_b",
    model: str = "qwen3:8b",
    export_traces: Optional[str] = None,
    limit: Optional[int] = None
) -> Dict[str, Any]:
    """Runs evaluation and optionally streams traces to JSONL."""
    examples = []
    with open(split_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))

    if limit and limit > 0:
        examples = examples[:limit]

    print(f"Running evaluation on {len(examples)} items from {split_path.name} (mode={mode}, model={model})...")

    writer = TraceWriter(Path(export_traces), str(split_path)) if export_traces else None
    existing_ids = writer.get_existing_item_ids() if writer else set()
    if existing_ids:
        print(f"Found {len(existing_ids)} completed items in trace file. Resuming...")

    # For integrated mode, set up real MCPGuardMiddleware with temporary baseline DB
    middleware = None
    if mode == "integrated":
        tmp_db = Path(tempfile.mktemp(suffix=".db"))
        tmp_log = Path(tempfile.mktemp(suffix=".jsonl"))
        cfg = GuardConfig(policy_mode="BALANCED", baseline_db_path=tmp_db, audit_log_path=tmp_log)
        middleware = MCPGuardMiddleware(cfg)

    tp, fp, tn, fn, errors = 0, 0, 0, 0, 0

    try:
        for idx, ex in enumerate(examples, 1):
            eid = ex.get("example_id", f"item_{idx}")
            server_id = ex.get("server_id", "unknown_server")
            tool_name = ex.get("tool_name", "unknown_tool")
            gold = ex.get("expected_label", "BENIGN")

            if eid in existing_ids:
                print(f"[{idx}/{len(examples)}] Skipping {eid} (already in trace file)")
                continue

            t_total_start = time.perf_counter()

            pred = "BENIGN"
            deciding_tier = "none"
            llm_called = False
            lat_llm_ms = None

            if mode == "hash":
                res = evaluate_hash_pinning_example(ex)
                pred = res["prediction"]
                deciding_tier = 0

            elif mode == "static":
                res = evaluate_static_rules_example(ex)
                pred = res["prediction"]
                deciding_tier = 2 if res["is_flagged"] else "none"

            elif mode == "mode_a":
                res = evaluate_semantic_judge_example(ex, mode="full", model_name=model)
                if res.get("prediction") == "ERROR" or res.get("parse_error"):
                    pred = "ERROR"
                else:
                    pred = "MALICIOUS" if res["is_flagged"] else "BENIGN"
                deciding_tier = 3
                llm_called = True
                lat_llm_ms = res.get("latency_ms_llm")

            elif mode == "mode_b":
                res = evaluate_semantic_judge_example(ex, mode="diff", model_name=model)
                if res.get("prediction") == "ERROR" or res.get("parse_error"):
                    pred = "ERROR"
                else:
                    pred = "MALICIOUS" if res["is_flagged"] else "BENIGN"
                deciding_tier = 3
                llm_called = True
                lat_llm_ms = res.get("latency_ms_llm")

            elif mode == "integrated":
                # Real MCPGuardMiddleware execution with baseline pre-population
                old_def = ex.get("old_definition")
                new_def = ex.get("new_definition")

                if old_def is not None:
                    middleware.baseline_store.update_trusted_baseline(
                        server_id, tool_name, old_def, reason="EVAL_PREPOPULATION"
                    )

                eval_res = middleware.evaluate_tool_update(server_id, new_def)
                action = eval_res["action"]
                verdict = eval_res["verdict"]

                audit = eval_res.get("audit_record", {})
                if not audit.get("semantic_judge_result", {}).get("skipped", True):
                    llm_called = True
                    lat_llm_ms = audit.get("timing_breakdown_ms", {}).get("tier3_judge")

                if verdict == "ERROR":
                    pred = "ERROR"
                else:
                    is_alarm = (action in ("BLOCK", "QUARANTINE") or verdict in ("MALICIOUS", "SUSPICIOUS"))
                    pred = "MALICIOUS" if is_alarm else "BENIGN"

                # Extract deciding tier
                if audit.get("hash_result", {}).get("is_identical"):
                    deciding_tier = 0
                elif audit.get("schema_security_result", {}).get("flagged"):
                    deciding_tier = 1.5
                elif audit.get("static_rules_result", {}).get("flagged") and audit.get("static_rules_result", {}).get("severity") == "high":
                    deciding_tier = 2
                elif llm_called:
                    deciding_tier = 3
                else:
                    deciding_tier = "none"

            tot_lat_ms = (time.perf_counter() - t_total_start) * 1000.0

            if pred == "ERROR":
                errors += 1
            elif gold == "MALICIOUS" and pred == "MALICIOUS":
                tp += 1
            elif gold == "BENIGN" and pred == "MALICIOUS":
                fp += 1
            elif gold == "BENIGN" and pred == "BENIGN":
                tn += 1
            elif gold == "MALICIOUS" and pred == "BENIGN":
                fn += 1

            if writer:
                writer.write_item(
                    item_id=eid,
                    server_id=server_id,
                    tool_name=tool_name,
                    gold_label=gold,
                    predicted_label=pred,
                    deciding_tier=deciding_tier,
                    llm_called=llm_called,
                    latency_ms_total=tot_lat_ms,
                    latency_ms_llm=lat_llm_ms,
                    model=model if llm_called else "none"
                )

            print(f"[{idx}/{len(examples)}] ID: {eid} | Gold: {gold} | Pred: {pred} | Tier: {deciding_tier} | Latency: {tot_lat_ms:.2f}ms")

    finally:
        if writer:
            writer.close()

    total = tp + fp + tn + fn
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

    print(f"\n--- Results ({mode}, N={total}, Errors={errors}) ---")
    print(f"TP={tp}, FP={fp}, TN={tn}, FN={fn}, Errors={errors}")
    print(f"Precision={prec*100:.1f}%, Recall={rec*100:.1f}%, F1={f1*100:.1f}%")

    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "errors": errors, "precision": prec, "recall": rec, "f1": f1}


def main():
    parser = argparse.ArgumentParser(description="Evaluate MCP tool drift detection models and pipeline.")
    parser.add_argument("--mode", choices=["mode_a", "mode_b", "integrated", "static", "hash"], default="mode_b", help="Evaluation mode")
    parser.add_argument("--model", default="qwen3:8b", help="Ollama model identifier")
    parser.add_argument("--data", default="data/drift_test.jsonl", help="Input dataset path")
    parser.add_argument("--export-traces", default=None, help="Output JSONL trace destination path")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of items to evaluate (for dry runs)")
    args = parser.parse_args()

    data_path = Path(args.data)
    run_evaluation(
        split_path=data_path,
        mode=args.mode,
        model=args.model,
        export_traces=args.export_traces,
        limit=args.limit
    )


if __name__ == "__main__":
    main()
