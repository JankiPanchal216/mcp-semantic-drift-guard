"""
Phase 3 Evaluation Suite & Policy Optimizer
Evaluates:
- Mode A: Semantic Judge (Full Description)
- Mode B: Semantic Judge (Diff Only)
- Integrated: Multi-Tier Guard Middleware
- Baseline Hash & Static Rules

Supports per-item trace export with real execution timings and git commit hash.
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
RESULTS_DIR = ROOT_DIR / "results"

sys.path.insert(0, str(ROOT_DIR))
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

    records = []
    tp, fp, tn, fn = 0, 0, 0, 0

    try:
        for idx, ex in enumerate(examples, 1):
            t_total_start = time.perf_counter()
            eid = ex.get("example_id", f"item_{idx}")
            server_id = ex.get("server_id", "unknown_server")
            gold = ex.get("expected_label", "BENIGN")

            pred = "BENIGN"
            deciding_tier = "Tier 0 (Hash Fast-Path)"
            llm_called = False
            lat_llm_ms = None

            if mode == "hash":
                res = evaluate_hash_pinning_example(ex)
                pred = res["prediction"]
                deciding_tier = "Tier 0 (Hash Pinning)"

            elif mode == "static":
                res = evaluate_static_rules_example(ex)
                pred = res["prediction"]
                deciding_tier = "Tier 2 (Static Rules)"

            elif mode == "mode_a":
                res = evaluate_semantic_judge_example(ex, mode="full", model_name=model)
                pred = "MALICIOUS" if res["is_flagged"] else "BENIGN"
                deciding_tier = "Tier 3 (Semantic Judge Mode A)"
                llm_called = True
                lat_llm_ms = res.get("latency_ms_llm")

            elif mode == "mode_b":
                res = evaluate_semantic_judge_example(ex, mode="diff", model_name=model)
                pred = "MALICIOUS" if res["is_flagged"] else "BENIGN"
                deciding_tier = "Tier 3 (Semantic Judge Mode B)"
                llm_called = True
                lat_llm_ms = res.get("latency_ms_llm")

            elif mode == "integrated":
                # Multi-tier pipeline execution
                static_res = evaluate_static_rules(ex.get("new_definition", {}), str(ex.get("structured_diff", "")))
                if static_res["flagged"] and static_res["severity"] == "high":
                    pred = "MALICIOUS"
                    deciding_tier = "Tier 2 (Static Rules)"
                else:
                    schema_res = evaluate_schema_security_example(ex)
                    if schema_res.get("is_flagged"):
                        pred = "MALICIOUS"
                        deciding_tier = "Tier 1.5 (Schema Rules)"
                    else:
                        res = evaluate_semantic_judge_example(ex, mode="diff", model_name=model)
                        pred = "MALICIOUS" if res["is_flagged"] else "BENIGN"
                        deciding_tier = "Tier 3 (Semantic Judge Mode B)"
                        llm_called = True
                        lat_llm_ms = res.get("latency_ms_llm")

            tot_lat_ms = (time.perf_counter() - t_total_start) * 1000.0

            if gold == "MALICIOUS" and pred == "MALICIOUS":
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
                    gold=gold,
                    predicted=pred,
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

    print(f"\n--- Results ({mode}, N={total}) ---")
    print(f"TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"Precision={prec*100:.1f}%, Recall={rec*100:.1f}%, F1={f1*100:.1f}%")

    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": prec, "recall": rec, "f1": f1}


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
