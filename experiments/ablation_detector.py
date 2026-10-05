"""
Multi-Tier Architectural Ablation Runner (Configs A through H)
Evaluates configurations A–H on the test split and streams per-item traces with unified schema.
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"

sys.path.insert(0, str(ROOT_DIR))
from guard.static_rules import evaluate_static_rules
from guard.schema_security_rules import evaluate_schema_security_example
from guard.semantic_judge import evaluate_semantic_judge_example
from experiments.baseline_hash_pinning import evaluate_hash_pinning_example
from experiments.trace_exporter import TraceWriter


def run_ablation(
    data_path: Path,
    model: str = "qwen3:8b",
    export_traces_dir: Optional[str] = None,
    limit: Optional[int] = None
):
    """Runs ablation configurations and exports traces."""
    items = []
    with open(data_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                items.append(json.loads(line))

    if limit and limit > 0:
        items = items[:limit]

    out_dir = Path(export_traces_dir) if export_traces_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    configs = [
        ("config_a", "Hash Only"),
        ("config_b", "Static Regex Only"),
        ("config_c", "Hash + Static"),
        ("config_d", "Hash + Static + Diff"),
        ("config_e", "Hash + Static + Semantic Judge"),
        ("config_f", "Full Guard Pipeline"),
        ("config_g", "Guard without Schema Check"),
        ("config_h", "Deterministic Fast Path (No LLM)")
    ]

    for cfg_id, cfg_name in configs:
        trace_file = out_dir / f"{cfg_id}_predictions.jsonl" if out_dir else None
        writer = TraceWriter(trace_file, str(data_path)) if trace_file else None
        existing_ids = writer.get_existing_item_ids() if writer else set()

        print(f"\n--- Running {cfg_name} ({cfg_id}, N={len(items)}) ---")
        if existing_ids:
            print(f"Found {len(existing_ids)} completed items in {cfg_id} trace. Resuming...")

        try:
            for idx, ex in enumerate(items, 1):
                eid = ex.get("example_id", f"ablation_{idx}")
                server_id = ex.get("server_id", "unknown_server")
                tool_name = ex.get("tool_name", "unknown_tool")
                gold = ex.get("expected_label", "BENIGN")

                if eid in existing_ids:
                    print(f"[{cfg_id} - {idx}/{len(items)}] Skipping {eid} (already in trace file)")
                    continue

                t_start = time.perf_counter()

                pred = "BENIGN"
                deciding_tier = "none"
                llm_called = False
                lat_llm = None

                if cfg_id == "config_a":
                    res = evaluate_hash_pinning_example(ex)
                    pred = res["prediction"]
                    deciding_tier = 0

                elif cfg_id == "config_b":
                    res = evaluate_static_rules(ex.get("new_definition", {}), str(ex.get("structured_diff", "")))
                    pred = "MALICIOUS" if res["flagged"] else "BENIGN"
                    deciding_tier = 2 if res["flagged"] else "none"

                elif cfg_id == "config_c":
                    # Hash check first; if diff exists, check static rules
                    h_res = evaluate_hash_pinning_example(ex)
                    if h_res["prediction"] == "BENIGN":
                        pred = "BENIGN"
                        deciding_tier = 0
                    else:
                        s_res = evaluate_static_rules(ex.get("new_definition", {}), str(ex.get("structured_diff", "")))
                        if s_res["flagged"] and s_res["severity"] == "high":
                            pred = "MALICIOUS"
                            deciding_tier = 2
                        else:
                            pred = "BENIGN"
                            deciding_tier = "none"

                elif cfg_id == "config_d":
                    # Hash + Static + Diff
                    h_res = evaluate_hash_pinning_example(ex)
                    if h_res["prediction"] == "BENIGN":
                        pred = "BENIGN"
                        deciding_tier = 0
                    else:
                        s_res = evaluate_static_rules(ex.get("new_definition", {}), str(ex.get("structured_diff", "")))
                        if s_res["flagged"] and s_res["severity"] == "high":
                            pred = "MALICIOUS"
                            deciding_tier = 2
                        else:
                            pred = "BENIGN"
                            deciding_tier = 1

                elif cfg_id in ("config_e", "config_g"):
                    # Hash + Static + Semantic Judge (No schema rule)
                    s_res = evaluate_static_rules(ex.get("new_definition", {}), str(ex.get("structured_diff", "")))
                    if s_res["flagged"] and s_res["severity"] == "high":
                        pred = "MALICIOUS"
                        deciding_tier = 2
                    else:
                        res = evaluate_semantic_judge_example(ex, mode="diff", model_name=model)
                        if res.get("prediction") == "ERROR" or res.get("parse_error"):
                            pred = "ERROR"
                        else:
                            pred = "MALICIOUS" if res["is_flagged"] else "BENIGN"
                        deciding_tier = 3
                        llm_called = True
                        lat_llm = res.get("latency_ms_llm")

                elif cfg_id == "config_f":
                    # Full Guard Pipeline (Schema + Static + Semantic Judge)
                    schema_res = evaluate_schema_security_example(ex)
                    if schema_res.get("is_flagged"):
                        pred = "MALICIOUS"
                        deciding_tier = 1.5
                    else:
                        s_res = evaluate_static_rules(ex.get("new_definition", {}), str(ex.get("structured_diff", "")))
                        if s_res["flagged"] and s_res["severity"] == "high":
                            pred = "MALICIOUS"
                            deciding_tier = 2
                        else:
                            res = evaluate_semantic_judge_example(ex, mode="diff", model_name=model)
                            if res.get("prediction") == "ERROR" or res.get("parse_error"):
                                pred = "ERROR"
                            else:
                                pred = "MALICIOUS" if res["is_flagged"] else "BENIGN"
                            deciding_tier = 3
                            llm_called = True
                            lat_llm = res.get("latency_ms_llm")

                elif cfg_id == "config_h":
                    # Deterministic Fast Path (No LLM: Hash + Schema + Static)
                    schema_res = evaluate_schema_security_example(ex)
                    if schema_res.get("is_flagged"):
                        pred = "MALICIOUS"
                        deciding_tier = 1.5
                    else:
                        s_res = evaluate_static_rules(ex.get("new_definition", {}), str(ex.get("structured_diff", "")))
                        if s_res["flagged"] and s_res["severity"] == "high":
                            pred = "MALICIOUS"
                            deciding_tier = 2
                        else:
                            pred = "BENIGN"
                            deciding_tier = "none"

                tot_lat = (time.perf_counter() - t_start) * 1000.0

                if writer:
                    writer.write_item(
                        item_id=eid,
                        server_id=server_id,
                        tool_name=tool_name,
                        gold_label=gold,
                        predicted_label=pred,
                        deciding_tier=deciding_tier,
                        llm_called=llm_called,
                        latency_ms_total=tot_lat,
                        latency_ms_llm=lat_llm,
                        model=model if llm_called else "none"
                    )

                print(f"[{cfg_id} - {idx}/{len(items)}] ID: {eid} | Pred: {pred} | Tier: {deciding_tier} | Latency: {tot_lat:.2f}ms")

        finally:
            if writer:
                writer.close()


def main():
    parser = argparse.ArgumentParser(description="Ablation Detector Runner (Configs A-H).")
    parser.add_argument("--model", default="qwen3:8b", help="Ollama model identifier")
    parser.add_argument("--data", default="data/drift_test.jsonl", help="Input dataset path")
    parser.add_argument("--export-traces-dir", default=None, help="Directory to export per-config predictions.jsonl traces")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of items to evaluate")
    args = parser.parse_args()

    data_path = Path(args.data)
    run_ablation(
        data_path=data_path,
        model=args.model,
        export_traces_dir=args.export_traces_dir,
        limit=args.limit
    )


if __name__ == "__main__":
    main()
