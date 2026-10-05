"""
Multi-Tier Architectural Ablation Runner (Configs A through H)
Evaluates configurations A–H on the test split and streams per-item traces.
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
        ("config_h", "Deterministic Fast Path (No LLM)"),
        ("config_e", "Hash + Static + Semantic Judge"),
        ("config_f", "Full Guard Pipeline")
    ]

    for cfg_id, cfg_name in configs:
        trace_file = out_dir / f"{cfg_id}_predictions.jsonl" if out_dir else None
        writer = TraceWriter(trace_file, str(data_path)) if trace_file else None

        print(f"\n--- Running {cfg_name} ({cfg_id}, N={len(items)}) ---")

        try:
            for idx, ex in enumerate(items, 1):
                t_start = time.perf_counter()
                eid = ex.get("example_id", f"ablation_{idx}")
                server_id = ex.get("server_id", "unknown_server")
                gold = ex.get("expected_label", "BENIGN")

                pred = "BENIGN"
                deciding_tier = "Tier 0 (Hash Fast-Path)"
                llm_called = False
                lat_llm = None

                if cfg_id == "config_a":
                    res = evaluate_hash_pinning_example(ex)
                    pred = res["prediction"]
                    deciding_tier = "Tier 0 (Hash Pinning)"

                elif cfg_id == "config_b":
                    res = evaluate_static_rules(ex.get("new_definition", {}), str(ex.get("structured_diff", "")))
                    pred = "MALICIOUS" if res["flagged"] else "BENIGN"
                    deciding_tier = "Tier 2 (Static Rules)"

                elif cfg_id == "config_h":
                    res = evaluate_static_rules(ex.get("new_definition", {}), str(ex.get("structured_diff", "")))
                    if res["flagged"] and res["severity"] == "high":
                        pred = "MALICIOUS"
                        deciding_tier = "Tier 2 (Static Rules)"
                    else:
                        pred = "BENIGN"
                        deciding_tier = "Fast Path (Pass-Through)"

                elif cfg_id in ("config_e", "config_f"):
                    static_res = evaluate_static_rules(ex.get("new_definition", {}), str(ex.get("structured_diff", "")))
                    if static_res["flagged"] and static_res["severity"] == "high":
                        pred = "MALICIOUS"
                        deciding_tier = "Tier 2 (Static Rules)"
                    else:
                        res = evaluate_semantic_judge_example(ex, mode="diff", model_name=model)
                        pred = "MALICIOUS" if res["is_flagged"] else "BENIGN"
                        deciding_tier = "Tier 3 (Semantic Judge Mode B)"
                        llm_called = True
                        lat_llm = res.get("latency_ms_llm")

                tot_lat = (time.perf_counter() - t_start) * 1000.0

                if writer:
                    writer.write_item(
                        item_id=eid,
                        server_id=server_id,
                        gold=gold,
                        predicted=pred,
                        deciding_tier=deciding_tier,
                        llm_called=llm_called,
                        latency_ms_total=tot_lat,
                        latency_ms_llm=lat_llm,
                        model=model if llm_called else "none"
                    )

                print(f"[{cfg_id} - {idx}/{len(items)}] ID: {eid} | Pred: {pred} | Latency: {tot_lat:.2f}ms")

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
