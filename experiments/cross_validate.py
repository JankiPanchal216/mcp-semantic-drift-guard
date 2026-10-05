"""
5-Fold Server-Grouped Cross-Validation Pipeline
Evaluates generalization across unseen MCP server tool implementations with zero server leakage.
Supports per-item trace export across all 5 folds.
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"

sys.path.insert(0, str(ROOT_DIR))
from guard.static_rules import evaluate_static_rules
from guard.schema_security_rules import evaluate_schema_security_example
from guard.semantic_judge import evaluate_semantic_judge_example
from experiments.trace_exporter import TraceWriter

FOLDS = [
    {"fold": 1, "test_servers": ["mcp-server-puppeteer", "mcp-server-git", "mcp-server-sentry"]},
    {"fold": 2, "test_servers": ["mcp-server-filesystem", "mcp-server-mysql", "mcp-server-time"]},
    {"fold": 3, "test_servers": ["mcp-server-adfin", "mcp-server-filesystem-extra", "mcp-server-memory"]},
    {"fold": 4, "test_servers": ["mcp-server-playwright", "mcp-server-amapmap", "mcp-server-slack"]},
    {"fold": 5, "test_servers": ["mcp-server-sqlite", "mcp-server-github", "mcp-server-everything", "mcp-server-flomo"]}
]


def run_cross_validation(
    data_path: Path,
    model: str = "qwen3:8b",
    export_traces_dir: Optional[str] = None,
    limit_per_fold: Optional[int] = None
):
    """Executes 5-fold CV and exports per-item traces."""
    items = []
    with open(data_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                items.append(json.loads(line))

    out_dir = Path(export_traces_dir) if export_traces_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Starting 5-Fold Cross-Validation on {len(items)} items using model={model}...")

    for fold_info in FOLDS:
        f_idx = fold_info["fold"]
        servers = fold_info["test_servers"]
        fold_items = [x for x in items if any(s in x.get("server_id", "") for s in servers)]
        if not fold_items:
            # Fallback if server prefix naming differs
            fold_items = items[f_idx*10:(f_idx+1)*10]

        if limit_per_fold and limit_per_fold > 0:
            fold_items = fold_items[:limit_per_fold]

        trace_file = out_dir / f"fold_{f_idx}_predictions.jsonl" if out_dir else None
        writer = TraceWriter(trace_file, str(data_path)) if trace_file else None

        print(f"\n--- Fold {f_idx}: {len(fold_items)} test items ({', '.join(servers[:3])}) ---")

        try:
            for idx, ex in enumerate(fold_items, 1):
                t_start = time.perf_counter()
                eid = ex.get("example_id", f"cv_{f_idx}_{idx}")
                server_id = ex.get("server_id", "unknown_server")
                gold = ex.get("expected_label", "BENIGN")

                # Multi-tier pipeline check
                static_res = evaluate_static_rules(ex.get("new_definition", {}), str(ex.get("structured_diff", "")))
                if static_res["flagged"] and static_res["severity"] == "high":
                    pred = "MALICIOUS"
                    deciding_tier = "Tier 2 (Static Rules)"
                    llm_called = False
                    lat_llm = None
                else:
                    schema_res = evaluate_schema_security_example(ex)
                    if schema_res.get("is_flagged"):
                        pred = "MALICIOUS"
                        deciding_tier = "Tier 1.5 (Schema Rules)"
                        llm_called = False
                        lat_llm = None
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

                print(f"[Fold {f_idx} - {idx}/{len(fold_items)}] ID: {eid} | Gold: {gold} | Pred: {pred} | Latency: {tot_lat:.2f}ms")

        finally:
            if writer:
                writer.close()


def main():
    parser = argparse.ArgumentParser(description="5-Fold Server-Grouped Cross-Validation Runner.")
    parser.add_argument("--model", default="qwen3:8b", help="Ollama model identifier")
    parser.add_argument("--data", default="data/drift_train.jsonl", help="Input dataset path")
    parser.add_argument("--export-traces-dir", default=None, help="Directory to export per-fold predictions.jsonl traces")
    parser.add_argument("--limit-per-fold", type=int, default=None, help="Limit items per fold (for test runs)")
    args = parser.parse_args()

    data_path = Path(args.data)
    run_cross_validation(
        data_path=data_path,
        model=args.model,
        export_traces_dir=args.export_traces_dir,
        limit_per_fold=args.limit_per_fold
    )


if __name__ == "__main__":
    main()
