"""
5-Fold Server-Grouped Cross-Validation Pipeline
Evaluates generalization across unseen MCP server tool implementations with zero server leakage.
Pools all 370 benchmark items (train + dev + test) and partitions them by server_id into 5 disjoint folds.
Supports per-item trace export with unified schema across all 5 folds.
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

# 5 Disjoint Server Folds covering all 19 unique servers in the 370-item benchmark
SERVER_FOLDS = [
    {
        "fold": 1,
        "servers": ["mcp-server-puppeteer", "mcp-server-git", "mcp-server-sentry", "mcptox-puppeteer"]
    },
    {
        "fold": 2,
        "servers": ["mcp-server-filesystem", "mcp-server-mysql", "mcp-server-time", "mcptox-filesystem"]
    },
    {
        "fold": 3,
        "servers": ["mcptox-adfin", "mcp-server-memory", "mcp-server-sequentialthinking"]
    },
    {
        "fold": 4,
        "servers": ["mcp-playwright", "mcptox-amapmap", "mcp-server-slack"]
    },
    {
        "fold": 5,
        "servers": ["mcp-server-sqlite", "mcp-server-github", "mcp-server-everything", "mcptox-flomo", "mcptox-github"]
    }
]


def load_all_benchmark_data(data_dir: Path) -> List[Dict[str, Any]]:
    """Loads all 370 benchmark examples across train, dev, and test splits."""
    all_items = []
    seen_ids = set()
    for fname in ["drift_train.jsonl", "drift_dev.jsonl", "drift_test.jsonl"]:
        fpath = data_dir / fname
        if fpath.exists():
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        ex = json.loads(line)
                        eid = ex.get("example_id")
                        if eid and eid not in seen_ids:
                            seen_ids.add(eid)
                            ex["_source_split"] = fname
                            all_items.append(ex)
    return all_items


def run_cross_validation(
    data_dir: Path,
    model: str = "qwen3:8b",
    export_traces_dir: Optional[str] = None,
    limit_per_fold: Optional[int] = None
):
    """Executes 5-fold server-grouped CV and exports per-item traces."""
    items = load_all_benchmark_data(data_dir)
    print(f"Loaded {len(items)} total items across all dataset splits for Server-Grouped 5-Fold CV.")

    out_dir = Path(export_traces_dir) if export_traces_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Starting 5-Fold Cross-Validation on {len(items)} items using model={model}...")

    # Validate zero server overlap between folds
    assigned_servers = set()
    for f in SERVER_FOLDS:
        f_servers = set(f["servers"])
        overlap = assigned_servers.intersection(f_servers)
        assert len(overlap) == 0, f"Server leakage detected across folds: {overlap}"
        assigned_servers.update(f_servers)

    for fold_info in SERVER_FOLDS:
        f_idx = fold_info["fold"]
        servers = set(fold_info["servers"])
        fold_items = [x for x in items if x.get("server_id") in servers]

        if limit_per_fold and limit_per_fold > 0:
            fold_items = fold_items[:limit_per_fold]

        trace_file = out_dir / f"fold_{f_idx}_predictions.jsonl" if out_dir else None
        writer = TraceWriter(trace_file, "data/drift_[train|dev|test].jsonl") if trace_file else None

        print(f"\n--- Fold {f_idx}: {len(fold_items)} test items (Servers: {', '.join(sorted(servers))}) ---")

        try:
            for idx, ex in enumerate(fold_items, 1):
                t_start = time.perf_counter()
                eid = ex.get("example_id", f"cv_{f_idx}_{idx}")
                server_id = ex.get("server_id", "unknown_server")
                tool_name = ex.get("tool_name", "unknown_tool")
                gold = ex.get("expected_label", "BENIGN")

                # Multi-tier pipeline check
                static_res = evaluate_static_rules(ex.get("new_definition", {}), str(ex.get("structured_diff", "")))
                if static_res["flagged"] and static_res["severity"] == "high":
                    pred = "MALICIOUS"
                    deciding_tier = 2
                    llm_called = False
                    lat_llm = None
                else:
                    schema_res = evaluate_schema_security_example(ex)
                    if schema_res.get("is_flagged"):
                        pred = "MALICIOUS"
                        deciding_tier = 1.5
                        llm_called = False
                        lat_llm = None
                    else:
                        res = evaluate_semantic_judge_example(ex, mode="diff", model_name=model)
                        pred = "MALICIOUS" if res["is_flagged"] else "BENIGN"
                        deciding_tier = 3
                        llm_called = True
                        lat_llm = res.get("latency_ms_llm")

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

                print(f"[Fold {f_idx} - {idx}/{len(fold_items)}] ID: {eid} | Gold: {gold} | Pred: {pred} | Tier: {deciding_tier} | Latency: {tot_lat:.2f}ms")

        finally:
            if writer:
                writer.close()


def main():
    parser = argparse.ArgumentParser(description="5-Fold Server-Grouped Cross-Validation Runner.")
    parser.add_argument("--model", default="qwen3:8b", help="Ollama model identifier")
    parser.add_argument("--data-dir", default="data", help="Directory containing dataset splits")
    parser.add_argument("--export-traces-dir", default=None, help="Directory to export per-fold predictions.jsonl traces")
    parser.add_argument("--limit-per-fold", type=int, default=None, help="Limit items per fold (for test runs)")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    run_cross_validation(
        data_dir=data_dir,
        model=args.model,
        export_traces_dir=args.export_traces_dir,
        limit_per_fold=args.limit_per_fold
    )


if __name__ == "__main__":
    main()
