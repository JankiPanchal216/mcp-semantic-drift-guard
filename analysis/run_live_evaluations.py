"""
Live Deterministic & Lexical Benchmark Execution.
Evaluates active local detectors on data/drift_test.jsonl (N=56):
1. Exact Hash Pinning (Tier 0)
2. TF-IDF Cosine Baseline (Lexical)
3. Static Heuristic & Regex Rules (Tier 2)
4. Deterministic Schema Security Rules (Tier 1.5)

Records per-item:
item_id, server_id, tool_name, gold_label, predicted_label, deciding_tier, llm_called,
latency_ms_total, latency_ms_llm, run_id, model, hardware, source_file, export_commit.
"""

import os
import sys
import json
import time
import platform
import shutil
from pathlib import Path
from typing import Dict, List, Any

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from experiments.baseline_hash_pinning import evaluate_hash_pinning_example
from experiments.baseline_embedding import EmbeddingCosineBaseline
from guard.static_rules import evaluate_static_rules_example
from guard.schema_security_rules import evaluate_schema_security_example

DATA_DIR = ROOT_DIR / "data"
RESULTS_DIR = ROOT_DIR / "results"
EXPORT_COMMIT = "381125b09dee2d05f23e170e32762a71f815305d"
HARDWARE_STRING = f"CPU: {platform.processor()} ({platform.platform()})"


def ensure_clean_dir(path: Path):
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def write_predictions(experiment_dir: str, predictions: List[Dict[str, Any]]):
    target_dir = RESULTS_DIR / experiment_dir
    ensure_clean_dir(target_dir)
    target_file = target_dir / "predictions.jsonl"
    with open(target_file, "w", encoding="utf-8") as f:
        for p in predictions:
            f.write(json.dumps(p) + "\n")
    print(f"Wrote {len(predictions)} real evaluated items to {target_file}")


def load_test_data() -> List[Dict[str, Any]]:
    test_file = DATA_DIR / "drift_test.jsonl"
    with open(test_file, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def run_live_evaluations():
    test_data = load_test_data()
    print(f"Loaded {len(test_data)} test items from {DATA_DIR / 'drift_test.jsonl'}")

    # 1. Exact Hash Pinning (Tier 0)
    hash_preds = []
    for ex in test_data:
        t0 = time.perf_counter()
        hp = evaluate_hash_pinning_example(ex)
        t1 = time.perf_counter()
        lat_ms = (t1 - t0) * 1000.0
        flagged = hp.get("is_flagged", True)
        hash_preds.append({
            "item_id": ex["example_id"],
            "server_id": ex.get("server_id", "unknown_server"),
            "tool_name": ex.get("tool_name", "unknown_tool"),
            "gold_label": ex["expected_label"],
            "predicted_label": "MALICIOUS" if flagged else "BENIGN",
            "deciding_tier": 0,
            "llm_called": False,
            "latency_ms_total": lat_ms,
            "latency_ms_llm": None,
            "run_id": "eval_hash_pinning_live",
            "model": "sha256",
            "hardware": HARDWARE_STRING,
            "source_file": "data/drift_test.jsonl",
            "export_commit": EXPORT_COMMIT
        })
    write_predictions("main_test_hash", hash_preds)

    # 2. Static Heuristic & Regex Rules (Tier 2)
    static_preds = []
    for ex in test_data:
        t0 = time.perf_counter()
        sr = evaluate_static_rules_example(ex)
        t1 = time.perf_counter()
        lat_ms = (t1 - t0) * 1000.0
        flagged = sr.get("is_flagged", False)
        static_preds.append({
            "item_id": ex["example_id"],
            "server_id": ex.get("server_id", "unknown_server"),
            "tool_name": ex.get("tool_name", "unknown_tool"),
            "gold_label": ex["expected_label"],
            "predicted_label": "MALICIOUS" if flagged else "BENIGN",
            "deciding_tier": 2 if flagged else "none",
            "llm_called": False,
            "latency_ms_total": lat_ms,
            "latency_ms_llm": None,
            "run_id": "eval_static_rules_live",
            "model": "regex_rules_v1",
            "hardware": HARDWARE_STRING,
            "source_file": "data/drift_test.jsonl",
            "export_commit": EXPORT_COMMIT
        })
    write_predictions("main_test_static", static_preds)

    # 3. TF-IDF Cosine Baseline (fit on train+dev, evaluated on test)
    train_ex = [json.loads(line) for line in open(DATA_DIR / "drift_train.jsonl", 'r', encoding='utf-8') if line.strip()]
    dev_ex = [json.loads(line) for line in open(DATA_DIR / "drift_dev.jsonl", 'r', encoding='utf-8') if line.strip()]
    all_texts = []
    for ex in train_ex + dev_ex:
        o = ex.get("old_definition") or {}
        n = ex.get("new_definition") or {}
        all_texts.extend([
            f"{o.get('name', '')} {o.get('description', '')} {json.dumps(o.get('inputSchema', {}))}",
            f"{n.get('name', '')} {n.get('description', '')} {json.dumps(n.get('inputSchema', {}))}"
        ])
    tfidf_model = EmbeddingCosineBaseline(threshold=0.590)
    tfidf_model.fit_corpus(all_texts)

    tfidf_preds = []
    for ex in test_data:
        t0 = time.perf_counter()
        res = tfidf_model.evaluate_example(ex)
        t1 = time.perf_counter()
        lat_ms = (t1 - t0) * 1000.0
        tfidf_preds.append({
            "item_id": ex["example_id"],
            "server_id": ex.get("server_id", "unknown_server"),
            "tool_name": ex.get("tool_name", "unknown_tool"),
            "gold_label": ex["expected_label"],
            "predicted_label": res["prediction"],
            "deciding_tier": 1 if res["prediction"] == "MALICIOUS" else "none",
            "llm_called": False,
            "latency_ms_total": lat_ms,
            "latency_ms_llm": None,
            "run_id": "eval_tfidf_baseline_live",
            "model": "tfidf_ngram_1_3",
            "hardware": HARDWARE_STRING,
            "source_file": "data/drift_test.jsonl",
            "export_commit": EXPORT_COMMIT
        })
    write_predictions("main_test_tfidf", tfidf_preds)

    # 4. Deterministic Schema Security Checks (Tier 1.5)
    schema_preds = []
    for ex in test_data:
        t0 = time.perf_counter()
        sch = evaluate_schema_security_example(ex)
        t1 = time.perf_counter()
        lat_ms = (t1 - t0) * 1000.0
        flagged = sch.get("flagged", False)
        schema_preds.append({
            "item_id": ex["example_id"],
            "server_id": ex.get("server_id", "unknown_server"),
            "tool_name": ex.get("tool_name", "unknown_tool"),
            "gold_label": ex["expected_label"],
            "predicted_label": "MALICIOUS" if flagged else "BENIGN",
            "deciding_tier": 1.5 if flagged else "none",
            "llm_called": False,
            "latency_ms_total": lat_ms,
            "latency_ms_llm": None,
            "run_id": "eval_schema_security_live",
            "model": "schema_security_rules_v1",
            "hardware": HARDWARE_STRING,
            "source_file": "data/drift_test.jsonl",
            "export_commit": EXPORT_COMMIT
        })
    write_predictions("main_test_schema", schema_preds)

    # Delete any constructed directories to prevent non-verifiable rows
    unverified_dirs = [
        "tier_ablation_A", "tier_ablation_B", "tier_ablation_C", "tier_ablation_D",
        "tier_ablation_E", "tier_ablation_F", "tier_ablation_G", "tier_ablation_H",
        "cv_fold_1", "cv_fold_2", "cv_fold_3", "cv_fold_4", "cv_fold_5",
        "matched_pairs", "redteam_baseline", "redteam_v2",
        "main_test_mode_a", "main_test_mode_b", "main_test_integrated"
    ]
    for d in unverified_dirs:
        p = RESULTS_DIR / d
        if p.exists():
            shutil.rmtree(p)
            print(f"Removed unverified directory: {p}")

    print("\nLive evaluations complete. Real per-item prediction files created.")


if __name__ == "__main__":
    run_live_evaluations()
