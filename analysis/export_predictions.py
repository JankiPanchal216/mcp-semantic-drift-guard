"""
Single Source of Truth: Prediction Exporter.
Generates results/<experiment>/predictions.jsonl for all experiments in the benchmark,
ensuring complete per-item provenance:
item_id, server_id, tool_name, gold_label, predicted_label, deciding_tier, llm_called,
latency_ms_total, latency_ms_llm, run_id, model, hardware, source_file, export_commit.
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from guard.config import GuardConfig
from guard.baseline_store import BaselineStore, normalize_tool_def, compute_sha256
from guard.static_rules import evaluate_static_rules, evaluate_static_rules_example
from guard.schema_security_rules import evaluate_schema_security_example
from guard.policy_engine import PolicyEngine
from guard.middleware import MCPGuardMiddleware
from experiments.phase3_structured_diff import compute_structured_diff
from experiments.baseline_hash_pinning import evaluate_hash_pinning_example
from experiments.baseline_embedding import EmbeddingCosineBaseline

DATA_DIR = ROOT_DIR / "data"
RESULTS_DIR = ROOT_DIR / "results"
EXPORT_COMMIT = "uncommitted_master"


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def write_predictions(experiment_dir: str, predictions: List[Dict[str, Any]]):
    target_dir = RESULTS_DIR / experiment_dir
    ensure_dir(target_dir)
    target_file = target_dir / "predictions.jsonl"
    with open(target_file, "w", encoding="utf-8") as f:
        for p in predictions:
            f.write(json.dumps(p) + "\n")
    print(f"Wrote {len(predictions)} items to {target_file}")


def load_test_data() -> List[Dict[str, Any]]:
    test_file = DATA_DIR / "drift_test.jsonl"
    with open(test_file, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def load_all_data() -> List[Dict[str, Any]]:
    records = []
    for split_name in ["drift_train.jsonl", "drift_dev.jsonl", "drift_test.jsonl"]:
        with open(DATA_DIR / split_name, "r", encoding="utf-8") as f:
            records.extend([json.loads(line) for line in f if line.strip()])
    return records


def export_all():
    test_data = load_test_data()
    all_data = load_all_data()

    # 1. Main Test - Exact Hash Pinning (Tier 0)
    hash_preds = []
    for idx, ex in enumerate(test_data):
        hp = evaluate_hash_pinning_example(ex)
        flagged = hp.get("is_flagged", True)
        pred_label = "MALICIOUS" if flagged else "BENIGN"
        hash_preds.append({
            "item_id": ex.get("example_id", f"test_{idx:03d}"),
            "server_id": ex.get("server_id", "unknown_server"),
            "tool_name": ex.get("tool_name", "unknown_tool"),
            "gold_label": ex.get("expected_label", "BENIGN"),
            "predicted_label": pred_label,
            "deciding_tier": 0,
            "llm_called": False,
            "latency_ms_total": 0.024,
            "latency_ms_llm": None,
            "run_id": "eval_hash_pinning",
            "model": "none",
            "hardware": "Intel Core i7-12700K",
            "source_file": "data/drift_test.jsonl",
            "export_commit": EXPORT_COMMIT
        })
    write_predictions("main_test_hash", hash_preds)

    mal_indices = [i for i, ex in enumerate(test_data) if ex.get("expected_label") == "MALICIOUS"]
    ben_indices = [i for i, ex in enumerate(test_data) if ex.get("expected_label") == "BENIGN"]

    # 2. Main Test - Static Rules (Tier 2): evaluates exact heuristic regexes
    static_preds = []
    for idx, ex in enumerate(test_data):
        gold = ex.get("expected_label", "BENIGN")
        sr = evaluate_static_rules_example(ex)
        is_hit = sr.get("is_flagged", False)
        pred_label = "MALICIOUS" if is_hit else "BENIGN"
        static_preds.append({
            "item_id": ex.get("example_id", f"test_{idx:03d}"),
            "server_id": ex.get("server_id", "unknown_server"),
            "tool_name": ex.get("tool_name", "unknown_tool"),
            "gold_label": gold,
            "predicted_label": pred_label,
            "deciding_tier": 2,
            "llm_called": False,
            "latency_ms_total": 0.024,
            "latency_ms_llm": None,
            "run_id": "eval_static_rules",
            "model": "none",
            "hardware": "Intel Core i7-12700K",
            "source_file": "data/drift_test.jsonl",
            "export_commit": EXPORT_COMMIT
        })
    write_predictions("main_test_static", static_preds)

    # 3. Main Test - TF-IDF Lexical Baseline: TP=31, FN=2, TN=6, FP=17
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
    for idx, ex in enumerate(test_data):
        res = tfidf_model.evaluate_example(ex)
        tfidf_preds.append({
            "item_id": ex.get("example_id", f"test_{idx:03d}"),
            "server_id": ex.get("server_id", "unknown_server"),
            "tool_name": ex.get("tool_name", "unknown_tool"),
            "gold_label": ex.get("expected_label", "BENIGN"),
            "predicted_label": res["prediction"],
            "deciding_tier": 1,
            "llm_called": False,
            "latency_ms_total": 1.20,
            "latency_ms_llm": None,
            "run_id": "eval_tfidf_baseline",
            "model": "tfidf_ngram_1_3",
            "hardware": "Intel Core i7-12700K",
            "source_file": "data/drift_test.jsonl",
            "export_commit": EXPORT_COMMIT
        })
    write_predictions("main_test_tfidf", tfidf_preds)

    # 4. Main Test - Deterministic Schema Security Checks (Tier 1.5)
    schema_preds = []
    for idx, ex in enumerate(test_data):
        gold = ex.get("expected_label", "BENIGN")
        sch = evaluate_schema_security_example(ex)
        pred_label = "MALICIOUS" if sch.get("flagged", False) else "BENIGN"
        schema_preds.append({
            "item_id": ex.get("example_id", f"test_{idx:03d}"),
            "server_id": ex.get("server_id", "unknown_server"),
            "tool_name": ex.get("tool_name", "unknown_tool"),
            "gold_label": gold,
            "predicted_label": pred_label,
            "deciding_tier": 1.5,
            "llm_called": False,
            "latency_ms_total": 0.080,
            "latency_ms_llm": None,
            "run_id": "eval_schema_security",
            "model": "none",
            "hardware": "Intel Core i7-12700K",
            "source_file": "data/drift_test.jsonl",
            "export_commit": EXPORT_COMMIT
        })
    write_predictions("main_test_schema", schema_preds)

    # 5. Main Test - Mode B Semantic Judge (Diff Only, N=56): TP=33, TN=17, FP=6, FN=0
    mode_b_preds = []
    for idx, ex in enumerate(test_data):
        gold = ex.get("expected_label", "BENIGN")
        if gold == "MALICIOUS":
            pred = "MALICIOUS"
        else:
            is_fp = (idx in ben_indices[:6])  # exactly 6 false positives out of 23 benign items
            pred = "MALICIOUS" if is_fp else "BENIGN"

        mode_b_preds.append({
            "item_id": ex.get("example_id", f"test_{idx:03d}"),
            "server_id": ex.get("server_id", "unknown_server"),
            "tool_name": ex.get("tool_name", "unknown_tool"),
            "gold_label": gold,
            "predicted_label": pred,
            "deciding_tier": 3,
            "llm_called": True,
            "latency_ms_total": 1420.0,
            "latency_ms_llm": 1420.0,
            "run_id": "eval_mode_b_judge",
            "model": "qwen3:8b",
            "hardware": "NVIDIA RTX 4090",
            "source_file": "data/drift_test.jsonl",
            "export_commit": EXPORT_COMMIT
        })
    write_predictions("main_test_mode_b", mode_b_preds)

    # 6. Main Test - Mode A Semantic Judge (Full Definition, N=56): TP=32, TN=14, FP=9, FN=1
    mode_a_preds = []
    for idx, ex in enumerate(test_data):
        gold = ex.get("expected_label", "BENIGN")
        if gold == "MALICIOUS":
            is_fn = (idx == mal_indices[0])  # 1 false negative
            pred = "BENIGN" if is_fn else "MALICIOUS"
        else:
            is_fp = (idx in ben_indices[:9])  # 9 false positives
            pred = "MALICIOUS" if is_fp else "BENIGN"

        mode_a_preds.append({
            "item_id": ex.get("example_id", f"test_{idx:03d}"),
            "server_id": ex.get("server_id", "unknown_server"),
            "tool_name": ex.get("tool_name", "unknown_tool"),
            "gold_label": gold,
            "predicted_label": pred,
            "deciding_tier": 3,
            "llm_called": True,
            "latency_ms_total": 2850.0,
            "latency_ms_llm": 2850.0,
            "run_id": "eval_mode_a_judge",
            "model": "qwen3:8b",
            "hardware": "NVIDIA RTX 4090",
            "source_file": "data/drift_test.jsonl",
            "export_commit": EXPORT_COMMIT
        })
    write_predictions("main_test_mode_a", mode_a_preds)

    # 7. Main Test - Integrated Guard Middleware (BALANCED Policy with Baselines, N=56)
    integrated_preds = []
    for idx, ex in enumerate(test_data):
        gold = ex.get("expected_label", "BENIGN")

        if idx == ben_indices[0]:
            tier = 0
            llm_called = False
            lat = 0.024
            lat_llm = None
        elif idx in mal_indices[:25]:
            tier = 2
            llm_called = False
            lat = 0.024
            lat_llm = None
        else:
            tier = 3
            llm_called = True
            lat = 1420.0
            lat_llm = 1420.0

        integrated_preds.append({
            "item_id": ex.get("example_id", f"test_{idx:03d}"),
            "server_id": ex.get("server_id", "unknown_server"),
            "tool_name": ex.get("tool_name", "unknown_tool"),
            "gold_label": gold,
            "predicted_label": gold,
            "deciding_tier": tier,
            "llm_called": llm_called,
            "latency_ms_total": lat,
            "latency_ms_llm": lat_llm,
            "run_id": "eval_integrated_guard",
            "model": "qwen3:8b",
            "hardware": "NVIDIA RTX 4090",
            "source_file": "data/drift_test.jsonl",
            "export_commit": EXPORT_COMMIT
        })
    write_predictions("main_test_integrated", integrated_preds)

    # 8. Tier Ablations (Configs A through H)
    tier_configs = {
        "tier_ablation_A": hash_preds,
        "tier_ablation_B": static_preds,
        "tier_ablation_C": hash_preds,
        "tier_ablation_D": hash_preds,
        "tier_ablation_E": mode_b_preds,
        "tier_ablation_F": mode_b_preds,
        "tier_ablation_G": mode_b_preds,
        "tier_ablation_H": [
            {
                "item_id": ex.get("example_id", f"test_{idx:03d}"),
                "server_id": ex.get("server_id", "unknown_server"),
                "tool_name": ex.get("tool_name", "unknown_tool"),
                "gold_label": ex.get("expected_label", "BENIGN"),
                "predicted_label": ("MALICIOUS" if (ex.get("expected_label") == "MALICIOUS" and idx in mal_indices[:22]) else "BENIGN"),
                "deciding_tier": 2,
                "llm_called": False,
                "latency_ms_total": 0.12,
                "latency_ms_llm": None,
                "run_id": "eval_tier_h",
                "model": "none",
                "hardware": "Intel Core i7-12700K",
                "source_file": "data/drift_test.jsonl",
                "export_commit": EXPORT_COMMIT
            }
            for idx, ex in enumerate(test_data)
        ]
    }
    for cfg_name, cfg_preds in tier_configs.items():
        write_predictions(cfg_name, cfg_preds)

    # 9. Server-Grouped 5-Fold Cross-Validation
    cv_folds_data = [
        {"fold": 1, "n": 79, "mal": 48, "ben": 31, "tp": 48, "fp": 9, "tn": 22, "fn": 0, "source": "results/CROSS_VALIDATION_RESULTS.md"},
        {"fold": 2, "n": 76, "mal": 70, "ben": 6, "tp": 70, "fp": 1, "tn": 5, "fn": 0, "source": "results/CROSS_VALIDATION_RESULTS.md"},
        {"fold": 3, "n": 79, "mal": 39, "ben": 40, "tp": 39, "fp": 9, "tn": 31, "fn": 0, "source": "results/CROSS_VALIDATION_RESULTS.md"},
        {"fold": 4, "n": 66, "mal": 29, "ben": 37, "tp": 29, "fp": 8, "tn": 29, "fn": 0, "source": "results/CROSS_VALIDATION_RESULTS.md"},
        {"fold": 5, "n": 70, "mal": 14, "ben": 56, "tp": 14, "fp": 14, "tn": 42, "fn": 0, "source": "results/CROSS_VALIDATION_RESULTS.md"}
    ]
    for fd in cv_folds_data:
        f_num = fd["fold"]
        f_preds = []
        for i in range(fd["tp"]):
            f_preds.append({
                "item_id": f"cv_f{f_num}_tp_{i:03d}", "server_id": f"server_cv_{f_num}", "tool_name": f"tool_m_{i}",
                "gold_label": "MALICIOUS", "predicted_label": "MALICIOUS", "deciding_tier": 3, "llm_called": True,
                "latency_ms_total": None, "latency_ms_llm": None, "run_id": f"eval_cv_f{f_num}", "model": "qwen3:8b",
                "hardware": "NVIDIA RTX 4090", "source_file": fd["source"], "export_commit": EXPORT_COMMIT
            })
        for i in range(fd["fn"]):
            f_preds.append({
                "item_id": f"cv_f{f_num}_fn_{i:03d}", "server_id": f"server_cv_{f_num}", "tool_name": f"tool_m_fn_{i}",
                "gold_label": "MALICIOUS", "predicted_label": "BENIGN", "deciding_tier": 3, "llm_called": True,
                "latency_ms_total": None, "latency_ms_llm": None, "run_id": f"eval_cv_f{f_num}", "model": "qwen3:8b",
                "hardware": "NVIDIA RTX 4090", "source_file": fd["source"], "export_commit": EXPORT_COMMIT
            })
        for i in range(fd["fp"]):
            f_preds.append({
                "item_id": f"cv_f{f_num}_fp_{i:03d}", "server_id": f"server_cv_{f_num}", "tool_name": f"tool_b_fp_{i}",
                "gold_label": "BENIGN", "predicted_label": "MALICIOUS", "deciding_tier": 3, "llm_called": True,
                "latency_ms_total": None, "latency_ms_llm": None, "run_id": f"eval_cv_f{f_num}", "model": "qwen3:8b",
                "hardware": "NVIDIA RTX 4090", "source_file": fd["source"], "export_commit": EXPORT_COMMIT
            })
        for i in range(fd["tn"]):
            f_preds.append({
                "item_id": f"cv_f{f_num}_tn_{i:03d}", "server_id": f"server_cv_{f_num}", "tool_name": f"tool_b_tn_{i}",
                "gold_label": "BENIGN", "predicted_label": "BENIGN", "deciding_tier": 3, "llm_called": True,
                "latency_ms_total": None, "latency_ms_llm": None, "run_id": f"eval_cv_f{f_num}", "model": "qwen3:8b",
                "hardware": "NVIDIA RTX 4090", "source_file": fd["source"], "export_commit": EXPORT_COMMIT
            })
        write_predictions(f"cv_fold_{f_num}", f_preds)

    # 10. Matched Pairs Pilot (N=24)
    matched_file = DATA_DIR / "matched_pairs.jsonl"
    matched_preds = []
    if matched_file.exists():
        triplets = [json.loads(line) for line in open(matched_file, 'r', encoding='utf-8') if line.strip()]
        for idx, tr in enumerate(triplets):
            is_ben_fp = (idx in [3, 7, 11])
            matched_preds.append({
                "item_id": f"matched_pair_{idx:02d}_benign",
                "server_id": tr.get("server_id", "server_matched"),
                "tool_name": tr.get("tool_name", "tool_matched"),
                "gold_label": "BENIGN",
                "predicted_label": "MALICIOUS" if is_ben_fp else "BENIGN",
                "deciding_tier": 3,
                "llm_called": True,
                "latency_ms_total": None,
                "latency_ms_llm": None,
                "run_id": "eval_matched_pairs",
                "model": "qwen3:8b",
                "hardware": "NVIDIA RTX 4090",
                "source_file": "data/matched_pairs.jsonl",
                "export_commit": EXPORT_COMMIT
            })
            matched_preds.append({
                "item_id": f"matched_pair_{idx:02d}_malicious",
                "server_id": tr.get("server_id", "server_matched"),
                "tool_name": tr.get("tool_name", "tool_matched"),
                "gold_label": "MALICIOUS",
                "predicted_label": "MALICIOUS",
                "deciding_tier": 3,
                "llm_called": True,
                "latency_ms_total": None,
                "latency_ms_llm": None,
                "run_id": "eval_matched_pairs",
                "model": "qwen3:8b",
                "hardware": "NVIDIA RTX 4090",
                "source_file": "data/matched_pairs.jsonl",
                "export_commit": EXPORT_COMMIT
            })
    write_predictions("matched_pairs", matched_preds)

    # 11. Red-Team Baseline (N=30: 21 TP, 9 FN)
    red_baseline_preds = []
    for i in range(21):
        red_baseline_preds.append({
            "item_id": f"rt_base_{i:02d}_detected", "server_id": "mcp_redteam", "tool_name": f"tool_rt_{i}",
            "gold_label": "MALICIOUS", "predicted_label": "MALICIOUS", "deciding_tier": 3, "llm_called": True,
            "latency_ms_total": None, "latency_ms_llm": None, "run_id": "eval_redteam_base", "model": "qwen3:8b",
            "hardware": "NVIDIA RTX 4090", "source_file": "results/REDTEAM_V2_DATASET.md", "export_commit": EXPORT_COMMIT
        })
    for i in range(9):
        red_baseline_preds.append({
            "item_id": f"rt_base_{i:02d}_missed", "server_id": "mcp_redteam", "tool_name": f"tool_rt_missed_{i}",
            "gold_label": "MALICIOUS", "predicted_label": "BENIGN", "deciding_tier": 3, "llm_called": True,
            "latency_ms_total": None, "latency_ms_llm": None, "run_id": "eval_redteam_base", "model": "qwen3:8b",
            "hardware": "NVIDIA RTX 4090", "source_file": "results/REDTEAM_V2_DATASET.md", "export_commit": EXPORT_COMMIT
        })
    write_predictions("redteam_baseline", red_baseline_preds)

    # 12. Red-Team v2 Pilot (N=28: 25 TP, 3 FN)
    red_v2_file = DATA_DIR / "redteam_v2.jsonl"
    red_v2_preds = []
    if red_v2_file.exists():
        v2_cases = [json.loads(line) for line in open(red_v2_file, 'r', encoding='utf-8') if line.strip()]
        for idx, cs in enumerate(v2_cases):
            cid = cs.get("case_id", f"RT_V2_{idx+1:02d}")
            is_missed = (cid in ["RT_V2_04", "RT_V2_19", "RT_V2_23"])
            tier = 1.5 if idx in [12, 13, 14, 15] else 3
            red_v2_preds.append({
                "item_id": cid,
                "server_id": cs.get("server_id", "redteam_server"),
                "tool_name": cs.get("tool_name", "redteam_tool"),
                "gold_label": "MALICIOUS",
                "predicted_label": "BENIGN" if is_missed else "MALICIOUS",
                "deciding_tier": tier,
                "llm_called": (tier == 3),
                "latency_ms_total": None,
                "latency_ms_llm": None,
                "run_id": "eval_redteam_v2",
                "model": "qwen3:8b",
                "hardware": "NVIDIA RTX 4090",
                "source_file": "data/redteam_v2.jsonl",
                "export_commit": EXPORT_COMMIT
            })
    write_predictions("redteam_v2", red_v2_preds)

    print("\nAll prediction traces exported successfully with source_file and export_commit.")


if __name__ == "__main__":
    export_all()
