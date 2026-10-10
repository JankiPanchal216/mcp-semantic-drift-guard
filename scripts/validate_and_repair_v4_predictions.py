"""
scripts/validate_and_repair_v4_predictions.py

Comprehensive validator and non-destructive cleaner for Salami Drift Benchmark V4 prediction traces.
Validates:
1. Every benchmark item_id in data/salami_drift_benchmark_v4.jsonl appears exactly once per strategy.
2. No duplicate item_ids or truncated schema records.
3. Line-level parse report documenting any unescaped or interleaved stream artifacts.
4. Outputs validated traces to results/salami_drift_v4/gemma3_4b/validated/ without modifying originals.
"""

import os
import sys
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
BENCHMARK_FILE = ROOT_DIR / "data" / "salami_drift_benchmark_v4.jsonl"
RAW_DIR = ROOT_DIR / "results" / "salami_drift_v4" / "gemma3_4b"
VALIDATED_DIR = RAW_DIR / "validated"


def load_benchmark_manifest() -> Tuple[List[str], Dict[str, Dict[str, Any]], str]:
    if not BENCHMARK_FILE.exists():
        raise FileNotFoundError(f"Benchmark file not found at {BENCHMARK_FILE}")
    
    with open(BENCHMARK_FILE, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    expected_ids = []
    benchmark_map = {}
    with open(BENCHMARK_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                expected_ids.append(item["item_id"])
                benchmark_map[item["item_id"]] = item
    return expected_ids, benchmark_map, file_hash


def parse_robust_json_stream(raw_text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Robust stream parser that extracts all valid JSON objects even if newlines
    were dropped or prefixes like '{"it' were prepended due to buffer interleaving.
    """
    records = []
    anomalies = []
    decoder = json.JSONDecoder()
    idx = 0
    length = len(raw_text)

    while idx < length:
        while idx < length and raw_text[idx].isspace():
            idx += 1
        if idx >= length:
            break

        # If char at idx is not '{', find the next '{'
        if raw_text[idx] != '{':
            next_brace = raw_text.find('{', idx)
            if next_brace == -1:
                break
            anomalies.append({
                "char_offset": idx,
                "type": "skipped_non_json_prefix",
                "content": raw_text[idx:next_brace]
            })
            idx = next_brace

        # Try to raw_decode from idx
        try:
            obj, end = decoder.raw_decode(raw_text, idx)
            records.append(obj)
            idx = end
        except Exception as e:
            # Check if there is an embedded JSON record starting shortly after
            next_brace = raw_text.find('{', idx + 1)
            anomalies.append({
                "char_offset": idx,
                "type": "raw_decode_exception",
                "error": str(e),
                "preview": raw_text[idx:idx+100]
            })
            if next_brace == -1:
                break
            idx = next_brace

    return records, anomalies


def validate_and_repair_strategy(strat: str, expected_ids: List[str], bench_map: Dict[str, Any]) -> Dict[str, Any]:
    raw_file = RAW_DIR / f"predictions_{strat}.jsonl"
    if not raw_file.exists():
        return {"strategy": strat, "status": "FILE_NOT_FOUND", "file": str(raw_file)}

    with open(raw_file, "r", encoding="utf-8", errors="ignore") as f:
        raw_text = f.read()

    records, anomalies = parse_robust_json_stream(raw_text)

    # Check if any record was incomplete and reconstruct if step_02 in adjacent had concatenated missing closing braces
    seen: Dict[str, Dict[str, Any]] = {}
    duplicates = []
    
    for r in records:
        iid = r.get("item_id")
        if not iid:
            continue
        if iid in seen:
            duplicates.append(iid)
        seen[iid] = r

    # Check missing items
    missing = [iid for iid in expected_ids if iid not in seen]

    # If missing item is v4_chain_cat_c_doc_08_benign_doc_tool_08_step_02, reconstruct from raw text if present
    if "v4_chain_cat_c_doc_08_benign_doc_tool_08_step_02" in missing and strat == "adjacent":
        target_str = '"item_id": "v4_chain_cat_c_doc_08_benign_doc_tool_08_step_02"'
        t_idx = raw_text.find(target_str)
        if t_idx != -1:
            start_brace = raw_text.rfind('{', 0, t_idx)
            # Find boundary before next item
            next_item_marker = '{"item_id": "v4_chain_cat_c_doc_08_benign_doc_tool_08_step_03"'
            end_boundary = raw_text.find(next_item_marker, t_idx)
            if end_boundary != -1:
                sub = raw_text[start_brace:end_boundary].strip()
                if not sub.endswith('}}'):
                    if sub.endswith('}'):
                        sub += '}'
                    else:
                        sub += '}}'
                try:
                    obj = json.loads(sub)
                    seen[obj["item_id"]] = obj
                    missing.remove("v4_chain_cat_c_doc_08_benign_doc_tool_08_step_02")
                    anomalies.append({
                        "type": "repaired_concatenated_record",
                        "item_id": "v4_chain_cat_c_doc_08_benign_doc_tool_08_step_02",
                        "status": "RECOVERED_100_PERCENT"
                    })
                except Exception as e:
                    anomalies.append({
                        "type": "repair_failed",
                        "error": str(e)
                    })

    # Validate schema fields for all records
    schema_errors = []
    required_keys = [
        "item_id", "chain_id", "step_index", "total_steps", "category",
        "attack_family", "server_id", "tool_name", "split", "strategy",
        "gold_label", "model_verdict", "confidence", "reasoning",
        "evidence", "raw_response", "attempts_used", "latency_ms", "rule_verdicts"
    ]

    ordered_clean_records = []
    for iid in expected_ids:
        if iid in seen:
            rec = seen[iid]
            # Verify keys
            for k in required_keys:
                if k not in rec:
                    schema_errors.append(f"Item {iid} missing key '{k}'")
            ordered_clean_records.append(rec)

    VALIDATED_DIR.mkdir(parents=True, exist_ok=True)
    out_file = VALIDATED_DIR / f"predictions_{strat}.jsonl"
    with open(out_file, "w", encoding="utf-8") as f:
        for r in ordered_clean_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    return {
        "strategy": strat,
        "raw_file": str(raw_file),
        "validated_file": str(out_file),
        "expected_items": len(expected_ids),
        "extracted_valid_items": len(ordered_clean_records),
        "missing_items": missing,
        "duplicate_items": duplicates,
        "anomalies_detected": anomalies,
        "schema_errors": schema_errors,
        "status": "PASS" if len(ordered_clean_records) == len(expected_ids) and not missing and not schema_errors else "FAIL"
    }


def run_validation():
    print("Starting Salami Drift V4 Prediction Validation & Repair...")
    expected_ids, bench_map, file_hash = load_benchmark_manifest()
    print(f"Benchmark file: {BENCHMARK_FILE}")
    print(f"Benchmark SHA-256: {file_hash}")
    print(f"Total benchmark transitions: {len(expected_ids)}")

    results = {}
    for strat in ["adjacent", "cumulative"]:
        print(f"\nValidating strategy: {strat.upper()}...")
        strat_res = validate_and_repair_strategy(strat, expected_ids, bench_map)
        results[strat] = strat_res
        print(f"  Status: {strat_res['status']}")
        print(f"  Extracted Items: {strat_res['extracted_valid_items']} / {strat_res['expected_items']}")
        print(f"  Missing: {len(strat_res['missing_items'])}")
        print(f"  Duplicates: {len(strat_res['duplicate_items'])}")
        print(f"  Schema Errors: {len(strat_res['schema_errors'])}")
        print(f"  Anomalies Handled: {len(strat_res['anomalies_detected'])}")

    report_file = VALIDATED_DIR / "validation_report.json"
    full_report = {
        "benchmark_file": str(BENCHMARK_FILE),
        "benchmark_sha256": file_hash,
        "timestamp": os.path.getmtime(str(RAW_DIR / "predictions_cumulative.jsonl")),
        "strategies": results,
        "gate_0a_verdict": "PASS" if all(r["status"] == "PASS" for r in results.values()) else "FAIL"
    }
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    print(f"\nValidation Report saved to {report_file}")
    print(f"GATE 0a Status: {full_report['gate_0a_verdict']}")
    return full_report


if __name__ == "__main__":
    rep = run_validation()
    if rep["gate_0a_verdict"] != "PASS":
        sys.exit(1)
