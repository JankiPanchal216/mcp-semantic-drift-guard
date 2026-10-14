"""
experiments/evaluate_real_corpus_modifications.py - Evaluates 13 Real-World MCP Tool Contract Modifications.

Applies the Adjacent structured-diff judge (Mode B, same prompt and schema as Benchmark V4 Adjacent):
1. Runs local gemma3:4b via MultiJudgeClient (JSON-schema constrained, temperature=0, seed=42).
2. Runs cloud gemini-3.1-flash-lite via MultiJudgeClient (JSON-schema constrained, temperature=0, seed=42).
3. Computes Rule (b) and Rule (a) alert rates with Wilson CIs.
4. Identifies genuine capability additions vs benign refactorings.
"""

import os
import sys
import json
import math
import time
from pathlib import Path
from typing import Dict, List, Any, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Load .env
env_path = ROOT_DIR / ".env"
if env_path.exists():
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip().strip('"').strip("'")

from guard.semantic_judge import (
    build_mode_b_prompt,
    SYSTEM_PROMPT_SECURITY_WRAPPER,
    JUDGE_JSON_SCHEMA
)
from guard.multi_judge_client import MultiJudgeClient

CHANGES_FILE = ROOT_DIR / "data" / "tool_changes.jsonl"
OUT_DIR = ROOT_DIR / "results" / "real_corpus_audit"
OUT_FILE = OUT_DIR / "real_corpus_eval.json"


def wilson_ci(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2.0 * n)) / denom
    half = (z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * n)) / n)) / denom
    return max(0.0, center - half) * 100.0, min(1.0, center + half) * 100.0


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(CHANGES_FILE, "r", encoding="utf-8") as f:
        all_changes = [json.loads(line) for line in f if line.strip()]

    mods = [c for c in all_changes if c.get("change_type") in ("clarification", "new_feature")]
    print(f"Loaded {len(mods)} real contract modifications.")

    # Check for existing Gemini results to avoid redundant quota usage
    existing_gemini = {}
    if OUT_FILE.exists():
        try:
            with open(OUT_FILE, "r", encoding="utf-8") as ef:
                prev_data = json.load(ef)
                for rec in prev_data.get("records", []):
                    if rec.get("gemini_3_1_flash_lite", {}).get("verdict") not in (None, "ERROR", "PARSE_ERROR"):
                        existing_gemini[rec["change_id"]] = rec["gemini_3_1_flash_lite"]
        except Exception:
            pass

    gemma_client = MultiJudgeClient(model_name="gemma3:4b")
    gemini_client = MultiJudgeClient(model_name="gemini-3.1-flash-lite") if len(existing_gemini) < len(mods) else None

    results = []
    for idx, item in enumerate(mods):
        cid = item.get("change_id")
        server = item.get("server_id")
        tool = item.get("tool_name")
        ctype = item.get("change_type")
        sdiff = item.get("structured_diff", {})
        prompt = build_mode_b_prompt(sdiff)

        # 1. Gemma call with constrained JSON Schema
        gemma_res = gemma_client.call_judge(prompt, system_prompt=SYSTEM_PROMPT_SECURITY_WRAPPER)
        g_parsed = gemma_res.get("parsed_verdict", {})
        gemma_verdict = g_parsed.get("label", "PARSE_ERROR") if g_parsed else "PARSE_ERROR"
        gemma_conf = g_parsed.get("confidence", 0.0) if g_parsed else 0.0
        gemma_reason = g_parsed.get("reason", "") if g_parsed else ""
        gemma_lat = gemma_res.get("latency_ms", 0.0)

        # 2. Gemini call (cached or fresh)
        if cid in existing_gemini:
            gem_data = existing_gemini[cid]
            gem_verdict = gem_data.get("verdict")
            gem_conf = gem_data.get("confidence", 0.0)
            gem_reason = gem_data.get("reason", "")
            gem_lat = gem_data.get("latency_ms", 0.0)
        else:
            try:
                gem_res = gemini_client.call_judge(prompt, system_prompt=SYSTEM_PROMPT_SECURITY_WRAPPER)
                gem_parsed = gem_res.get("parsed_verdict", {})
                gem_verdict = gem_parsed.get("label", "PARSE_ERROR") if gem_parsed else "PARSE_ERROR"
                gem_conf = gem_parsed.get("confidence", 0.0) if gem_parsed else 0.0
                gem_reason = gem_parsed.get("reason", "") if gem_parsed else ""
                gem_lat = gem_res.get("latency_ms", 0.0)
                time.sleep(1.0)
            except Exception as e:
                gem_verdict = "ERROR"
                gem_conf = 0.0
                gem_reason = str(e)
                gem_lat = 0.0

        rec = {
            "index": idx + 1,
            "change_id": cid,
            "server_id": server,
            "tool_name": tool,
            "change_type": ctype,
            "structured_diff": sdiff,
            "gemma3_4b": {
                "verdict": gemma_verdict,
                "confidence": gemma_conf,
                "reason": gemma_reason,
                "latency_ms": gemma_lat
            },
            "gemini_3_1_flash_lite": {
                "verdict": gem_verdict,
                "confidence": gem_conf,
                "reason": gem_reason,
                "latency_ms": gem_lat
            }
        }
        results.append(rec)
        print(f"[{idx+1}/13] {tool} ({ctype}): gemma={gemma_verdict}, gemini={gem_verdict}", flush=True)

    N = len(results)
    gemma_b_alerts = [r for r in results if r["gemma3_4b"]["verdict"] in ("MALICIOUS", "SUSPICIOUS")]
    gemma_a_alerts = [r for r in results if r["gemma3_4b"]["verdict"] == "MALICIOUS"]

    gemini_b_alerts = [r for r in results if r["gemini_3_1_flash_lite"]["verdict"] in ("MALICIOUS", "SUSPICIOUS")]
    gemini_a_alerts = [r for r in results if r["gemini_3_1_flash_lite"]["verdict"] == "MALICIOUS"]

    gb_low, gb_high = wilson_ci(len(gemma_b_alerts), N)
    ga_low, ga_high = wilson_ci(len(gemma_a_alerts), N)

    gemb_low, gemb_high = wilson_ci(len(gemini_b_alerts), N)
    gema_low, gema_high = wilson_ci(len(gemini_a_alerts), N)

    summary = {
        "total_modifications": N,
        "gemma3_4b": {
            "rule_b_alerts": len(gemma_b_alerts),
            "rule_b_rate_pct": round(len(gemma_b_alerts) / N * 100, 1),
            "rule_b_ci": [round(gb_low, 1), round(gb_high, 1)],
            "rule_a_alerts": len(gemma_a_alerts),
            "rule_a_rate_pct": round(len(gemma_a_alerts) / N * 100, 1),
            "rule_a_ci": [round(ga_low, 1), round(ga_high, 1)]
        },
        "gemini_3_1_flash_lite": {
            "rule_b_alerts": len(gemini_b_alerts),
            "rule_b_rate_pct": round(len(gemini_b_alerts) / N * 100, 1),
            "rule_b_ci": [round(gemb_low, 1), round(gemb_high, 1)],
            "rule_a_alerts": len(gemini_a_alerts),
            "rule_a_rate_pct": round(len(gemini_a_alerts) / N * 100, 1),
            "rule_a_ci": [round(gema_low, 1), round(gema_high, 1)]
        },
        "records": results
    }

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n--- Real Corpus Evaluation Summary ---", flush=True)
    print(f"Total: {N} real contract modifications", flush=True)
    print(f"gemma3:4b: Rule (b) Alert Rate = {summary['gemma3_4b']['rule_b_rate_pct']}% ({len(gemma_b_alerts)}/{N}) {summary['gemma3_4b']['rule_b_ci']}", flush=True)
    print(f"gemma3:4b: Rule (a) Alert Rate = {summary['gemma3_4b']['rule_a_rate_pct']}% ({len(gemma_a_alerts)}/{N}) {summary['gemma3_4b']['rule_a_ci']}", flush=True)
    print(f"gemini-3.1-flash-lite: Rule (b) Alert Rate = {summary['gemini_3_1_flash_lite']['rule_b_rate_pct']}% ({len(gemini_b_alerts)}/{N}) {summary['gemini_3_1_flash_lite']['rule_b_ci']}", flush=True)
    print(f"gemini-3.1-flash-lite: Rule (a) Alert Rate = {summary['gemini_3_1_flash_lite']['rule_a_rate_pct']}% ({len(gemini_a_alerts)}/{N}) {summary['gemini_3_1_flash_lite']['rule_a_ci']}", flush=True)

    print("\n[ALL 13 MODIFICATIONS EVALUATION TABLE]:", flush=True)
    for r in results:
        print(f"[{r['index']}] Tool: {r['tool_name']} ({r['change_type']}) | Server: {r['server_id']}")
        print(f"    Gemma Verdict: {r['gemma3_4b']['verdict']} | Reason: {r['gemma3_4b']['reason']}")
        print(f"    Gemini Verdict: {r['gemini_3_1_flash_lite']['verdict']} | Reason: {r['gemini_3_1_flash_lite']['reason']}")
        print(f"    Diff: {json.dumps(r['structured_diff'])}")


if __name__ == "__main__":
    main()
