#!/usr/bin/env python3
"""
scripts/check_numbers.py: Recomputes every "x% (n/N)" and Wilson CI in paper.md
using a single round-half-up rule (1 decimal) and unified Wilson score function.

Usage:
    python scripts/check_numbers.py [--file path/to/paper.md]
"""

import sys
import math
import re
from pathlib import Path
from decimal import Decimal, ROUND_HALF_UP
from typing import List, Tuple, Dict, Any


def round_half_up(val: float | Decimal, decimals: int = 1) -> float:
    """Rounds half up to specified decimal places."""
    d = Decimal(str(val))
    fmt = "0." + "0" * decimals if decimals > 0 else "0"
    return float(d.quantize(Decimal(fmt), rounding=ROUND_HALF_UP))


def calc_percentage(n: int, N: int) -> float:
    """Calculates n / N * 100 with round-half-up to 1 decimal place."""
    if N == 0:
        return 0.0
    val = (Decimal(n) * Decimal(100)) / Decimal(N)
    return round_half_up(val, 1)


def wilson_ci(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    """Computes Wilson score confidence interval with round-half-up (1 decimal)."""
    if n == 0:
        return (0.0, 0.0)
    z = 1.95996
    p = k / n
    denom = 1.0 + (z**2) / n
    center = (p + (z**2) / (2 * n)) / denom
    margin = (z * math.sqrt((p * (1 - p) / n) + ((z**2) / (4 * (n**2))))) / denom
    lo = max(0.0, center - margin) * 100
    hi = min(1.0, center + margin) * 100
    return (round_half_up(lo, 1), round_half_up(hi, 1))


def check_paper_numbers(file_path: Path) -> Tuple[int, List[Dict[str, Any]]]:
    """Scans markdown file for percentage and Wilson CI consistency.
    
    Returns:
        (total_checked, list_of_mismatches)
    """
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    pct_pattern = re.compile(r'(\d+(?:\.\d+)?)\s*%\s*[\(\[]\s*(\d+)\s*/\s*(\d+)\s*[\)\]]')
    # Matches (k/N) or [k/N] followed by Wilson CI [lo%, hi%] within the same line / table cell
    ci_pattern = re.compile(r'[\(\[]\s*(\d+)\s*/\s*(\d+)\s*[\)\]][^\[\]\n\r]{0,40}\[\s*(\d+(?:\.\d+)?)\s*%\s*,\s*(\d+(?:\.\d+)?)\s*%\s*\]')

    mismatches = []
    total_checked = 0

    for line_no, line in enumerate(lines, 1):
        # 1. Check percentage matches: x% (n/N)
        for m in pct_pattern.finditer(line):
            total_checked += 1
            observed_pct = float(m.group(1))
            n = int(m.group(2))
            N = int(m.group(3))
            expected_pct = calc_percentage(n, N)
            if abs(observed_pct - expected_pct) > 1e-4:
                mismatches.append({
                    "line": line_no,
                    "type": "percentage",
                    "raw": m.group(0),
                    "n": n,
                    "N": N,
                    "observed": observed_pct,
                    "expected": expected_pct,
                    "line_content": line.strip()
                })

        # 2. Check Wilson CI matches: (k/N) ... [lo%, hi%]
        for m in ci_pattern.finditer(line):
            total_checked += 1
            k = int(m.group(1))
            n = int(m.group(2))
            obs_lo = float(m.group(3))
            obs_hi = float(m.group(4))
            exp_lo, exp_hi = wilson_ci(k, n)
            if abs(obs_lo - exp_lo) > 1e-4 or abs(obs_hi - exp_hi) > 1e-4:
                mismatches.append({
                    "line": line_no,
                    "type": "wilson_ci",
                    "raw": m.group(0),
                    "k": k,
                    "n": n,
                    "observed": (obs_lo, obs_hi),
                    "expected": (exp_lo, exp_hi),
                    "line_content": line.strip()
                })

    return total_checked, mismatches


def check_exposure_bounds(file_path: Path, max_exposure: float = 2.0) -> Tuple[int, List[Dict[str, Any]]]:
    """Validates that every reported Salami mean exposure window lies in [0, max_exposure]."""
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    exp_pattern = re.compile(r'(\d+(?:\.\d+)?)\s*steps')
    we_pattern = re.compile(r'\\bar\{W\}_e\s*=\s*(\d+(?:\.\d+)?)')

    total_checked = 0
    mismatches = []

    for line_no, line in enumerate(lines, 1):
        for m in exp_pattern.finditer(line):
            total_checked += 1
            val = float(m.group(1))
            if val < 0.0 or val > max_exposure:
                mismatches.append({
                    "line": line_no,
                    "type": "exposure_out_of_bounds",
                    "raw": m.group(0),
                    "value": val,
                    "max_allowed": max_exposure,
                    "line_content": line.strip()
                })
        for m in we_pattern.finditer(line):
            total_checked += 1
            val = float(m.group(1))
            if val < 0.0 or val > max_exposure:
                mismatches.append({
                    "line": line_no,
                    "type": "exposure_out_of_bounds",
                    "raw": m.group(0),
                    "value": val,
                    "max_allowed": max_exposure,
                    "line_content": line.strip()
                })

    return total_checked, mismatches


def check_cross_table_consistency(file_path: Path) -> Tuple[int, List[Dict[str, Any]]]:
    """Validates that identical defense configurations report identical values across Tables 6, 7, 8, A.1, A.2, and prose."""
    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()

    # Canonical configurations evaluated on frozen held-out test split (N=58)
    configs = [
        {
            "name": "gemma3:4b Adjacent (Rule b)",
            "expected_recall": "96.2% (25/26)",
            "expected_fpr": "4.0% (1/25)",
            "expected_exp": "0.192",
            "table_regexes": [
                r"^\s*\|\s*\*\*Held-Out Test \(\$?N=58\$?\)\*\*\s*\|\s*\*\*Rule \(b\) Primary BALANCED\*\*\s*\|\s*\*\*Adjacent\*\*\s*\|.*?$",
                r"^\s*\|\s*\*\*Semantic Drift Guard: Adjacent \(Rule b\)\*\*\s*\|\s*Tier 3 Local.*?$",
                r"^\s*\|\s*\*\*Plain Adjacent Guard \(Rule b\)\*\*\s*\|.*?$",
                r"^\s*\|\s*\*\*MCP Semantic Guard \(Adjacent, Rule \(b\) Primary BALANCED\)\*\*\s*\|.*?$",
                r"^\s*\|\s*\*\*gemma3:4b\*\*\s*\(Local 4B\)\s*\|\s*\*\*Rule \(b\) Primary BALANCED\*\*\s*\|\s*\*\*Adjacent\*\*\s*\|.*?$",
            ]
        },
        {
            "name": "gemma3:4b Cumulative (Rule b)",
            "expected_recall": "76.9% (20/26)",
            "expected_fpr": "0.0% (0/25)",
            "expected_exp": "0.731",
            "table_regexes": [
                r"^\s*\|\s*\|\s*\|\s*\*\*Cumulative\*\*\s*\|\s*.*?76\.9%.*?$",
                r"^\s*\|\s*\*\*Semantic Drift Guard: Cumulative \(Rule b\)\*\*\s*\|\s*Tier 3 Local.*?$",
                r"^\s*\|\s*\*\*Plain Cumulative Guard \(Rule b\)\*\*\s*\|.*?$",
                r"^\s*\|\s*\*\*MCP Semantic Guard \(Cumulative, Rule \(b\) Primary BALANCED\)\*\*\s*\|.*?$",
                r"^\s*\|\s*\*\*gemma3:4b\*\*\s*\(Local 4B\)\s*\|\s*\*\*Rule \(b\) Primary BALANCED\*\*\s*\|\s*\*\*Cumulative\*\*\s*\|.*?$",
            ]
        },
        {
            "name": "gemini-3.1-flash-lite Adjacent (Rule b)",
            "expected_recall": "88.5% (23/26)",
            "expected_fpr": "0.0% (0/25)",
            "expected_exp": "0.808",
            "table_regexes": [
                r"^\s*\|\s*\*\*Semantic Drift Guard: Adjacent \(Rule b\)\*\*\s*\|\s*Tier 3 Cloud.*?$",
                r"^\s*\|\s*\*\*gemini-3\.1-flash-lite\*\*\s*\(Lite-tier Cloud\)\s*\|\s*\*\*Rule \(b\) Primary BALANCED\*\*\s*\|\s*\*\*Adjacent\*\*\s*\|.*?$",
            ]
        },
        {
            "name": "gemini-3.1-flash-lite Cumulative (Rule b)",
            "expected_recall": "84.6% (22/26)",
            "expected_fpr": "0.0% (0/25)",
            "expected_exp": "0.769",
            "table_regexes": [
                r"^\s*\|\s*\*\*Semantic Drift Guard: Cumulative \(Rule b\)\*\*\s*\|\s*Tier 3 Cloud.*?$",
                r"^\s*\|\s*\*\*gemini-3\.1-flash-lite\*\*\s*\(Lite-tier Cloud\)\s*\|\s*\*\*Rule \(b\) Primary BALANCED\*\*\s*\|\s*\*\*Cumulative\*\*\s*\|.*?$",
            ]
        },
        {
            "name": "Exact Cryptographic Hash Pinning",
            "expected_recall": "100.0% (26/26)",
            "expected_fpr": "100.0% (25/25)",
            "expected_exp": "0.000",
            "table_regexes": [
                r"^\s*\|\s*\*\*Exact Cryptographic Hash Pinning\*\*\s*\|\s*Tier 0 Deterministic.*?$",
                r"^\s*\|\s*\*\*Exact Hash Pinning \(Tier 0\)\*\*\s*\|\s*100\.0% \(26/26\).*?$",
            ]
        },
        {
            "name": "Parameter Count Delta (Thresh >= 4)",
            "expected_recall": "76.9% (20/26)",
            "expected_fpr": "44.0% (11/25)",
            "expected_exp": "1.231",
            "table_regexes": [
                r"^\s*\|\s*\*\*Parameter Count Delta \(Thresh >= 4\)\*\*\s*\|\s*Tier 1\.5 Deterministic.*?$",
                r"^\s*\|\s*\*\*Parameter Count Delta \(Calibrated Dev Target=50\.0%, Thresh >= 4.*?$",
            ]
        },
        {
            "name": "Normalized Edit Distance (Thresh >= 0.7369)",
            "expected_recall": "0.0% (0/26)",
            "expected_fpr": "0.0% (0/25)",
            "expected_exp": "2.000",
            "table_regexes": [
                r"^\s*\|\s*\*\*Normalized Edit Distance \(Thresh >= 0\.7369\)\*\*\s*\|\s*Tier 1 Lexical.*?$",
                r"^\s*\|\s*\*\*Normalized Edit Distance \(Calibrated Dev Target=0\.0%, Thresh >= 0\.7369.*?$",
            ]
        },
        {
            "name": "TF-IDF Cosine Distance (Thresh >= 0.6569)",
            "expected_recall": "3.8% (1/26)",
            "expected_fpr": "4.0% (1/25)",
            "expected_exp": "1.962",
            "table_regexes": [
                r"^\s*\|\s*\*\*TF-IDF Cosine Distance \(Thresh >= 0\.6569\)\*\*\s*\|\s*Tier 1 Statistical.*?$",
                r"^\s*\|\s*\*\*TF-IDF Distance \(Calibrated Dev Target=0\.0%, Thresh >= 0\.6569.*?$",
            ]
        }
    ]

    total_checked = 0
    mismatches = []

    for cfg in configs:
        for pat in cfg["table_regexes"]:
            total_checked += 1
            m = re.search(pat, text, re.MULTILINE)
            if not m:
                mismatches.append({
                    "config": cfg["name"],
                    "pattern": pat,
                    "error": "Table row pattern not found in paper.md"
                })
                continue
            row_str = m.group(0)
            row_clean = row_str.replace("**", "")
            if cfg["expected_recall"] not in row_clean:
                mismatches.append({
                    "config": cfg["name"],
                    "expected_recall": cfg["expected_recall"],
                    "found_in_row": row_str,
                    "error": f"Recall mismatch: expected {cfg['expected_recall']}"
                })
            if cfg["expected_fpr"] not in row_clean:
                mismatches.append({
                    "config": cfg["name"],
                    "expected_fpr": cfg["expected_fpr"],
                    "found_in_row": row_str,
                    "error": f"FPR mismatch: expected {cfg['expected_fpr']}"
                })
            if cfg["expected_exp"] not in row_clean:
                mismatches.append({
                    "config": cfg["name"],
                    "expected_exp": cfg["expected_exp"],
                    "found_in_row": row_str,
                    "error": f"Exposure mismatch: expected {cfg['expected_exp']}"
                })

    return total_checked, mismatches


def check_table_order_and_references(file_path: Path) -> Tuple[int, List[Dict[str, Any]]]:
    """Validates that:
    1. All declared tables (captions '*Table N: ...*' or '### Table N: ...') are strictly sequential.
       Main tables: 1, 2, ..., N (strictly increasing integer sequence).
       Appendix tables: A.1, A.2, ..., A.M (strictly increasing appendix sequence).
       No letter suffixes or out-of-order tables.
    2. Every Table N referenced in prose exists in the declared tables.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()

    errors = []
    
    # 1. Declared tables
    declared = []
    for line_num, line in enumerate(text.splitlines(), start=1):
        m = re.search(r'(?:^\*\s*|###\s*)Table\s+([0-9]+[a-z]?|A\.[0-9]+):', line)
        if m:
            declared.append((m.group(1), line_num))

    # Validate ordering
    main_tables = []
    app_tables = []
    for tid, line_num in declared:
        if tid.startswith("A."):
            app_tables.append((tid, line_num))
        else:
            main_tables.append((tid, line_num))

    # Check main tables sequential
    expected_main = 1
    for tid, line_num in main_tables:
        if not tid.isdigit():
            errors.append({
                "type": "table_naming",
                "table": tid,
                "line": line_num,
                "error": f"Main table '{tid}' has non-integer suffix (not allowed; tables must be strictly sequential integers)."
            })
        else:
            val = int(tid)
            if val != expected_main:
                errors.append({
                    "type": "table_order",
                    "table": tid,
                    "line": line_num,
                    "error": f"Table order mismatch: expected Table {expected_main}, but found Table {tid}."
                })
            expected_main = val + 1

    # Check appendix tables sequential
    expected_app = 1
    for tid, line_num in app_tables:
        sub = tid.split(".")[1]
        if not sub.isdigit():
            errors.append({
                "type": "appendix_table_naming",
                "table": tid,
                "line": line_num,
                "error": f"Appendix table '{tid}' is invalid."
            })
        else:
            val = int(sub)
            if val != expected_app:
                errors.append({
                    "type": "appendix_table_order",
                    "table": tid,
                    "line": line_num,
                    "error": f"Appendix table order mismatch: expected Table A.{expected_app}, but found Table {tid}."
                })
            expected_app = val + 1

    # 2. Check all referenced tables exist
    declared_set = {tid for tid, _ in declared}
    refs = set(re.findall(r'Table\s+([0-9]+[a-z]?|A\.[0-9]+)', text))
    for r in refs:
        if r not in declared_set:
            errors.append({
                "type": "missing_table",
                "table": r,
                "error": f"Referenced Table {r} does not exist in declared tables."
            })

    total_checked = len(declared) + len(refs)
    return total_checked, errors


def main():
    target = Path("paper.md")
    if len(sys.argv) > 1 and sys.argv[1] == "--file" and len(sys.argv) > 2:
        target = Path(sys.argv[2])
    elif len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        target = Path(sys.argv[1])

    if not target.exists():
        print(f"Error: Target file {target} does not exist.")
        sys.exit(1)

    print(f"Checking numerical consistency in: {target}")
    total_checked, mismatches = check_paper_numbers(target)
    print(f"Total checked expressions: {total_checked}")

    exp_checked, exp_mismatches = check_exposure_bounds(target)
    print(f"Total checked exposure windows: {exp_checked}")

    cross_checked, cross_mismatches = check_cross_table_consistency(target)
    print(f"Total cross-table checks: {cross_checked}")

    tbl_checked, tbl_errors = check_table_order_and_references(target)
    print(f"Total table order and reference checks: {tbl_checked}")

    all_errors = mismatches + exp_mismatches + cross_mismatches + tbl_errors

    if all_errors:
        print(f"\n[FAIL] Found {len(all_errors)} consistency errors:")
        for m in all_errors:
            print(f"  {m}")
        sys.exit(1)
    else:
        print("[PASS] All percentages, Wilson CIs, exposure windows, and cross-table configurations are consistent!")
        sys.exit(0)


if __name__ == "__main__":
    main()

