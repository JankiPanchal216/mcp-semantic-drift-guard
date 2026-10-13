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

    if mismatches:
        print(f"\n[FAIL] Found {len(mismatches)} numerical mismatches:")
        for m in mismatches:
            if m["type"] == "percentage":
                print(f"  Line {m['line']}: {m['raw']} -> Observed {m['observed']}%, Expected {m['expected']}% ({m['n']}/{m['N']})")
            else:
                print(f"  Line {m['line']}: {m['raw']} -> Observed [{m['observed'][0]}%, {m['observed'][1]}%], Expected [{m['expected'][0]}%, {m['expected'][1]}%] for ({m['k']}/{m['n']})")
        sys.exit(1)
    else:
        print("[PASS] All percentages and Wilson CIs are numerically consistent!")
        sys.exit(0)


if __name__ == "__main__":
    main()
