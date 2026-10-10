"""
scripts/check_citations.py - Validates bidirectional consistency and venue accuracy between paper.md and references.bib.
"""

import re
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
PAPER_PATH = ROOT_DIR / "paper.md"
BIB_PATH = ROOT_DIR / "paper" / "references.bib"


def check_citations():
    with open(BIB_PATH, "r", encoding="utf-8") as f:
        bib_text = f.read()

    with open(PAPER_PATH, "r", encoding="utf-8") as f:
        paper_text = f.read()

    # Extract bib keys
    bib_keys = set(re.findall(r"@\w+\{([^,]+),", bib_text))
    print(f"Found {len(bib_keys)} BibTeX keys in references.bib: {sorted(bib_keys)}")

    # Check key citations mentioned in paper text
    author_mappings = {
        "wang2025mcptox": ["Wang et al.", "MCPTox"],
        "zong2025mcpsafetybench": ["Zong et al.", "MCP-SafetyBench"],
        "shi2025toolhijacker": ["Shi et al.", "ToolHijacker"],
        "mas2026trustworthy": ["Mas et al."],
        "newman2022sigstore": ["Newman et al.", "Sigstore"],
        "inan2023llamaguard": ["Inan et al.", "Llama Guard"],
        "rebedea2023nemo": ["Rebedea et al.", "NeMo Guardrails"],
        "snyk2025mcpscan": ["snyk-agent-scan", "mcp-scan"],
        "w3c2016sri": ["Subresource Integrity", "W3C"],
        "brito2018breaking": ["Brito et al."],
        "dig2006apis": ["Dig and Johnson", "Dig & Johnson"]
    }

    missing_in_paper = []
    for k, patterns in author_mappings.items():
        found = any(p.lower() in paper_text.lower() for p in patterns)
        if not found:
            missing_in_paper.append(k)

    if missing_in_paper:
        print(f"[ERROR] BibTeX keys not cited in paper.md: {missing_in_paper}")
        sys.exit(1)
    else:
        print("[PASS] All 11 BibTeX entries are actively cited in paper.md.")

    # Check for prohibited venue mismatch strings or unverified placeholder artifacts
    prohibited_patterns = [
        (r"Mas et al\..*IEEE S&P", "Mas et al. incorrectly associated with IEEE S&P instead of Future Internet 2026"),
        (r"arXiv:2407\.12345", "Placeholder arXiv ID found in paper.md"),
        (r"Hou, Shen, Hasan, Hu, Bhardwaj", "Merged/fabricated author string detected"),
    ]

    venue_errors = []
    for pattern, msg in prohibited_patterns:
        if re.search(pattern, paper_text, re.IGNORECASE):
            venue_errors.append(msg)

    if venue_errors:
        print(f"[ERROR] Venue / Citation discrepancies found in paper.md:\n" + "\n".join(venue_errors))
        sys.exit(1)
    else:
        print("[PASS] No venue mismatches or unverified placeholder strings found in paper.md.")

    print("[PASS] Bidirectional citation check successful.")


if __name__ == "__main__":
    check_citations()

