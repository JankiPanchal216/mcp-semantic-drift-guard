# Audit of Remaining Risky Claims across Repository Artifacts

## 1. Executive Summary & Audit Scope

This document records the global repository scan for uncalibrated, unhedged, or risky phrasing (e.g., "100% accurate", "zero false negatives", "production ready", "no prior work", "guarantees").

Per Rule 3 & Rule 14, **historical Phase 1–6 files remain strictly preserved for reproducibility**, while all **Reviewer Upgrade artifacts (`_REVIEWER_READY`) have corrected these expressions**.

---

## 2. Scan Findings & Disposition Table

| Search Pattern | Found File(s) & Line | Original Phrase in Historical Artifact | Status in Upgraded Reviewer Artifacts |
|---|---|---|---|
| **"no prior work"** | `results/FINAL_RESEARCH_REPORT.md:26` | *"No prior work has characterized..."* | **CORRECTED**: Section 4 of `FINAL_RESEARCH_REPORT_REVIEWER_READY.md` cites and analyzes MCPTox (2024), ToolHijack (2024), and Sigstore (2022). |
| **"production ready"** | `results/FINAL_RESULTS_SUMMARY.md:14` | *"Fully production ready"* | **CORRECTED**: Abstract and Section 11 of `FINAL_RESEARCH_REPORT_REVIEWER_READY.md` explicitly label the system as a research prototype and detail CPU latency limitations (~1.42s). |
| **"zero false negatives"** | `results/PROMPT_SENSITIVITY.md:51` | *"zero false negatives"* | **CONTEXTUALIZED**: Explicitly bounded to the evaluated sample: `(0/12 misses in sample, 95% Wilson CI: [0.0%, 24.1%])`. |
| **"eliminates attacks"** | `results/FINAL_RESULTS_SUMMARY.md:8` | *"Eliminates 100% of tool poisoning"* | **CORRECTED**: Replaced with exact empirical recall: `33/33 detected in Phase 5 held-out test split (95% CI: [89.4%, 100.0%])`. |
| **"100% accurate"** | `results/PHASE5_RESULTS.md:9` | *"Precision = 100%, Recall = 100%, F1 = 100%"* | **CORRECTED**: Reconciled in `PHASE5_VS_REVIEWER_UPGRADE_RECONCILIATION.md` and conservatively reported as `F1 = 92.3%` in main reviewer comparison. |

---

## 3. Conclusion

All active reviewer-facing artifacts adhere strictly to conservative, evidence-backed scientific phrasing with explicit sample sizes and confidence intervals.
