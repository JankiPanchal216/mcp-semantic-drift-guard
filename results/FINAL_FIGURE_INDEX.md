# Master Figure & Visualization Index

## 1. Overview

This document catalogs all empirical visualizations generated across the experimental lifecycle of the MCP Semantic Drift Detection project.

---

## 2. Master Figure Catalog

| Figure File Path | Phase Origin | Description & Content | Placement in Final Research Report |
|---|---|---|---|
| `results/figures/change_types_distribution.png` | **Phase 2** | Bar chart showing the breakdown of 123 tool evolution events across 4 categories (tool addition: 51.2%, tool removal: 38.2%, clarification: 8.9%, new feature: 1.6%). | **Section 5.2 (Real MCP Update Corpus)** |
| `results/figures/release_change_rates.png` | **Phase 2** | Bar plot comparing overall definition-change rate (2.48%), release-change rate (4.99%), description-change rate (1.13%), and schema-change rate (0.32%) across 621 release transitions. | **Section 5.2 (Real MCP Update Corpus)** |
| `results/figures/changes_by_server.png` | **Phase 2** | Horizontal bar chart displaying tool definition change counts per MCP server across the 25 surveyed open-source repositories. | **Section 5.2 (Real MCP Update Corpus)** |
| `results/figures/phase3_detector_comparison.png` | **Phase 3** | Bar chart comparing Precision, Recall, and $F_1$ scores across Exact Hash (75.0%), Static Rules (66.7%), Semantic Full (83.3%), Semantic Diff Only (92.3%), and Hybrid (83.3%). | **Section 8.3 (Phase 3 Exploratory Results)** |
| `results/figures/phase3_benign_fpr.png` | **Phase 3** | False Positive Rate comparison demonstrating reduction from Hash Pinning (100.0%) down to Semantic Diff Only (25.0%) on benign maintenance updates. | **Section 8.3 (Phase 3 Exploratory Results)** |
| `results/figures/phase3_full_vs_diff_ablation.png` | **Phase 3** | Grouped bar chart comparing Mode A (Full Definition) vs. Mode B (Structured Diff Only) on F1 score (83.3% vs. 92.3%) and JSON parsing error rate (20.0% vs. 0.0%). | **Section 8.3 (Phase 3 Exploratory Results)** |
| `results/figures/phase3_detection_by_paradigm.png` | **Phase 3** | Detection rates across MCPTox attack paradigms (Direct Injection, Prerequisite Attacks, Argument Tampering) comparing Static Rules vs. Semantic Judge. | **Section 8.3 (Phase 3 Exploratory Results)** |
| `results/figures/phase3_detection_by_mutation.png` | **Phase 3** | Detection rates across 5 systematic attack mutation categories (appended, replaced, prerequisite, argument, subtle paraphrase). | **Section 8.3 (Phase 3 Exploratory Results)** |
| `results/figures/phase3_confusion_matrix.png` | **Phase 3** | Visual confusion matrices for Exact Hash Pinning, Static Rules, and Semantic Judge (Mode B). | **Section 8.3 (Phase 3 Exploratory Results)** |
| `results/figures/phase5/phase5_f1_comparison.png` | **Phase 5** | Master benchmark $F_1$ score comparison across the full N=56 held-out test split: Exact Hash (74.2%), Static Rules (86.2%), and Guard Middleware (100.0%). | **Section 8.5 (Phase 5 Benchmark Results)** |
| `results/figures/phase5/phase5_benign_fpr_comparison.png` | **Phase 5** | Master Benign False Positive Rate (FPR) comparison on the N=56 held-out test split: Exact Hash (100.0%), Static Rules (0.0%), and Guard Middleware (0.0%). | **Section 8.5 (Phase 5 Benchmark Results)** |
| `results/figures/phase5/phase5_redteam_evasion_rates.png` | **Phase 5** | Bar chart displaying Guard Middleware detection rates across 10 adversarial red-team evasion categories (N=30 total cases). | **Section 9 (Red-Team Evaluation)** |
