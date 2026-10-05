# Reconciliation: Phase 5 Integrated Middleware vs. Standalone Semantic-Judge Results

## 1. Executive Summary

This document clarifies and reconciles the two evaluated configurations reported across the research package:

### 1. Integrated Middleware Result (Original Phase 5 Evaluation)
- **Sample**: $N=56$ held-out test split (`data/drift_test.jsonl`)
- **Metrics**: TP = 33, TN = 23, FP = 0, FN = 0
- **Precision**: 100.0%
- **Recall**: 100.0%
- **F1 Score**: 100.0%
- **Benign FPR**: 0.0% (0/23)
- **Configuration**: Full integrated middleware pipeline (`guard/middleware.py`) operating under the `BALANCED` policy with pre-populated trusted baselines, deterministic static/schema pre-filters, and policy thresholds.

### 2. Standalone Semantic-Judge Result (Reviewer-Upgrade Evaluation)
- **Sample**: $N=56$ held-out test split (`data/drift_test.jsonl`)
- **Metrics**: TP = 33, TN = 17, FP = 6, FN = 0
- **Precision**: 85.7% (33/39)
- **Recall**: 100.0% (33/33)
- **F1 Score**: 92.3%
- **Benign FPR**: 26.1% (6/23)
- **Configuration**: Standalone Mode-B semantic judge evaluation isolating LLM semantic classification behavior on structured diffs without upstream deterministic filtering or end-to-end middleware state context.

> [!IMPORTANT]
> **Key Methodological Principle**: Neither result replaces or contradicts the other; they evaluate different layers and configurations. The integrated middleware benefits from deterministic tiers, policy handling, and baseline context, whereas the standalone semantic judge isolates semantic classification behavior.
> - Do not use the 100% integrated result to claim that the semantic judge itself has 100% F1.
> - Do not use the 92.3% standalone judge result to imply that the integrated middleware achieved only 92.3% in the original Phase 5 evaluation.

---

## 2. Methodology & Configuration Comparison

| Dimension | Integrated Middleware Evaluation (Phase 5) | Standalone Semantic Judge Evaluation (Reviewer Upgrade) |
|---|---|---|
| **Test Dataset File** | `data/drift_test.jsonl` ($N=56$) | `data/drift_test.jsonl` ($N=56$) |
| **Dataset Breakdown** | 33 Malicious, 23 Benign (11 additions, 4 removals, 8 modifications) | 33 Malicious, 23 Benign (11 additions, 4 removals, 8 modifications) |
| **Evaluated Layer** | Full Integrated Middleware Pipeline (`guard/middleware.py`) | Standalone Tier 3 Semantic Judge (Mode B Diff Only) |
| **Baseline Context** | Pre-populated trusted baseline store with historical V1 contracts | Isolated canonical field-level diffs per test case |
| **Deterministic Tiers** | Active upstream (Tier 0 Hash, Tier 1 Static Regex, Tier 1.5 Schema) | Bypassed / Isolated (Direct prompt evaluation) |
| **Policy Enforcement** | `BALANCED` middleware policy (allows benign maintenance, blocks high risk) | Direct discrete output parsing (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`) |
| **LLM Model & Engine** | Local Ollama `qwen3:8b` (Q4_K_M, temperature=0) | Local Ollama `qwen3:8b` (Q4_K_M, temperature=0) |
| **Reported Metric Focus** | End-to-end system effectiveness with trusted baselines | Isolated semantic classification robustness and conservative error profile |

---

## 3. Detailed Root Cause Analysis

### A. Malicious Attack Detections (33/33 Caught in Both Configurations)
In both the integrated middleware and standalone semantic judge configurations, **all 33 malicious attacks were detected** (33/33 TP, 0 FN, Recall = 100.0% [95% CI: 89.4%, 100.0%]):
- In the integrated middleware: 25 attacks were intercepted by upstream Tier 1 Static Regex Rules in $< 0.05\text{ ms}$, and 8 attacks were detected by Tier 3 Semantic Judge.
- In the standalone semantic judge: All 33 attacks presented as diffs were correctly classified as security threats by the LLM judge.

### B. Benign Maintenance Evaluations (23 Examples)
- **Integrated Middleware Pipeline**: Under the full `BALANCED` middleware policy with pre-populated trusted baselines, all 23 benign items (11 tool additions, 4 tool removals, and 8 docstring clarifications) were resolved as `ALLOW` / `BENIGN` without false alarms (0/23 FP, Benign FPR = 0.0%).
- **Standalone Semantic Judge**: When isolating the semantic judge on raw text diffs without repository context, 6 of the 23 benign refactoring diffs (e.g., changes mentioning security bug fixes or argument restructuring) triggered conservative suspicion from the standalone model, resulting in 6 False Positives (FPR = 26.1%).

---

## 4. Scientific Reporting Protocol

1. **When reporting end-to-end system capability**:
   - Report the **Integrated Middleware Result**: 100.0% precision, 100.0% recall, 100.0% F1, 0.0% benign FPR on the evaluated held-out test split ($N=56$).
   - Explicitly qualify that this performance reflects the multi-tiered pipeline with pre-populated trusted baselines and deterministic pre-filters.

2. **When reporting isolated semantic reasoning capability**:
   - Report the **Standalone Semantic-Judge Result**: 85.7% precision, 100.0% recall, 92.3% F1, 26.1% benign FPR on $N=56$.
   - Explicitly qualify that this metric isolates Mode-B semantic classification on text diffs.

3. **When reporting server-level generalization**:
   - Report the **5-Fold Server-Grouped Cross-Validation Result**: 89.7% ± 6.2% F1, 100.0% ± 0.0% recall, 23.0% ± 4.1% benign FPR across 370 examples partitioned by server cluster (where ± denotes standard deviation across the 5 folds).

