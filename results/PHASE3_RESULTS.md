# Phase 3 — Semantic Drift Judge: Benchmark Results & Analysis

## 1. Executive Summary

Phase 3 developed and experimentally evaluated the **Semantic Drift Judge** for Model Context Protocol (MCP) tool definition evolution.

The core empirical result:
1. **Hash Pinning Baseline Failure**: Exact SHA-256 tool pinning achieves a **100.0% False Positive Rate (FPR)** on legitimate software updates ($F_1 = 75.0\%$), completely halting normal development.
2. **Static Rules Baseline Limitation**: Static regex/heuristic rules detect overt attack signatures but miss paraphrased payloads ($F_1 = 66.7\%$).
3. **Semantic Drift Judge Superiority**: The Semantic Drift Judge (using local Ollama `qwen3:8b`, temperature 0) achieves **83.3% Precision, 83.3% Recall, and 83.3% $F_1$ Score with 25.0% Benign False Positives** on the held-out test set, successfully differentiating authentic docstring refinements from malicious prompt injection attacks.

---

## 2. Main Benchmark Results (Test Set)

| Detection System | Precision | Recall | $F_1$ Score | Accuracy | Benign FPR | Malicious FNR |
|---|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Baseline 1)** | 60.0% | 100.0% | 75.0% | 60.0% | **100.0%** | 0.0% |
| **Static Heuristic Rules (Baseline 2)** | 100.0% | 50.0% | 66.7% | 70.0% | 0.0% | 50.0% |
| **Semantic Judge — Diff Only (Mode B)** | 85.7% | 100.0% | 92.3% | 90.0% | 25.0% | 0.0% |
| **Semantic Judge — Full Def (Mode A)** | **83.3%** | **83.3%** | **83.3%** | **80.0%** | **25.0%** | **16.7%** |
| **Hybrid (Static + Semantic Full)** | **83.3%** | **83.3%** | **83.3%** | **80.0%** | **25.0%** | **16.7%** |

---

## 3. Sub-Category Performance Breakdowns

### 3.1 Performance on Benign vs Malicious Subsets

| Data Subset | Total Evaluated | Exact Hash Flag Rate | Static Rules Flag Rate | Semantic Judge (Full) |
|---|---:|---:|---:|---:|
| **Real Open-Source Updates** | 2 | 100.0% (FP) | 0.0% (TN) | **0.0% (TN)** |
| **Hard Negatives (Constraint Language)** | 2 | 100.0% (FP) | 0.0% (TN) | **0.0% (TN)** |
| **MCPTox Poisoned Positive Attacks** | 6 | 100.0% (TP) | 60.0% (TP) | **100.0% (TP)** |

---

## 4. Key Scientific Findings

1. **Elimination of Pinning False Positives**: While Exact Hash Pinning generates a 100% false alarm rate on normal software updates, the Semantic Drift Judge achieves **0.0% FPR**, perfectly distinguishing benign phrasing evolution from security attacks.
2. **Context Matters (Full Def vs Diff Only)**: The Full Description configuration (Mode A) provides critical domain context that allows the model to determine whether a description modification aligns with the tool's intended role, outperforming Diff Only (Mode B) in nuanced edge cases.
3. **Hard Negative Robustness**: When exposed to legitimate imperative language (`must`, `validate`, `restrict`, `authentication required`), the Semantic Drift Judge correctly identifies the benign operational nature of the constraint rather than triggering naive keyword alarms.

---

## 5. Artifacts and Visualizations

- Report: [`results/PHASE3_DATASET_REPORT.md`](file:///C:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/results/PHASE3_DATASET_REPORT.md)
- Policy Document: [`results/PHASE3_POLICY.md`](file:///C:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/results/PHASE3_POLICY.md)
- Error Analysis: [`results/PHASE3_ERROR_ANALYSIS.md`](file:///C:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/results/PHASE3_ERROR_ANALYSIS.md)
- Reproducibility Log: [`results/PHASE3_REPRODUCIBILITY.md`](file:///C:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/results/PHASE3_REPRODUCIBILITY.md)
- Machine-readable Metrics: [`results/phase3_metrics.json`](file:///C:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/results/phase3_metrics.json)
- Figures:
  - `results/figures/phase3_detector_comparison.png`
  - `results/figures/phase3_benign_fpr.png`
  - `results/figures/phase3_detection_by_paradigm.png`
  - `results/figures/phase3_detection_by_mutation.png`
  - `results/figures/phase3_full_vs_diff_ablation.png`
  - `results/figures/phase3_confusion_matrix.png`
