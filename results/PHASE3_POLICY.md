# Phase 3 — Semantic Drift Judge Policy Selection & Dev Set Calibration

## 1. Development Set Objectives
The development set (`data/drift_dev.jsonl`) was used to calibrate the decision threshold and operational policy without exposing the test set.

## 2. Dev Set Results Summary

| Detector | Precision | Recall | F1 Score | Benign FPR | Malicious FNR |
|---|---:|---:|---:|---:|---:|
| **Exact Hash Pinning** | 50.0% | 100.0% | 66.7% | 100.0% | 0.0% |
| **Static Rules** | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| **Semantic Judge (Diff Only)** | 75.0% | 100.0% | 85.7% | 33.3% | 0.0% |
| **Semantic Judge (Full Def)** | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| **Hybrid (Static + Semantic)** | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |

## 3. Operational Policy Selection

**Selected Primary Policy**: `Semantic Judge (Full Def)` with a **Zero-Tolerance Flagging Rule**:
$$\text{Verdict} = \begin{cases} \text{MALICIOUS / SUSPICIOUS} \rightarrow \text{BLOCK / ESCALATE} \\ \text{BENIGN} \rightarrow \text{ALLOW} \end{cases}$$

**Rationale**:
1. Zero benign false alarms ($0.0\%$ FPR) on real-world updates, eliminating the 100% false positive penalty of exact hash pinning.
2. High precision and recall against complex prompt injection and prerequisite tampering payloads.
