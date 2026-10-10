# Salami Drift Benchmark V4: Formal Validation Report

**Generation Date:** 2026-10-09T06:59:30Z  
**Generator Version:** 4.0.0  
**Benchmark Version:** v4  
**Dataset Path:** `data/salami_drift_benchmark_v4.jsonl`  
**Dataset SHA-256:** `91f1d0de6f7673731c34967e3f5c77504e598b49fd6cc4807ef6209ddd4faebe`  
**Overall Validation Status:** **`VALIDATED_FOR_INFERENCE`**

---

## 1. Quality Gate Decision Table

| Gate ID | Quality Gate Description | Status | Violations |
|:---:|---|:---:|:---:|
| **G1** | Adjacent-Smallness Test | PASS | 0 |
| **G2** | Monotonic / Structural Validity Test | PASS | 0 |
| **G3** | No Single-Step Capability Leap in Semantic Categories | PASS | 0 |
| **G4** | Deterministic Static Rule Leakage Test (0 leakage in semantic categories) | PASS | 0 |
| **G5** | Deterministic Schema Security Leakage Test (0 leakage in semantic categories) | PASS | 0 |
| **G6** | Gold-Label Leakage Test (Zero leakage in model-facing definitions) | PASS | 0 |
| **G7** | Schema Validity Test (Draft-07 JSON Schema verification) | PASS | 0 |
| **G8** | Step Ordering & Lineage Integrity Test | PASS | 0 |
| **G9** | Benign Control Balance & Diversity Test | PASS | 0 |
| **G10** | Trivial Separator Check (AUC < 0.65 for Length, Param Delta, Levenshtein) | PASS | 0 |

---

## 2. Dataset Composition & Split Distribution

- **Total Trajectory Chains:** 116
  - Malicious Chains: 72 (60 Salami Drift + 12 Fast Jump Controls)
  - Benign Control Chains: 44 (20 Long Drift + 16 Standard Evolution + 8 Docstring Refactor)
- **Total Transitions:** 436
  - Malicious Transitions: 132
  - Benign Transitions: 304
- **Server-Disjoint Partition:**
  - Calibration Split (Train/Dev): 58 chains
  - Held-Out Test Split: 58 chains

---

## 3. Trivial Separator AUC Metrics (Gate G10)

- **Chain Length (Step Count) AUC:** `0.6029` (Target: < 0.65)
- **Cumulative Parameter Delta AUC:** `0.6098` (Target: < 0.65)
- **Cumulative Levenshtein Edit Distance AUC:** `0.5562` (Target: < 0.65)

---

## 4. Final Verdict

**OVERALL STATUS:** **`VALIDATED_FOR_INFERENCE`**
