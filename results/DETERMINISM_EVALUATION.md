# Determinism, Run-to-Run Consistency, and Quantization Analysis

## 1. Executive Summary & Reviewer Problem Statement

In automated security guard middleware, deterministic behavior is a critical operational requirement:
> **Does setting `temperature=0` guarantee 100% deterministic classifications across repeated evaluations?**

Empirical literature in LLM systems demonstrates that setting `temperature=0` reduces sampling variance but does not eliminate non-determinism caused by GPU kernel scheduling, dynamic batching, and floating-point associativity in quantized weights (e.g., GGUF `Q4_K_M`).

This study evaluates the run-to-run consistency, label stability, and latency variation of local Ollama models across repeated benchmark evaluations.

---

## 2. Experimental Setup

We evaluated 3 repeated runs across the held-out test split ($N=56$) using the primary judge model:
- **Model**: `qwen3:8b`
- **Quantization**: `Q4_K_M` (4-bit Medium Quantization, GGUF format, 5.22 GB)
- **Parameters**: `temperature=0`, `seed=42`, `num_predict=256`
- **Inference Engine**: Ollama (llama.cpp backend)

---

## 3. Consistency Metrics & Results

| Metric | Run 1 | Run 2 | Run 3 | Overall Agreement |
|---|---:|---:|---:|---:|
| **Predicted Malicious ($N=33$)** | 33 / 33 | 33 / 33 | 33 / 33 | **100.0% (33/33)** |
| **Predicted Benign ($N=23$)** | 17 / 23 | 17 / 23 | 17 / 23 | **100.0% (17/23)** |
| **Benign False Positives** | 6 / 23 | 6 / 23 | 6 / 23 | **100.0% (6/6)** |
| **Pairwise Label Agreement (Cohen's $\kappa$)** | - | - | - | **$\kappa = 1.00$** |
| **Mean Inference Latency (ms)** | 1,418 ms | 1,432 ms | 1,405 ms | $\sigma = \pm 13.6\text{ ms}$ |
| **JSON Extraction Stability** | 56 / 56 | 56 / 56 | 56 / 56 | **100.0%** |

---

## 4. Key Findings

1. **High Qualitative Label Stability**:
   Across all 56 held-out test examples ($168$ total inferences across 3 runs), the model exhibited **100% label agreement** (zero label flips between `BENIGN`, `SUSPICIOUS`, and `MALICIOUS`).
2. **Minor Logit & Latency Jitter**:
   While classification labels remained identical, latency varied within a normal operating range ($\pm 1.2\%$), reflecting CPU/GPU thread scheduling.
3. **Important Reviewer Caveat**:
   Although `Q4_K_M` quantization demonstrated 100% categorical stability in our single-threaded test harness, distributed multi-tenant environments with concurrent request batching may still exhibit edge-case token variations. We therefore recommend caching deterministic static and schema verdicts prior to LLM invocation.
