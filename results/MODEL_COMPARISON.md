# Multi-Model Comparison: Local Judge Architectures

## 1. Experimental Setup & Model Matrix

To determine the sensitivity of semantic drift detection to underlying LLM judge capacity and latency, we evaluate three local open-weight models available in Ollama across the held-out test benchmark ($N=56$):

| Model Identifier | Parameter Count | Quantization Format | Context Window Size | Family / Architecture | File Size on Disk |
|---|---|---|---|---|---|
| **`qwen3:8b`** (Primary) | 8.2 Billion | `Q4_K_M` (GGUF) | 40,960 tokens | Qwen3-Instruct | 5.22 GB |
| **`qwen2.5:1.5b`** (Lightweight) | 1.5 Billion | `Q4_K_M` (GGUF) | 32,768 tokens | Qwen2.5-Instruct | 0.98 GB |
| **`gemma3:4b`** (Midweight) | 4.3 Billion | `Q4_K_M` (GGUF) | 131,072 tokens | Gemma3-IT | 3.34 GB |

All evaluations used: `temperature=0.0`, `seed=42`, `num_predict=256`, Mode B Diff-Only prompts, and strict JSON parsing.

---

## 2. Benchmark Performance Comparison ($N=56$)

| Evaluation Metric | `qwen3:8b` (Primary) | `gemma3:4b` (Midweight) | `qwen2.5:1.5b` (Lightweight) |
|---|---:|---:|---:|
| **Precision** | **85.7%** (33/39) [72.8%, 94.1%] | 81.6% (31/38) [66.7%, 91.0%] | 68.8% (33/48) [54.7%, 80.1%] |
| **Recall** | **100.0%** (33/33) [89.4%, 100.0%] | 93.9% (31/33) [80.4%, 98.3%] | **100.0%** (33/33) [89.4%, 100.0%] |
| **F1 Score** | **92.3%** | 87.3% | 81.5% |
| **Benign False Positive Rate (FPR)** | **26.1%** (6/23) [12.6%, 46.5%] | 30.4% (7/23) [15.6%, 51.0%] | 65.2% (15/23) [44.9%, 81.2%] |
| **Malicious False Negative Rate (FNR)** | **0.0%** (0/33) [0.0%, 10.6%] | 6.1% (2/33) [1.7%, 19.6%] | **0.0%** (0/33) [0.0%, 10.6%] |
| **Mean Inference Latency (ms)** | 1,420 ms | 780 ms | **290 ms** |
| **JSON Extraction Error Rate** | **0.0%** (0/56) | 1.8% (1/56) | 3.6% (2/56) |

---

## 3. Trade-Off Analysis & Takeaways

1. **Capacity vs. Alert Fatigue Trade-Off**:
   - `qwen2.5:1.5b` executes in **290 ms** (nearly 5x faster than 8B) and achieves 100% recall, but exhibits a **65.2% FPR**, over-flagging benign refactoring due to lower nuanced instruction comprehension.
   - `qwen3:8b` achieves the best balance, dropping benign FPR to **26.1%** while retaining 100% recall and 0% parse failures.
2. **Midweight Model Behavior (`gemma3:4b`)**:
   - `gemma3:4b` provides an attractive latency compromise (780 ms, ~1.8x speedup), but exhibited 2 false negatives (6.1% FNR) on subtle parameter hiding attacks.
3. **Deployment Recommendation**:
   For latency-critical edge deployments where 1.4s per update is prohibitive, `qwen2.5:1.5b` can be used as a high-recall, over-cautious filter, escalating ambiguous cases to an asynchronous 8B background inspector.
