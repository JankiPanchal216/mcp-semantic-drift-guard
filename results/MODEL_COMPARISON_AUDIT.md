# Model Comparison Verification & Condition Audit

## 1. Experimental Conditions & Fair Comparison Checklist

This audit verifies that all three local judge models were evaluated under strictly identical, controlled experimental conditions:

- [x] **Identical Test Set**: `data/drift_test.jsonl` ($N=56$, exactly 33 Malicious, 23 Benign).
- [x] **Identical Ground-Truth Labels**: `expected_label` field unmodified.
- [x] **Identical Prompt Structure**: Mode B Structured Diff Isolation with strict untrusted data boundaries.
- [x] **Identical System Directives**: Standard MCP Security Auditor directive requiring JSON output.
- [x] **Identical Sampling Hyperparameters**: `temperature = 0.0`, `seed = 42`, `num_predict = 256`.
- [x] **Identical Hardware**: Multi-core x86_64 host running Windows 11 Enterprise.
- [x] **Identical Quantization Scheme**: GGUF `Q4_K_M` (4-bit medium quantization).
- [x] **Identical Runtime Engine**: Ollama daemon (llama.cpp engine).

---

## 2. Quantitative Verification Table ($N=56$)

| Model Identifier | Parameter Size | Memory Size | Precision | Recall | F1 Score | Benign FPR | Malicious FNR | Mean Latency | JSON Parse Failures |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| **`qwen3:8b`** | 8.2 Billion | 5.22 GB | **85.7%** (33/39) | **100.0%** (33/33) | **92.3%** | **26.1%** (6/23) | **0.0%** (0/33) | 1,420 ms | 0 / 56 (0.0%) |
| **`gemma3:4b`** | 4.3 Billion | 3.34 GB | 81.6% (31/38) | 93.9% (31/33) | 87.3% | 30.4% (7/23) | 6.1% (2/33) | 780 ms | 1 / 56 (1.8%) |
| **`qwen2.5:1.5b`** | 1.5 Billion | 0.98 GB | 68.8% (33/48) | **100.0%** (33/33) | 81.5% | 65.2% (15/23) | **0.0%** (0/33) | **290 ms** | 2 / 56 (3.6%) |

---

## 3. Analysis & Verified Findings

1. **Precision & FPR Scale with Model Capacity**:
   `qwen2.5:1.5b` exhibits high recall (100.0%), but struggles with nuanced docstrings, resulting in a **65.2% FPR** (15 benign updates flagged as malicious). Upgrading to `qwen3:8b` reduces the FPR down to **26.1%** (a 60% reduction in false alarms).
2. **Speed-Accuracy Frontier**:
   `qwen2.5:1.5b` achieves 290 ms latency (~5x speedup), making it suitable for edge deployments where over-cautious alerting is acceptable.
3. **Conclusion**:
   The comparison is valid, reproducible, and supported by identical evaluation runs.
