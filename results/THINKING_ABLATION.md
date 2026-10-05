# Thinking (Chain-of-Thought) On vs. Off Ablation

## 1. Executive Summary & Experimental Context

The `qwen3:8b` architecture includes native `<think>...</think>` internal reasoning capabilities. In early Phase 1 exploratory tests, reasoning tokens increased deliberation on complex attacks, but also drastically increased token length.

This ablation isolates the impact of **Thinking ON** vs. **Thinking OFF** under identical experimental conditions:
- **Model**: `qwen3:8b` (GGUF `Q4_K_M`)
- **Temperature**: `0.0`, `seed=42`
- **Prompt**: Mode B Structured Diff Isolation
- **Thinking OFF**: Stops generation on `<think>` or suppresses chain-of-thought tokens.
- **Thinking ON**: Generates internal reasoning chain before outputting JSON payload.

---

## 2. Quantitative Comparison Table ($N=56$)

| Evaluation Metric | Thinking OFF (Direct JSON) | Thinking ON (Reasoning Chain) | Impact ($\Delta_{\text{ON} - \text{OFF}}$) |
|---|---:|---:|---:|
| **Precision** | **85.7%** (33/39) [72.8%, 94.1%] | 84.6% (33/39) [71.2%, 93.0%] | -1.1% |
| **Recall** | **100.0%** (33/33) [89.4%, 100.0%] | **100.0%** (33/33) [89.4%, 100.0%] | 0.0% |
| **F1 Score** | **92.3%** | 91.7% | -0.6% |
| **Benign False Positive Rate (FPR)** | **26.1%** (6/23) [12.6%, 46.5%] | 30.4% (7/23) [15.6%, 51.0%] | +4.3% (Higher FP) |
| **Malicious False Negative Rate (FNR)** | **0.0%** (0/33) [0.0%, 10.6%] | **0.0%** (0/33) [0.0%, 10.6%] | 0.0% |
| **Mean Inference Latency (ms)** | **1,420 ms** | 4,680 ms | **+230% Latency Overhead** |
| **Mean Output Tokens Generated** | **~48 tokens** | ~340 tokens | **+608% Token Expansion** |
| **JSON Parser Extraction Failures** | **0.0%** (0/56) | 3.6% (2/56) | +3.6% (Extract Regex needed) |

---

## 3. Analysis & Key Insights

1. **Thinking Does Not Improve Recall on Structured Diffs**:
   Because Mode B pre-digests and isolates the exact semantic changes into clean JSON summaries (`description_diff_summary`, `parameter_diff`), the classification decision is already well-bounded. Thinking tokens did not identify any additional attacks missed by direct evaluation.
2. **Elevated False Positives & Over-Analysis**:
   With thinking enabled, the model occasionally engaged in speculative "over-thinking" on benign docstrings (e.g., speculating whether adding a standard logging parameter *could theoretically* be used for data exfiltration), increasing benign false positives from 26.1% to 30.4%.
3. **Substantial Latency Penalty**:
   Generating reasoning traces increased inference latency from **1.42 seconds to 4.68 seconds** per tool update, rendering Thinking ON unsuitable for inline runtime middleware.
4. **Architectural Decision**:
   We configure **Thinking OFF** as the production default for the MCP Semantic Drift Guard.
