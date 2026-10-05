# Master Method Comparison Table: MCP Semantic Drift Detection

## 1. Primary Benchmark Comparison (Phase 5 Full Held-Out Test Split N=56)

This table compares detection mechanisms evaluated across the complete 56-example held-out test split (`data/drift_test.jsonl`: 23 Benign, 33 Malicious/Suspicious):

| Detection Method | Precision (95% CI) | Recall (95% CI) | $F_1$ Score | Benign FPR (95% CI) | Malicious FNR | Avg Latency | LLM Calls / Update |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Baseline 1)** | 58.9% (46.2%–70.6%) | 100.0% (89.6%–100%) | 74.2% | **100.0%** (85.7%–100%) | 0.0% | **<1 ms** | **0.0** |
| **Static Heuristic Rules (Baseline 2)** | 100.0% (86.7%–100%) | 75.8% (59.0%–87.2%) | 86.2% | **0.0%** (0.0%–14.3%) | 24.2% | **<1 ms** | **0.0** |
| **MCP Guard Middleware (Integrated)** | **100.0%** (89.6%–100%) | **100.0%** (89.6%–100%) | **100.0%** | **0.0%** (0.0%–14.3%) | **0.0%** | **30.5 s** | **0.54** |

---

## 2. Phase 3 Method Exploration & Representation Ablation (Stratified Sample N=10)

This table compares the architectural variants evaluated during Phase 3 exploratory benchmarking on a stratified 10-example test sample (6 Malicious, 4 Benign):

| Method / Representation Variant | Precision | Recall | $F_1$ Score | Benign FPR | Malicious FNR | Avg Latency | LLM Calls / Update | JSON Parsing Error Rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning** | 60.0% | 100.0% | 75.0% | 100.0% | 0.0% | <1 ms | 0.0 | 0.0% |
| **Static Heuristic Rules** | 100.0% | 50.0% | 66.7% | 0.0% | 50.0% | <1 ms | 0.0 | 0.0% |
| **Semantic Judge — Full Def (Mode A)** | 83.3% | 83.3% | 83.3% | 25.0% | 16.7% | ~60 s | 1.0 | 20.0% |
| **Semantic Judge — Diff Only (Mode B)** | 85.7% | 100.0% | 92.3% | 25.0% | 0.0% | ~50 s | 1.0 | **0.0%** |
| **Hybrid (Static + Semantic Full)** | 83.3% | 83.3% | 83.3% | 25.0% | 16.7% | ~60 s | 1.0 | 20.0% |
| **Phase 4 Guard Middleware (Replay)** | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% | 23.7 s | 0.30 | 0.0% |

*Note on Latency & Calls*: Latency figures reflect single-threaded local CPU execution with Ollama `qwen3:8b`. The Guard Middleware reduces average LLM calls per update by short-circuiting unchanged tools (Tier 0) and overt static rule triggers (Tier 1).

---

## 3. Red-Team Adversarial Evaluation (N=30 Adaptive Evasion Suite)

This table shows performance of the Guard Middleware across 10 adversarial mutation categories (3 cases per category):

| Attack Category | Total Cases | Detected (TP) | Missed (FN) | Detection Rate (%) |
|---|---:|---:|---:|---:|
| **Indirect Wording** | 3 | 2 | 1 | 66.7% |
| **Euphemistic Instructions** | 3 | 3 | 0 | 100.0% |
| **Multi-Step Intent** | 3 | 1 | 2 | 33.3% |
| **Semantically Subtle Changes** | 3 | 3 | 0 | 100.0% |
| **Benign-Looking Prerequisites** | 3 | 3 | 0 | 100.0% |
| **Parameter Description Hiding** | 3 | 3 | 0 | 100.0% |
| **Optional Parameter Hijacking** | 3 | 0 | 3 | **0.0%** |
| **Argument Redirection** | 3 | 3 | 0 | 100.0% |
| **Field Splitting** | 3 | 3 | 0 | 100.0% |
| **Low-Signal Semantic Drift** | 3 | 0 | 3 | **0.0%** |
| **Total Red-Team Suite** | **30** | **21** | **9** | **70.0%** |

---

## 4. Key Takeaways

1. **Hash Pinning vs. Guard Middleware**: Exact hash pinning guarantees change detection but fails operationally due to a 100.0% Benign FPR. The Guard Middleware eliminates false alarms on the evaluated test set (0.0% FPR) while maintaining 100.0% recall against non-obfuscated attack vectors.
2. **Static Rules Limitation**: While fast (<1 ms) and 100% precise, static rules miss 24.2% of attacks in the full test split and 50.0% in exploratory testing due to paraphrase sensitivity.
3. **Red-Team Boundary**: While achieving 100% detection on 6 of 10 red-team categories, the semantic judge is vulnerable to schema-only modifications (Optional Parameter Hijacking and Low-Signal Boolean Schema Toggles, both 0/3 detected), demonstrating the need for specialized JSON Schema diff validation rules.
