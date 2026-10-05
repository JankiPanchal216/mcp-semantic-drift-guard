# Baseline 3: TF-IDF Cosine-Similarity Lexical Baseline

## 1. Overview & Methodology

To evaluate whether lightweight geometric text similarity can distinguish semantic drift without invoking large language models, we implemented **Baseline 3: TF-IDF Cosine-Similarity Lexical Baseline** (`experiments/baseline_embedding.py`).

### 1.1 Vectorization & Similarity Metric
- **Representation**: Sublinear TF-IDF word n-gram vectorizer ($n \in [1, 3]$) capturing lexical co-occurrences across tool names, descriptions, and serialized JSON schemas.
- **Decision Rule**:
  $$\text{Similarity}(D_{\text{old}}, D_{\text{new}}) = \frac{\mathbf{v}_{\text{old}} \cdot \mathbf{v}_{\text{new}}}{\|\mathbf{v}_{\text{old}}\| \|\mathbf{v}_{\text{new}}\|}$$
  $$\text{Prediction} = \begin{cases} \text{MALICIOUS (DRIFT)}, & \text{Similarity} < \theta \\ \text{BENIGN}, & \text{Similarity} \ge \theta \end{cases}$$

### 1.2 Strict Dev-Split Threshold Calibration
To prevent test-set data leakage, the decision threshold $\theta$ was calibrated strictly across the **Train + Dev splits** ($N=314$). Sweeping candidate thresholds $\theta \in [0.40, 0.99]$, the optimal $F_1$ score on the Dev set ($F_1 = 77.1\%$) yielded the calibrated threshold:
$$\theta^* = 0.59$$

---

## 2. Quantitative Results on Held-Out Test Split (N=56)

Evaluating the calibrated model ($\theta^* = 0.59$) on the independent held-out test split (`data/drift_test.jsonl`: 23 Benign, 33 Malicious):

| Metric | Point Estimate | Counts (Numerator / Denominator) | 95% Wilson Confidence Interval |
|---|---:|---:|---|
| **Precision** | **64.6%** | 31 / 48 | [50.4%, 76.6%] |
| **Recall** | **93.9%** | 31 / 33 | [80.4%, 98.3%] |
| **$F_1$ Score** | **76.5%** | — | — |
| **Benign False Positive Rate (FPR)** | **73.9%** | 17 / 23 | [53.1%, 87.5%] |
| **Malicious False Negative Rate (FNR)** | **6.1%** | 2 / 33 | [1.7%, 19.6%] |
| **Average Latency** | **~1.2 ms** | Single-threaded CPU | — |
| **LLM Calls per Update** | **0.0** | Non-neural | — |

---

## 3. Comparative Analysis & Findings

| Detection Baseline | Precision | Recall | $F_1$ Score | Benign FPR | Malicious FNR | Avg Latency | LLM Calls |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Baseline 1)** | 58.9% | 100.0% | 74.2% | **100.0%** (23/23) | 0.0% | < 0.05 ms | 0.0 |
| **Static Heuristic Rules (Baseline 2)** | 100.0% | 54.5% | 70.6% | **0.0%** (0/23) | 45.5% | < 0.05 ms | 0.0 |
| **TF-IDF Cosine-Similarity Lexical Baseline** | 64.6% | 93.9% | 76.5% | **73.9%** (17/23) | 6.1% | ~1.2 ms | 0.0 |
| **Standalone Semantic Judge (Mode B)** | 85.7% | 100.0% | 92.3% | **26.1%** (6/23) | 0.0% | ~1,420 ms | 1.0 |
| **Integrated Guard Middleware (BALANCED Policy)** | **100.0%** | **100.0%** | **100.0%** | **0.0%** (0/23) | **0.0%** | ~960 ms | 0.61 |

### Key Findings
1. **Marginal Improvement over Hash Pinning**: The lexical similarity baseline modestly reduces benign false alarms from 100.0% (exact pinning) down to **73.9%**, achieving $F_1 = 76.5\%$ (vs. $74.2\%$).
2. **Lexical Confounding**: Routine documentation refactorings alter significant surface vocabulary, causing cosine similarity to fall below $\theta = 0.59$ and raising false alarms (17 false positives out of 23 benign updates).
3. **Takeaway**: Shallow bag-of-words and lexical similarity distance measures lack the compositional semantic reasoning required to differentiate harmless clarifications from malicious instructions.
