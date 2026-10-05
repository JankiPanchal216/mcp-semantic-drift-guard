# Final Reviewer Comparison Table

This document provides a consolidated, multi-system comparison across all evaluated baselines, ablations, and the MCP Semantic Drift Guard configurations on the held-out benchmark ($N=56$, 33 Malicious, 23 Benign) and cross-validation sets.

---

## 1. Primary Benchmark Comparison Matrix

| Method | Evaluation | N | Precision | Recall | F1 | Benign FPR | Latency |
|---|---|---:|---:|---:|---:|---:|---:|
| **Cryptographic Hash Pinning (Tier 0)** | Standalone Baseline (Exact Match) | 56 | 58.9% (33/56) | 100.0% (33/33) | 74.2% | 100.0% (23/23) | < 0.05 ms |
| **Static Keyword Rules (Tier 1)** | Standalone Baseline (Regex Filter) | 56 | 100.0% (18/18) | 54.5% (18/33) | 70.6% | 0.0% (0/23) | < 0.05 ms |
| **TF-IDF Cosine-Similarity Lexical Baseline** | Standalone Baseline ($\theta^*=0.59$) | 56 | 64.6% (31/48) | 93.9% (31/33) | 76.5% | 73.9% (17/23) | ~1.2 ms |
| **Deterministic Schema Security (Tier 1.5)** | Standalone Layer Check | 56 | 100.0% (12/12) | 36.4% (12/33) | 53.3% | 0.0% (0/23) | ~0.08 ms |
| **Semantic Judge Mode A (Full Context)** | Standalone LLM Judge (Mode A) | 56 | 80.5% (32/39) | 97.0% (32/33) | 87.9% | 39.1% (9/23) | ~2,850 ms |
| **Semantic Judge Mode B (Diff Only)** | Standalone Semantic Judge (Mode B) | 56 | 85.7% (33/39) | 100.0% (33/33) | 92.3% | 26.1% (6/23) | ~1,420 ms |
| **Hybrid Guard (Tiers 0+1+1.5+2+3, Mode B)** | Standalone Pipeline (No Middleware Context) | 56 | 85.7% (33/39) | 100.0% (33/33) | 92.3% | 26.1% (6/23) | ~960 ms |
| **Integrated Guard Middleware (BALANCED Policy)** | Integrated Middleware (Held-Out Test) | 56 | 100.0% (33/33) | 100.0% (33/33) | 100.0% | 0.0% (0/23) | ~960 ms |
| **Semantic Judge Mode B (5-Fold Group CV)** | Server-Grouped Generalization | 370 | 81.8% ± 10.3% | 100.0% ± 0.0% | 89.7% ± 6.2% | 23.0% ± 4.1% | ~1,420 ms |

*Note: In the 5-fold cross-validation row, ± indicates sample standard deviation across the 5 server-partitioned folds.*

---

## 2. Key Observations & Trade-Off Analysis

1. **Hash Pinning vs. Guard**:
   Exact hash pinning flags every observed tool-definition change because its integrity criterion is byte-level equality. In the observed corpus, 31 of 621 release transitions (4.99%) changed tool manifests, meaning these changes trigger review under exact pinning. The guard reduces benign false alarm burden from 100.0% down to 26.1% (standalone judge) or 0.0% (integrated middleware on held-out test), while catching 100% of malicious drift in this sample.
2. **Deterministic Tiers as Fast Pre-Filters**:
   Static rules and schema security checks execute in $< 0.1\text{ ms}$ and have zero false positives on the evaluated $N=23$ benign cases. When placed upstream, they resolve 39% of changes immediately without invoking the local LLM.
3. **Diff-Only Isolation Superiority**:
   Mode B diff-only judge reduces latency from ~2.85s down to ~1.42s and lowers benign false alarms from 39.1% to 26.1% relative to full-definition prompts (Mode A).
4. **Integrated Middleware vs Standalone Semantic Judge**:
   The integrated middleware leverages deterministic tiers, baseline context, and policy thresholds to achieve 100% F1 on the held-out test split, whereas the standalone semantic judge isolates text-classification performance on diffs ($92.3\%$ F1).

