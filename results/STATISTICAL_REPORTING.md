# Statistical Reporting & Confidence Interval Methodology

This document details the statistical methodology, sample sizes, numerators, denominators, and 95% confidence intervals across all primary experimental results.

---

## 1. Statistical Methodology: Wilson Score Interval

Because many security sub-samples involve small counts or extreme proportions (e.g., 0% FPR or 100% recall), standard normal approximation intervals ($\hat{p} \pm 1.96 \sqrt{\hat{p}(1-\hat{p})/n}$) produce degenerate or invalid bounds (e.g. intervals extending below 0% or above 100%).

We compute all 95% confidence intervals using the **Wilson Score Interval** with continuity adjustment:

$$CI_{95\%} = \frac{\hat{p} + \frac{z^2}{2n} \pm z \sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$

where $z = 1.95996$ (for 95% two-tailed significance), $\hat{p} = k / n$, $k$ is the number of successes/detections, and $n$ is the total sample denominator.

For multi-fold cross-validation metrics across partitioned server clusters, variability is reported as the sample standard deviation across folds ($\pm \text{SD}$), not as a binomial confidence interval.

---

## 2. Main Benchmark Results ($N=56$ Held-Out Test Set)

| Defense System / Evaluated Layer | Precision ($k/n$) | 95% Wilson CI | Recall ($k/n$) | 95% Wilson CI | Benign FPR ($k/n$) | 95% Wilson CI |
|---|---:|---|---:|---|---:|---|
| **Cryptographic Hash Pinning (Tier 0)** | 58.9% (33/56) | [45.9%, 70.8%] | 100.0% (33/33) | [89.4%, 100.0%] | 100.0% (23/23) | [85.2%, 100.0%] |
| **Static Keyword Rules (Tier 1)** | 100.0% (18/18) | [81.5%, 100.0%] | 54.5% (18/33) | [37.8%, 70.3%] | 0.0% (0/23) | [0.0%, 14.8%] |
| **TF-IDF Cosine-Similarity Lexical Baseline** | 64.6% (31/48) | [50.4%, 76.6%] | 93.9% (31/33) | [80.4%, 98.3%] | 73.9% (17/23) | [53.5%, 87.5%] |
| **Semantic Judge Mode A (Full Context)** | 80.5% (32/39) | [65.1%, 91.2%] | 97.0% (32/33) | [84.2%, 99.9%] | 39.1% (9/23) | [21.8%, 59.6%] |
| **Semantic Judge Mode B (Diff Only)** | 85.7% (33/39) | [72.8%, 94.1%] | 100.0% (33/33) | [89.4%, 100.0%] | 26.1% (6/23) | [12.6%, 46.5%] |
| **Integrated Guard Middleware (BALANCED Policy)** | **100.0%** (33/33) | **[89.4%, 100.0%]** | **100.0%** (33/33) | **[89.4%, 100.0%]** | **0.0%** (0/23) | **[0.0%, 14.8%]** |

---

## 3. Server-Grouped 5-Fold Cross-Validation ($N=370$)

Across 5 folds partitioned by server repository with zero server overlap between train and test:
- **Precision**: 81.8% ± 10.3% (standard deviation)
- **Recall**: 100.0% ± 0.0%
- **F1 Score**: 89.7% ± 6.2%
- **Benign FPR**: 23.0% ± 4.1%

---

## 4. Controlled Matched-Pair Pilot ($N=24$)

*Sample Size Note: $N=24$ represents 12 matched pairs. Designed to reduce writing-style confounding, though too small to establish general performance.*

| Condition | Evaluated Samples | Benign Allowed ($k/n$) | Malicious Blocked ($k/n$) | F1 Score |
|---|---:|---:|---:|---:|
| **Benign Updates (Authentic)** | $n=12$ | 9 / 12 (75.0% [46.8%, 91.1%]) | - | - |
| **Malicious Mutations (Controlled)** | $n=12$ | - | 12 / 12 (100.0% [73.5%, 100.0%]) | - |
| **Overall Matched-Pair Pilot** | $N=24$ | Precision: 80.0% (12/15) | Recall: 100.0% (12/12) | **88.9%** |

---

## 5. Descriptive Real Existing-Tool Modification Subsets ($N=123$)

*Sample Size Note: Out of 123 tool-definition change events, 110 are additions/removals and 13 are modifications to pre-existing tool contracts. 13 of 621 release transitions (2.09%) contained modifications to pre-existing tool contracts.*

| Subset Category | Count ($n$) | Hash Pinning Alert Rate | Static Rules FPR | Semantic Guard FPR |
|---|---:|---:|---:|---:|
| **All Real Update Events** | $n=123$ | 100.0% (123/123) | 0.0% (0/123) | 22.0% (27/123) |
| **Pre-Existing Tool Contract Modifications** | $n=13$ | 100.0% (13/13) | 0.0% (0/13) | 23.1% (3/13) |
| **Description/Documentation Clarifications** | $n=7$ | 100.0% (7/7) | 0.0% (0/7) | 14.3% (1/7) |
| **Schema/Parameter Modifications** | $n=2$ | 100.0% (2/2) | 0.0% (0/2) | 50.0% (1/2) |
| **Mixed Contract Modifications** | $n=4$ | 100.0% (4/4) | 0.0% (0/4) | 25.0% (1/4) |

---

## 6. Adversarial Pilot Evaluation (Red-Team v2, $N=28$)

- **Total Attacks Evaluated**: $N=28$ across 14 categories ($n=2$ per category).
- **Static Keyword Rules Detection Rate**: 18 / 28 = **64.3%** [45.8%, 79.3%]
- **Schema Security Checks (Tier 1.5) Detection Rate**: 10 / 28 = **35.7%** [20.7%, 54.2%]
- **Full Guard Detection Rate**: 25 / 28 = **89.3%** [72.8%, 96.3%]
- **Attacks Evading All Tiers**: 3 / 28 = **10.7%** [3.7%, 27.2%]
