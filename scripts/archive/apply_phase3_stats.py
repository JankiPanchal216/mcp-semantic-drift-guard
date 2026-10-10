"""
scripts/apply_phase3_stats.py - Applies Phase 3 Statistical Formulation and Results to paper.md
"""

from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
PAPER_PATH = ROOT_DIR / "paper.md"


def apply_phase3():
    with open(PAPER_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Update Section 5.1 with Multi-Step and Exposure Metrics
    target_5_1 = """#### 3. Classification Evaluation Metrics
To quantify detector effectiveness across benchmark datasets, we use standard classification metrics:
$$\\text{Precision} = \\frac{TP}{TP + FP}, \\qquad \\text{Recall} = \\frac{TP}{TP + FN}$$
$$F_1 = 2 \\cdot \\frac{\\text{Precision} \\times \\text{Recall}}{\\text{Precision} + \\text{Recall}}$$
where $TP$ denotes malicious tool modifications correctly identified as threats, $FP$ denotes benign maintenance updates incorrectly flagged as security violations (false alarms), and $FN$ denotes malicious mutations that evade detection.

### 5.2 Multi-Tier Guard Pipeline"""

    replacement_5_1 = """#### 3. Classification Evaluation Metrics
To quantify detector effectiveness across single-step benchmark datasets, we use standard classification metrics:
$$\\text{Precision} = \\frac{TP}{TP + FP}, \\qquad \\text{Recall} = \\frac{TP}{TP + FN}$$
$$F_1 = 2 \\cdot \\frac{\\text{Precision} \\times \\text{Recall}}{\\text{Precision} + \\text{Recall}}$$
where $TP$ denotes malicious tool modifications correctly identified as threats, $FP$ denotes benign maintenance updates incorrectly flagged as security violations (false alarms), and $FN$ denotes malicious mutations that evade detection.

#### 4. Multi-Step Trajectory and Exposure Metrics
In multi-step evolution, a tool contract progresses across a sequence of versions $C = (V_0, V_1, \\dots, V_K)$, generating $K$ consecutive transition evaluations.
- **Chain Recall**: A malicious chain $C \\in \\mathcal{C}_{\\text{mal}}$ is detected if the guard emits a positive security verdict ($\\hat{y} \\in \\{\\text{MALICIOUS}, \\text{SUSPICIOUS}\\}$) at any step $k \\in \\{1, \\dots, K\\}$:
$$\\text{Chain Recall} = \\frac{|\\{C \\in \\mathcal{C}_{\\text{mal}} \\mid \\exists k \\le K, \\, \\hat{y}_k \\ne \\text{BENIGN}\\}|}{|\\mathcal{C}_{\\text{mal}}|}$$
- **Benign Chain False Positive Rate (FPR)**: A benign sequence $C \\in \\mathcal{C}_{\\text{ben}}$ experiences a false alarm if any benign transition in the trajectory triggers an alert:
$$\\text{Benign Chain FPR} = \\frac{|\\{C \\in \\mathcal{C}_{\\text{ben}} \\mid \\exists k \\le K, \\, \\hat{y}_k \\ne \\text{BENIGN}\\}|}{|\\mathcal{C}_{\\text{ben}}|}$$
- **Exposure Window ($W_e$)**: Let $m$ be the first malicious transition step ($m \\ge 1$) in a malicious chain $C$ of length $K$, and let $d$ be the first step index at which the defense triggers a positive detection ($d \\in \\{1, \\dots, K\\}$). If the chain completes without detection, we define $d = K + 1$. The operational exposure window $W_e(C)$ measures the number of unprotected intermediate steps during which the agent operated with an active, undetected poisoned contract:
$$W_e(C) = \\begin{cases} 0 & \\text{if } d \\le m \\\\ d - m & \\text{if } m < d \\le K \\\\ K - m + 1 & \\text{if } d > K \\text{ (undetected)} \\end{cases}$$
The Mean Exposure Window across all malicious chains is:
$$\\bar{W}_e = \\frac{1}{|\\mathcal{C}_{\\text{mal}}|} \\sum_{C \\in \\mathcal{C}_{\\text{mal}}} W_e(C)$$
Lower values indicate earlier interception of salami drift, with $\\bar{W}_e = 0$ representing immediate zero-step interception at the moment of initial adversarial mutation.

### 5.2 Multi-Tier Guard Pipeline"""

    assert target_5_1 in content, "Target 5.1 not found in paper.md"
    content = content.replace(target_5_1, replacement_5_1)

    # 2. Update Section 9.5.4 & 9.5.5 with Cluster Bootstrap and Chain McNemar
    target_9_5 = """##### Transition-Level Main Results ($N=144$ Transitions):
*Source: `results/salami_drift_v3/computed_metrics.json` and traces in `results/salami_drift_v3_*/predictions.jsonl`.*

| Strategy | TP | TN | FP | FN | Recall | Precision | F1 | Benign Transition FPR |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Adjacent** | 17 | 104 | 0 | 23 | 42.5% | 100.0% | 0.597 | 0.0% |
| **Cumulative** | 25 | 102 | 2 | 15 | 62.5% | 92.6% | 0.746 | 1.9% |
| **Dual** | 28 | 102 | 2 | 12 | 70.0% | 93.3% | 0.800 | 1.9% |

##### Chain-Level Trajectory Outcomes ($N=40$ Chains):

| Strategy | Malicious Chain Recall | Benign Chain FPR | Mean Exposure |
|---|:---:|:---:|:---:|
| **Adjacent** | 58.3% (14/24) | 6.2% (1/16) | 0.88 |
| **Cumulative** | 91.7% (22/24) | 50.0% (8/16) | 0.42 |
| **Dual** | 91.7% (22/24) | 50.0% (8/16) | 0.38 |

*Methodological Audit on Chain FPR*: Chain-level FPR is substantially higher than transition-level FPR because a benign chain is counted as a false-positive chain if at least one transition is flagged across its trajectory. Final audit findings confirm that while transition-level benign FPR remained low at **1.9%** (2 false positives across 104 benign transitions), 6 of the 8 cumulative/dual benign-chain flags were associated with parsing-error $\\rightarrow$ `WARN` fallbacks rather than substantive semantic `MALICIOUS` judgments. Only 2 benign chains (`v3_chain_29` and `v3_chain_31`) exhibited semantic false alarms at Step 4 due to natural feature accumulation across multiple valid versions.

#### 5. Hypothesis Testing & Paired Statistical Analysis
The core research hypothesis evaluates whether cumulative context recovers malicious incremental transitions missed by adjacent-only comparison:
$$\\text{Adjacent Prediction} = \\text{BENIGN} \\quad \\wedge \\quad \\text{Cumulative Prediction} = \\text{MALICIOUS}$$

##### Paired McNemar Exact Tests ($N=144$ Paired Transitions):
- **Adjacent vs. Cumulative**: McNemar exact $p = 0.21011$ ($\\text{not statistically significant at } \\alpha = 0.05$).
- **Adjacent vs. Dual**: McNemar exact $p = 0.02246$ ($\\text{statistically significant at } \\alpha = 0.05$).

There were **11 cumulative-only detections** (Adjacent = `BENIGN`, Cumulative = `MALICIOUS`) versus **3 reverse discordant cases** (Adjacent = `MALICIOUS`, Cumulative = `BENIGN`, 2 of which stemmed from JSON parse failures on cumulative diffs).

V3 provides direct evidence that cumulative context can recover malicious transitions missed by adjacent-only comparison, with 11 cumulative-only detections versus 3 reverse discordant cases. However, the paired Adjacent-vs-Cumulative comparison was not statistically significant (McNemar exact $p = 0.21011$). In contrast, Dual-Anchor significantly outperformed Adjacent-only monitoring (McNemar exact $p = 0.02246$), indicating that combining local and root-relative comparisons provides stronger detection than adjacent comparison alone on this benchmark."""

    replacement_9_5 = """##### Transition-Level Main Results ($N=144$ Transitions):
*Source: `results/salami_drift_v3/computed_metrics.json`, `results/STATISTICAL_REPORTING.json`, and prediction traces in `results/salami_drift_v3_*/predictions.jsonl`. Transition confidence intervals are 95% Wilson score intervals.*

| Strategy | TP | TN | FP | FN | Recall (95% CI) | Precision (95% CI) | $F_1$ Score | Benign Transition FPR (95% CI) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Adjacent** | 17 | 104 | 0 | 23 | 42.5% [28.5%, 57.8%] | 100.0% [81.6%, 100.0%] | 0.597 | 0.0% [0.0%, 3.6%] |
| **Cumulative** | 25 | 102 | 2 | 15 | 62.5% [47.0%, 75.8%] | 92.6% [76.6%, 97.9%] | 0.746 | 1.9% [0.5%, 6.7%] |
| **Dual-Anchor** | 28 | 102 | 2 | 12 | **70.0%** [54.6%, 81.9%] | 93.3% [78.7%, 98.2%] | **0.800** | 1.9% [0.5%, 6.7%] |

##### Chain-Level Trajectory Outcomes ($N=40$ Chains):
*Source: Stratified cluster bootstrap (10,000 resamples over 40 chains, fixed seed 42) logged in `results/STATISTICAL_REPORTING.json`.*

| Strategy | Malicious Chain Recall (95% CI) | Benign Chain FPR (95% CI) | Chain Precision (95% CI) | Chain $F_1$ (95% CI) | Mean Exposure $\\bar{W}_e$ (95% CI) |
|---|:---:|:---:|:---:|:---:|:---:|
| **Adjacent** | 58.3% [37.5%, 79.2%] | **6.2%** [0.0%, 18.8%] | **93.5%** [80.0%, 100.0%] | 0.713 [0.529, 0.857] | 0.875 steps [0.542, 1.208] |
| **Cumulative** | **91.7%** [79.2%, 100.0%] | 50.0% [25.0%, 75.0%] | 73.6% [63.9%, 84.6%] | 0.815 [0.727, 0.902] | 0.417 steps [0.208, 0.667] |
| **Dual-Anchor** | **91.7%** [79.2%, 100.0%] | 50.0% [25.0%, 75.0%] | 73.6% [63.9%, 84.6%] | **0.815** [0.727, 0.902] | **0.375 steps** [0.167, 0.625] |

*Methodological Audit on Chain FPR*: Chain-level FPR is substantially higher than transition-level FPR because a benign chain is counted as a false-positive chain if at least one transition is flagged across its trajectory. Final audit findings confirm that while transition-level benign FPR remained low at **1.9%** (2 false positives across 104 benign transitions), 6 of the 8 cumulative/dual benign-chain flags were associated with parsing-error $\\rightarrow$ `WARN` fallbacks rather than substantive semantic `MALICIOUS` judgments. Only 2 benign chains (`v3_chain_29` and `v3_chain_31`) exhibited semantic false alarms at Step 4 due to natural feature accumulation across multiple valid versions.

#### 5. Hypothesis Testing & Paired Statistical Analysis
The core research hypothesis evaluates whether cumulative context recovers malicious incremental transitions missed by adjacent-only comparison:
$$\\text{Adjacent Prediction} = \\text{BENIGN} \\quad \\wedge \\quad \\text{Cumulative Prediction} = \\text{MALICIOUS}$$

##### Paired McNemar Exact Tests:
1. **Transition-Level Paired Tests ($N=144$ Transitions)**:
   - **Adjacent vs. Cumulative**: McNemar exact $p = 0.21011$ (16 discordant pairs; not statistically significant at $\\alpha = 0.05$).
   - **Adjacent vs. Dual-Anchor**: McNemar exact **$p = 0.02246$** (13 discordant pairs; **statistically significant** at $\\alpha = 0.05$).
   - **Cumulative vs. Dual-Anchor**: McNemar exact $p = 0.37500$ (5 discordant pairs).
2. **Chain-Level Paired Tests on Malicious Trajectories ($N=24$ Malicious Chains)**:
   - **Adjacent vs. Cumulative / Dual-Anchor**: Contingency table (Both Detected = 14, Adjacent-only = 0, Dual-only = 8, Neither = 2). McNemar exact **$p = 0.00781$** (**statistically significant** at $\\alpha = 0.01$).
   - Dual-Anchor monitoring detected 8 additional evasive salami-drift chains that completely bypassed adjacent step-by-step detection without missing any chain detected by Adjacent monitoring.
3. **Cluster Bootstrap Comparisons (10,000 Resamples)**:
   - **Chain Recall Gain (Dual vs. Adj)**: $+33.4$ percentage points (95% CI: $[+16.7\\%, +54.2\\%]$, empirical $p = 0.00040$).
   - **Mean Exposure Window Reduction (Adj vs. Dual)**: $-0.500$ steps (95% CI: $[0.250, 0.792]$ steps reduction, empirical $p < 0.0001$).
   - **Benign Chain FPR Increase (Dual vs. Adj)**: $+43.7$ percentage points (95% CI: $[+18.8\\%, +68.8\\%]$), formalizing the operational security-vs-review trade-off.

There were **11 cumulative-only detections** (Adjacent = `BENIGN`, Cumulative = `MALICIOUS`) versus **3 reverse discordant cases** (Adjacent = `MALICIOUS`, Cumulative = `BENIGN`, 2 of which stemmed from JSON parse failures on cumulative diffs)."""

    assert target_9_5 in content, "Target 9.5 not found in paper.md"
    content = content.replace(target_9_5, replacement_9_5)

    with open(PAPER_PATH, "r+", encoding="utf-8") as f:
        f.seek(0)
        f.write(content)
        f.truncate()

    print("[OK] Successfully updated paper.md with Phase 3 statistical formulations and audited results.")


if __name__ == "__main__":
    apply_phase3()
