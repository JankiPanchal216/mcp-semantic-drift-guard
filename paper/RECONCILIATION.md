# Benchmark Reconciliation & Number Provenance Audit (`paper/RECONCILIATION.md`)

This document records the exact provenance, result file paths, timestamps (UTC), SHA-256 hashes, and numerical reconciliation between historical reported numbers and verified raw trace computations.

---

## 1. Result Files Inventory & Trace Provenance

| Benchmark & Evaluation Run | File Path | File Size | Last Modified (UTC) | SHA-256 Digest |
|---|---|---:|---|---|
| **V3 Unconstrained Adjacent** | `results/salami_drift_v3_per_step/predictions.jsonl` | 134,254 B | 2026-10-08T13:56:00Z | `226fa85c571a34c4742e0292e3c2c5a6d38e17b3098fe981e1418af4d2d4de80` |
| **V3 Unconstrained Cumulative** | `results/salami_drift_v3_cumulative/predictions.jsonl` | 135,848 B | 2026-10-08T13:56:00Z | `8b139c5de837f522ca6317552bae7e19afc0025c2f2a39ee61aa84ebf9866848` |
| **V3 Constrained Adjacent** | `results/salami_drift_v3_constrained/predictions_adjacent.jsonl` | 67,721 B | 2026-10-09T05:52:58Z | `205f599f850fbfd29c8b4a58782dcd588afb26d1e1a5393a70fd23f0a3c56e5d` |
| **V3 Constrained Cumulative** | `results/salami_drift_v3_constrained/predictions_cumulative.jsonl` | 67,918 B | 2026-10-09T06:31:32Z | `38c7b43e71a6a7e4135e26fd7bebe61e3ddab53f2f892d28cc2f9fb4e02525a3` |
| **V3 Decision Rule Audit** | `results/DECISION_RULE_AUDIT_DATA.json` | 16,470 B | 2026-10-09T04:42:19Z | `bece052b6a7c4f41d82fe157013372fe853771ccb098f8978d92c3bd8b86dbef` |
| **V4 Held-Out Predictions Adj** | `results/salami_drift_v4/gemma3_4b/predictions_adjacent.jsonl` | 672,788 B | 2026-10-09T12:03:42Z | `7c643026c1d859cdb10b1d54573df54fc1f4c3879df31b3142c5ae7589666558` |
| **V4 Held-Out Predictions Cum** | `results/salami_drift_v4/gemma3_4b/predictions_cumulative.jsonl` | 670,904 B | 2026-10-09T16:03:25Z | `bea29c99daa07eb3a6bc325e55d3194d4b3c7dec9d8aa9a9750166d44ea87e46` |
| **V4 Statistical Report** | `results/salami_drift_v4/gemma3_4b/validated/v4_statistical_report.json` | 112,525 B | 2026-10-09T16:30:09Z | `97e5f6b67764e2e709be74ef251d8911dd8068546b4699f340feb1b1a86fe0c7` |

---

## 2. Explanation of Moved Numbers & Root Causes

### 1. V3 Constrained Cumulative Salami Recall & FPR (87.5% / 12.5% vs. 43.8% / 0.0%)
- **Original Claim**: V3 Constrained Cumulative achieved 87.5% (14/16) Salami recall and 12.5% (2/16) Benign FPR.
- **True Trace Result**: Re-evaluation from raw predictions `results/salami_drift_v3_constrained/predictions_cumulative.jsonl` yields **43.8% (7/16)** Salami Recall and **0.0% (0/16)** Benign FPR.
- **Root Cause**: The 87.5% (14/16) and 12.5% (2/16) numbers were the **Unconstrained Rule (a) / Rule (c) Parsed-Only** numbers from `results/DECISION_RULE_AUDIT_DATA.json` (where 14/16 salami chains were detected without parse fallbacks). In an earlier draft of `paper.md`, these unconstrained parsed-only metrics were mistakenly transposed into the "Constrained JSON" row in Table 13.
- **Correction**: Updated Table 13 in `paper.md` to show the verified trace result: **43.8% (7/16)** Salami Recall, **62.5% (5/8)** Fast-Jump Recall, and **0.0% (0/16)** Benign FPR.

### 2. V3 Unconstrained Cumulative Parse Failures (5.4% vs. 6.9% vs. 10.4%)
- **Original Claim**: 5.4% or 6.9% (10/144) parse errors.
- **True Trace Result**: In `results/salami_drift_v3_cumulative/predictions.jsonl`, exactly **15 of 144 transitions (10.42%)** produced JSON extraction failures (`parse_error != null`).
- **Root Cause**: In early drafts, only benign-transition parse failures (10 transitions = 6.94%) or dual-anchor parse failures (8 transitions = 5.56%) were reported rather than the total 15 failures (10 benign + 5 malicious).
- **Correction**: Reconciled to the exact trace count: **15/144 (10.42%)** total transition parse failures in unconstrained cumulative evaluation.

### 3. V4 Hash Pinning Recall (0.0% vs. 100.0%)
- **Original Claim**: V4 Hash Pinning achieved 0.0% (0/26) Salami recall.
- **True Trace Result**: Exact cryptographic hash pinning achieves **100.0% (26/26)** Salami Recall, **100.0% (25/25)** Benign FPR, and $\bar{W}_e = 0.000$ steps.
- **Root Cause**: `experiments/evaluate_v4_baselines.py` had a pre-attack alert rejection bug where any alert on $t < m$ erroneously discarded subsequent valid alerts on attack transitions. Fixed in `experiments/evaluate_v4_baselines.py` and certified via unit test `tests/test_hash_pinning_v4.py`.
- **Correction**: Table 8 and all paper text updated to **100.0% (26/26)** recall at **100.0% (25/25)** FPR.

---

## 3. Authoritative Recomputed Headline Matrix

### A. Salami Drift Benchmark V3 ($N=40$ Chains, 144 Transitions)

| Evaluation Setting | Strategy | Decision Rule | Salami Recall ($N=16$) | Fast-Jump Recall ($N=8$) | Benign Chain FPR ($N=16$) | Salami Mean Exposure $\bar{W}_e$ | Transition Parse Failures |
|---|---|---|:---:|:---:|:---:|:---:|:---:|
| **Unconstrained Prompting** | Adjacent | Rule (b) BALANCED | 50.0% (8/16) [28.0%, 72.0%] | 75.0% (6/8) [40.9%, 92.9%] | 6.2% (1/16) [1.1%, 28.3%] | 1.188 steps | 3/144 (2.08%) |
| | Cumulative | Rule (b) BALANCED | 87.5% (14/16) [64.0%, 96.5%] | 87.5% (7/8) [52.9%, 97.8%] | 50.0% (8/16) [28.0%, 72.0%] | 0.562 steps | 15/144 (10.42%) |
| | Adjacent | Rule (a) Strict | 0.0% (0/16) [0.0%, 19.4%] | 37.5% (3/8) [13.7%, 69.4%] | 0.0% (0/16) [0.0%, 19.4%] | 2.000 steps | - |
| | Cumulative | Rule (a) Strict | 25.0% (4/16) [10.2%, 49.5%] | 37.5% (3/8) [13.7%, 69.4%] | 0.0% (0/16) [0.0%, 19.4%] | 1.688 steps | - |
| **Constrained JSON Schema** | Adjacent | Rule (b) BALANCED | 81.2% (13/16) [57.0%, 93.4%] | 50.0% (4/8) [21.5%, 78.5%] | 0.0% (0/16) [0.0%, 19.4%] | 0.875 steps | 0/144 (0.00%) |
| | Cumulative | Rule (b) BALANCED | 43.8% (7/16) [23.1%, 66.8%] | 62.5% (5/8) [30.6%, 86.3%] | 0.0% (0/16) [0.0%, 19.4%] | 1.500 steps | 0/144 (0.00%) |
| | Adjacent | Rule (a) Strict | 0.0% (0/16) [0.0%, 19.4%] | 37.5% (3/8) [13.7%, 69.4%] | 0.0% (0/16) [0.0%, 19.4%] | 2.000 steps | - |
| | Cumulative | Rule (a) Strict | 0.0% (0/16) [0.0%, 19.4%] | 37.5% (3/8) [13.7%, 69.4%] | 0.0% (0/16) [0.0%, 19.4%] | 2.000 steps | - |

### B. Salami Drift Benchmark V4 ($N=116$ Chains, 436 Transitions)

| Dataset Partition | Strategy | Decision Rule | Salami Recall (95% CI) | Fast-Jump Recall (95% CI) | Overall Malicious Recall (95% CI) | Benign Chain FPR (95% CI) | Salami Mean Exposure $\bar{W}_e$ |
|---|---|---|:---:|:---:|:---:|:---:|:---:|
| **Held-Out Test ($N=58$)** | Adjacent | Rule (b) Primary | **96.2%** (25/26) [81.1%, 99.3%] | **100.0%** (7/7) [64.6%, 100.0%] | **97.0%** (32/33) [84.7%, 99.5%] | **4.0%** (1/25) [0.7%, 19.5%] | **0.192** steps |
| | Cumulative | Rule (b) Primary | **76.9%** (20/26) [58.0%, 89.0%] | **100.0%** (7/7) [64.6%, 100.0%] | **81.8%** (27/33) [65.6%, 91.4%] | **0.0%** (0/25) [0.0%, 13.3%] | **0.731** steps |
| **Calibration Split ($N=58$)** | Adjacent | Rule (b) Primary | **94.1%** (32/34) [80.9%, 98.4%] | **100.0%** (5/5) [56.5%, 100.0%] | **94.9%** (37/39) [83.1%, 98.6%] | **10.5%** (2/19) [2.9%, 31.4%] | **0.353** steps |
| | Cumulative | Rule (b) Primary | **67.7%** (23/34) [50.8%, 80.9%] | **100.0%** (5/5) [56.5%, 100.0%] | **71.8%** (28/39) [56.2%, 83.5%] | **0.0%** (0/19) [0.0%, 16.8%] | **1.118** steps |
| **Full Benchmark ($N=116$)** | Adjacent | Rule (b) Primary | **95.0%** (57/60) [86.3%, 98.3%] | **100.0%** (12/12) [75.8%, 100.0%] | **95.8%** (69/72) [88.4%, 98.6%] | **6.8%** (3/44) [2.4%, 18.2%] | **0.283** steps |
| | Cumulative | Rule (b) Primary | **71.7%** (43/60) [59.2%, 81.5%] | **100.0%** (12/12) [75.8%, 100.0%] | **76.4%** (55/72) [65.4%, 84.7%] | **0.0%** (0/44) [0.0%, 8.0%] | **0.950** steps |
