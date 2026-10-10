# Claims Traceability Matrix (`paper/CLAIMS_MATRIX.md`)

This matrix maps every claim, quantitative assertion, and contribution statement in `paper.md` directly to its backing results artifact, script, test, and line numbers with PASS/FAIL verification status.

---

## 1. Abstract & Introduction Claims Verification

| Abstract / Intro Statement | Claimed Metric / Assertion | Backing Artifact / Script | Verification Test | Paper Location | Status |
|---|---|---|---|---|:---:|
| **P1: Motivation & Release Audit** | 31 of 621 releases (4.99%) contained tool modifications (0.050 alerts/transition under exact hash pinning; 13 existing contract refactorings = 2.09%) | `results/computed_metrics.json` | `tests/test_metrics_consistency.py` | `paper.md:33-44` | **PASS** |
| **P2: Defense Architecture** | 5-tier defense with sub-millisecond fast-paths and 4B local judge (`gemma3:4b`) under Draft-07 JSON Schema decoding | `guard/middleware.py`, `guard/semantic_judge.py` | `tests/test_middleware.py` | `paper.md:7, 147-156` | **PASS** |
| **P3: V4 Held-Out Test Recall (Rule b BALANCED)** | Adjacent: 96.2% (25/26) Salami Recall [81.1%, 99.3%], Exposure $\bar{W}_e = 0.192$, Benign FPR = 4.0% (1/25) [0.7%, 19.5%]. Cumulative: 76.9% (20/26) Salami Recall [58.0%, 89.0%], Exposure $\bar{W}_e = 0.731$, Benign FPR = 0.0% (0/25) [0.0%, 13.3%]. Difference: +19.2% [0.0%, 38.5%], $p = 0.1250$. | `results/salami_drift_v4/gemma3_4b/validated/v4_statistical_report.json` | `tests/test_raw_traces_table_consistency.py` | `paper.md:11-13, 255-280` | **PASS** |
| **P4: Matched-FPR Baseline Evaluation** | Exact hash pinning achieves 100.0% (26/26) recall at 100.0% (25/25) FPR. At low FPR ($\le 4.0\%$), deterministic baselines achieve 0.0%–3.9% recall. Parameter delta achieves 76.9% recall only at 44.0% FPR. | `results/baselines_v4/baselines_summary.json` | `tests/test_v4_baselines_and_novelty.py`, `tests/test_hash_pinning_v4.py` | `paper.md:13, 284-306` | **PASS** |
| **P5: Novel Methods (Capability & Drift Budget)** | Capability-Set Tracking: 61.5% (16/26) Salami recall, 32.0% (8/25) Benign FPR; Drift Budget ($B^*=4.10$): 30.8% (8/26) Salami recall, 0.0% (0/25) Benign FPR. | `results/novel_methods_v4/novel_methods_summary.json` | `tests/test_v4_baselines_and_novelty.py` | `paper.md:14, 320-336` | **PASS** |
| **P6: Adaptive Attacker Resistance** | Adjacent Guard retains 91.7% (22/24) post-adaptive recall (8.3% evasion rate [2.3%, 25.9%], 8.12 queries/chain), whereas Cumulative Guard suffers 41.7% evasion (10/24) and Drift Budget suffers 83.3% evasion (20/24). | `results/adaptive_attacker/adaptive_summary.json` | `tests/test_delivery_and_adaptive.py` | `paper.md:15, 342-360` | **PASS** |
| **P7: Delivery Layer Transport Fixes** | 5 scripted transport failure conditions evaluated in simulation; unvetted delivery eliminated across all 5 conditions (5/5 $\rightarrow$ 0/5). | `results/delivery_layer/delivery_summary.json` | `tests/test_delivery_and_adaptive.py` | `paper.md:16, 362-375` | **PASS** |

---

## 2. Benchmark V4 Provenance & Trivial-Separator Audit

| Benchmark V4 Claim | Value / Property | Backing Script / Artifact | Paper Location | Status |
|---|---|---|---|:---:|
| **Dataset Scale** | $N=116$ Chains, 436 Transitions (58 Calibration: 34 Salami, 5 Fast-Jump, 19 Benign; 58 Frozen Held-Out Test: 26 Salami, 7 Fast-Jump, 25 Benign) | `data/salami_drift_benchmark_v4.jsonl` | `paper.md:11, 245-280` | **PASS** |
| **Dataset Hash** | SHA-256: `91f1d0de6f7673731c34967e3f5c77504e598b49fd6cc4807ef6209ddd4faebe` | `paper/PREREGISTRATION.md` | `paper.md:11, 49` | **PASS** |
| **Parameter Delta AUC** | ROC-AUC = 0.5203 ($< 0.65$ threshold) | `results/salami_drift_v4/gemma3_4b/validated/v4_statistical_report.json` | `paper.md:245-253` | **PASS** |
| **Edit Distance AUC** | ROC-AUC = 0.3489 ($\max(\text{AUC}, 1-\text{AUC}) = 0.6511$, borderline / reported) | `results/salami_drift_v4/gemma3_4b/validated/v4_statistical_report.json` | `paper.md:17, 245-253` | **PASS** |
| **Docstring Length AUC** | ROC-AUC = 0.7228 ($> 0.65$, FAIL / reported honestly as limitation) | `results/salami_drift_v4/gemma3_4b/validated/v4_statistical_report.json` | `paper.md:17, 245-253` | **PASS** |

---

## 3. Methodological Boundaries & Limitations Verification

| Limitation Claim | Implementation in Paper | Backing Artifact | Paper Location | Status |
|---|---|---|---|:---:|
| **Single Small Judge** | Section 14 explicitly notes evaluation restricted to local `gemma3:4b` at Q4_K_M | `paper.md` Section 14 | `paper.md:383-384` | **PASS** |
| **Synthetic Benchmark** | Section 14 notes chains are scripted evolutions over open-source schemas | `paper.md` Section 14 | `paper.md:385` | **PASS** |
| **Trivial Separator Confound** | Section 14 explicitly reports length AUC = 0.7228 and edit distance 0.6511 | `paper.md` Section 14 | `paper.md:386` | **PASS** |
| **Generator Provenance** | Section 14 documents script-generation provenance disjoint from judge | `paper.md` Section 14 | `paper.md:387` | **PASS** |
| **Threat Model Scope** | Section 2.5 & Section 14 document single-server scope (cross-server collusion out of scope) | `paper.md` Section 2.5 & 14 | `paper.md:95-105, 388` | **PASS** |
| **Live Transport Scope** | Section 14 documents 5 scripted failure modes evaluated on localhost mock harness | `paper.md` Section 14 | `paper.md:362-375, 389` | **PASS** |
| **Production Operator Burden** | Section 1.2, Table 1 & Section 14 mark production burden as unmeasured qualitative factor | `paper.md` Section 1.2, Table 1, 14 | `paper.md:44, 117, 390` | **PASS** |
