# Claims Traceability Matrix (`paper/CLAIMS_MATRIX.md`)

This matrix maps every claim, quantitative assertion, and contribution statement in `paper.md` directly to its backing results artifact, script, test, and line numbers with PASS/FAIL verification status.

---

## 1. Abstract & Introduction Claims Verification

| Abstract / Intro Statement | Claimed Metric / Assertion | Backing Artifact / Script | Verification Test | Paper Location | Status |
|---|---|---|---|---|:---:|
| **P1: Motivation & Release Audit** | 646 snapshots yielding 621 release transitions across 25 active repos; 31 of 621 releases (4.99%) contained tool modifications (0.050 alerts/transition under exact hash pinning; 13 existing contract refactorings = 2.09%) | `results/computed_metrics.json` | `tests/test_metrics_consistency.py` | `paper.md:33-44` | **PASS** |
| **P2: Defense Architecture** | 5-tier defense with sub-millisecond fast-paths and multi-judge support: local open-weight judge (`gemma3:4b`, 4B parameters) and cloud judge (`gemini-3.1-flash-lite`) under Draft-07 JSON Schema constrained decoding | `guard/middleware.py`, `guard/semantic_judge.py` | `tests/test_middleware.py` | `paper.md:7, 147-156` | **PASS** |
| **P3: Gemma V4 Held-Out Test Recall (Rule b BALANCED)** | Adjacent: 96.2% (25/26) Salami Recall [81.1%, 99.3%], Exposure $\bar{W}_e = 0.192$, Benign FPR = 4.0% (1/25) [0.7%, 19.5%]. Cumulative: 76.9% (20/26) Salami Recall [57.9%, 89.0%], Exposure $\bar{W}_e = 0.731$, Benign FPR = 0.0% (0/25) [0.0%, 13.3%]. Difference: +19.2% [0.0%, 38.5%], $p = 0.1250$ (pooled post hoc $p = 0.0026$). | `results/salami_drift_v4/gemma3_4b/validated/v4_statistical_report.json` | `tests/test_raw_traces_table_consistency.py` | `paper.md:7, 290-315` | **PASS** |
| **P4: Matched-FPR Baseline Evaluation** | Exact hash pinning achieves 100.0% (26/26) recall at 100.0% (25/25) FPR. At low FPR ($\le 4.0\%$), deterministic baselines achieve 0.0%–3.8% recall. Parameter delta achieves 76.9% recall only at 44.0% FPR. | `results/baselines_v4/baselines_summary.json` | `tests/test_v4_baselines_and_novelty.py`, `tests/test_hash_pinning_v4.py` | `paper.md:7, 318-340` | **PASS** |
| **P5: Novel Methods (Capability & Drift Budget)** | Capability-Set Tracking: 61.5% (16/26) Salami recall, 32.0% (8/25) Benign FPR; Drift Budget ($B^*=4.10$): 30.8% (8/26) Salami recall, 0.0% (0/25) Benign FPR. | `results/novel_methods_v4/novel_methods_summary.json` | `tests/test_v4_baselines_and_novelty.py` | `paper.md:400-415` | **PASS** |
| **P6: Template Mutation Search Resistance** | Adjacent Guard retains 91.7% (22/24) post-adaptive recall (8.3% evasion rate [2.3%, 25.8%], 8.12 queries/chain; evaluated against `gemma3:4b` only using template-based mutation search with no LLM), whereas Cumulative Guard suffers 41.7% evasion (10/24) and Drift Budget suffers 83.3% evasion (20/24). | `results/adaptive_attacker/adaptive_summary.json` | `tests/test_delivery_and_adaptive.py` | `paper.md:420-435` | **PASS** |
| **P7: Delivery Layer Transport Fixes** | 5 scripted transport failure conditions evaluated in simulation; unvetted delivery prevented across all 5 conditions (5/5 $\rightarrow$ 0/5). | `results/delivery_layer/delivery_summary.json` | `tests/test_delivery_and_adaptive.py` | `paper.md:440-450` | **PASS** |
| **P8: Gemini Replication ($H_1'$)** | Cross-architecture replication on `gemini-3.1-flash-lite` shows no significant difference between Adjacent (88.5%, 23/26) and Cumulative (84.6%, 22/26) Salami recall (exact McNemar $p = 1.0000$); direction depends on rule (Cumulative higher under Rule a: 25/26 vs 22/26); post hoc exploratory hypothesis ($H_1'$) and attention dilution not supported on Gemini. | `results/salami_drift_v4/google_gemini-3.1-flash-lite/` | `scripts/make_tables.py` (Table 7, Table A.2) | `paper.md:320-335, Table A.2` | **PASS** |
| **P9: Combined Prompt Evaluation ($H_2$)** | Combined matches Adjacent on gemma (96.2%, 25/26; 0/25 FPR, $p = 1.0000$); not supported on Gemini (84.6% vs 88.5%, $p = 1.0000$), weakly supported on gemma (one fewer false-alarm chain, p=1.0), judge-dependent; expands prompt tokens by +47.0% on gemma. | `results/salami_drift_v4/` | `scripts/make_tables.py` (Table 7, Table A.2) | `paper.md:355-370, Table A.2` | **PASS** |
| **P10: Candidate Qualifications & Exclusions** | DeepSeek API (`deepseek-flash`) authenticated with valid key but excluded due to zero balance ($0.00, HTTP 402 Insufficient Balance, zero completed calls); qwen3:8b disqualified (40% parse rate, Gate 1 failed); Hugging Face disqualified (HTTP 402). | `paper/PREREGISTRATION.md` | Section 8.7 audit | `paper.md:410-420, Table 11` | **PASS** |

---

## 2. Benchmark V4 Provenance & Trivial-Separator Audit

| Benchmark V4 Claim | Value / Property | Backing Script / Artifact | Paper Location | Status |
|---|---|---|---|:---:|
| **Dataset Scale** | $N=116$ Chains, 436 Transitions (58 Calibration: 34 Salami, 5 Fast-Jump, 19 Benign; 58 Frozen Held-Out Test: 26 Salami, 7 Fast-Jump, 25 Benign) | `data/salami_drift_benchmark_v4.jsonl` | `paper.md:260-270` | **PASS** |
| **Dataset Hash** | SHA-256: `91f1d0de6f7673731c34967e3f5c77504e598b49fd6cc4807ef6209ddd4faebe` | `paper/PREREGISTRATION.md` | `paper.md:7, 39, 262, 500` | **PASS** |
| **Parameter Delta AUC** | ROC-AUC = 0.5203 ($< 0.65$ threshold) | `results/salami_drift_v4/gemma3_4b/validated/v4_statistical_report.json` | `paper.md:278` | **PASS** |
| **Edit Distance AUC** | ROC-AUC = 0.3489 ($\max(\text{AUC}, 1-\text{AUC}) = 0.6511 > 0.65$, FAIL / reported) | `results/salami_drift_v4/gemma3_4b/validated/v4_statistical_report.json` | `paper.md:7, 279, 472` | **PASS** |
| **Docstring Length AUC** | ROC-AUC = 0.7228 ($> 0.65$, FAIL / reported honestly as limitation) | `results/salami_drift_v4/gemma3_4b/validated/v4_statistical_report.json` | `paper.md:7, 280, 472` | **PASS** |

---

## 3. Methodological Boundaries & Limitations Verification

| Limitation Claim | Implementation in Paper | Backing Artifact | Paper Location | Status |
|---|---|---|---|:---:|
| **Two Verified Judges Scope** | Evaluated on local `gemma3:4b` (Q4_K_M) and cloud `gemini-3.1-flash-lite`; larger models deferred to Future Work | `paper.md` Section 14 | `paper.md:470` | **PASS** |
| **Synthetic Benchmark** | Section 14 notes chains are scripted evolutions over open-source schemas from a single generator | `paper.md` Section 14 | `paper.md:471` | **PASS** |
| **Trivial Separator Confound** | Section 14 explicitly reports length AUC = 0.7228 and edit distance 0.6511 (FAIL) | `paper.md` Section 14 | `paper.md:472` | **PASS** |
| **Generator Provenance** | Section 14 documents script-generation provenance disjoint from judge | `paper.md` Section 14 | `paper.md:473` | **PASS** |
| **External Scanner Scope** | Section 14 & Table 11 document that proprietary `mcp-scan` was not run; Tier 2 evaluates author-defined regex | `paper.md` Section 14 | `paper.md:474, Table 11` | **PASS** |
| **Threat Model Scope** | Section 2.5 & Section 14 document single-server scope (cross-server collusion out of scope) | `paper.md` Section 2.5 & 14 | `paper.md:95-105, 475` | **PASS** |
| **Live Transport Scope** | Section 14 documents 5 scripted failure modes evaluated on localhost mock harness (architectural proposals) | `paper.md` Section 14 | `paper.md:440-450, 476` | **PASS** |
| **Production Operator Burden** | Section 1.2, Table 1 & Section 14 mark production burden as unmeasured qualitative factor | `paper.md` Section 1.2, Table 1, 14 | `paper.md:34, Table 1, 477` | **PASS** |
| **Single-Step Sweeps Scope** | Table 11 explicitly documents standalone Mode A/B and integrated sweeps on $N=56$ as Not Done / Future Work | `paper.md` Section 14 & Table 11 | `paper.md:478, Table 11` | **PASS** |
| **Third-Party Exclusions** | Table 11 & Section 10.4 document DeepSeek ($0.00 balance, HTTP 402), qwen3:8b (40% parse rate), and HF (HTTP 402) exclusions | `paper.md` Table 11 & Section 10.4 | `paper.md:410-420, Table 11` | **PASS** |
| **Rule (c) Single Definition** | Evaluates Rule (b) strictly on directly parsed responses without fail-secure fallbacks (Diagnostic / Parsed-Only); chain-equivalent to Rule (a) on V3 unconstrained decoding | `scripts/audit_decision_rules.py` | `paper.md:198, PREREGISTRATION.md:33` | **PASS** |
