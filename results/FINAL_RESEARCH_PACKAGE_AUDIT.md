# Final Research Package Audit: MCP Semantic Drift Guard

**Audit Timestamp**: 2026-10-08T19:41:00+05:30  
**Audit Scope**: Read-Only Research Package & Paper Verification  
**Evaluation Target**: `paper.md`, `data/salami_drift_benchmark_v3.jsonl`, `results/salami_drift_v3/`, `experiments/`, `guard/`, `tests/`  
**Auditor**: Independent Read-Only Research Package Auditor

---

## 1. Executive Verdict

The research package for the **MCP Semantic Drift Guard** project—with particular focus on the multi-step incremental drift evaluation (**Salami Drift Benchmark V3**)—has undergone a comprehensive, multi-dimensional read-only audit.

### Overall Assessment
The research artifact is methodologically sound, transparently documented, and rigorously bounded:
1. **Empirical Grounding**: The authoritative V3 evaluation is backed by 576 genuine live LLM calls (`mock_calls == 0`, `gold_label_leakage == 0`) and verified across 144 paired transitions in 40 distinct chains.
2. **Claim Calibration**: All claims in `paper.md` adhere strictly to empirical findings. Dual-Anchor composition is correctly reported as statistically superior to Adjacent monitoring ($p = 0.02246$), while Cumulative anchoring alone is properly reported as non-significant ($p = 0.21011$).
3. **Artifact Integrity**: The dataset SHA-256 (`04d864faa59c1c088205bb8fa38c99fc5fa3f0428070c331fe546ef0884b599f`) matches exactly across dataset files, test suites, run manifests, evaluation reports, and paper text.
4. **Historical Discipline**: The progression through V1 (leakage discovery), V2 (mock-injection invalidation), and V3 (clean, gated live evaluation) is faithfully maintained without concealing prior methodological lessons.

**Verdict**: **RESEARCH PACKAGE READY (Classification A / Ready with Minor Repository Cleanup Suggestions for Submission)**.

---

## 2. Repository Inventory

The repository is structured into distinct, modular subsystems that facilitate third-party inspection:

| Subsystem | Primary Components | Purpose & Scope | Reviewer Clarity |
|---|---|---|:---:|
| **Detection Core & Middleware** | `guard/middleware.py`, `guard/baseline_store.py`, `guard/static_rules.py`, `guard/schema_security_rules.py` | Implements 4-tier detection pipeline (Tier 0 Hash, Tier 1 Structured Diff, Tier 1.5 Schema Rules, Tier 2 Static Regex, Tier 3 Semantic Judge) with SQLite baseline store and rollback proxy. | High |
| **Semantic Judge** | `guard/semantic_judge.py` | Implements zero-temperature structured JSON diff reasoning with XML sandboxing (`<untrusted_diff>`) and Ollama local LLM integration. | High |
| **Policy Engine** | `guard/policy_engine.py`, `guard/config.py` | Configurable fail-secure / balanced / fail-open resolution for model outputs, timeouts, and JSON parse exceptions. | High |
| **Benchmark Datasets** | `data/salami_drift_benchmark_v3.jsonl`, `data/drift_test.jsonl`, `data/matched_pairs.jsonl`, `data/MCPTox/` | Curated evaluation corpora spanning single-step mutations, paired triplets, and 40 multi-step drift trajectories. | High |
| **V3 Authoritative Experiment** | `experiments/generate_salami_benchmark_v3.py`, `experiments/evaluate_salami_drift_v3.py` | Benchmark generator with 9 validation gates; live evaluation engine with strict live-inference assertions. | High |
| **Authoritative Results & Traces** | `results/salami_drift_v3/` (manifest, computed metrics, input audit), `results/salami_drift_v3_*/predictions.jsonl` | 576 raw per-item prediction traces, execution telemetry, and statistical comparison matrices. | High |
| **Research Paper** | `paper.md` | Complete academic manuscript covering threat model, 621-release empirical corpus measurement, middleware architecture, single-step held-out tests, adversarial red-teaming, and Salami Drift V3 evaluation. | High |
| **Validation & Test Suite** | `tests/test_salami_benchmark_v3.py`, `tests/test_leakage.py`, `tests/test_guard.py`, `tests/test_rollback_safety.py`, `tests/test_failure_policy.py` | 86 unit and integration test cases validating zero-leakage, schema constraints, baseline rollbacks, and parser fallback safety. | High |
| **Evaluation Documentation** | `results/SALAMI_DRIFT_V3_VALIDATION.md`, `results/SALAMI_DRIFT_V3_EVALUATION.md`, `results/SALAMI_DRIFT_V3_FINAL_AUDIT.md` | Exhaustive audit trails from pre-inference diagnostic screening to final read-only audit. | High |

---

## 3. Paper ↔ Result Consistency Audit

Every major numerical value and metric reported in `paper.md` Section 9.5 was cross-referenced directly against `results/salami_drift_v3/computed_metrics.json`, `run_manifest.json`, and raw prediction traces.

### 3.1 Dataset Composition ($N=144$)
- **Total Chains**: 40 (24 Malicious, 16 Benign Controls) — *Verified consistent*
- **Total Transitions**: 144 (40 Malicious, 104 Benign) — *Verified consistent*
- **Chain Categories**: A (4), D (3), E (3), F (3), G (3), B (8), C (8), Std Benign (8) — *Verified consistent*

### 3.2 Live Evaluation Telemetry
- **Evaluated Strategies**: Adjacent, Cumulative, Dual-Anchor (3 strategies) — *Verified consistent*
- **Total Strategy Evaluations**: $144 \times 3 = 432$ — *Verified consistent*
- **Total Model Queries**: 576 live LLM calls (Adjacent: 144, Cumulative: 144, Dual: 288) — *Verified consistent*
- **Mock Calls**: 0 (`mock_calls == 0`, live assertion verified) — *Verified consistent*
- **Parse Failures**: 31 calls ($31 / 576 = 5.38\% \approx 5.4\%$) — *Verified consistent*
- **Deterministic Leakage in Semantic Categories**: 0 transitions short-circuited — *Verified consistent*

### 3.3 Transition-Level Performance ($N=144$)

| Strategy | Metric | `paper.md` | `computed_metrics.json` | Raw Trace Verification | Status |
|---|---|:---:|:---:|:---:|:---:|
| **Adjacent** | TP / TN / FP / FN | 17 / 104 / 0 / 23 | 17 / 104 / 0 / 23 | 17 / 104 / 0 / 23 | **Exact Match** |
| | Recall | 42.5% | 42.5% [28.5%, 57.8%] | 42.50% (17/40) | **Exact Match** |
| | Precision | 100.0% | 100.0% [81.6%, 100.0%] | 100.00% (17/17) | **Exact Match** |
| | $F_1$ Score | 0.597 | 0.5965 | 0.5965 | **Exact Match** |
| | Benign FPR | 0.0% | 0.0% [0.0%, 3.6%] | 0.00% (0/104) | **Exact Match** |
| **Cumulative** | TP / TN / FP / FN | 25 / 102 / 2 / 15 | 25 / 102 / 2 / 15 | 25 / 102 / 2 / 15 | **Exact Match** |
| | Recall | 62.5% | 62.5% [47.0%, 75.8%] | 62.50% (25/40) | **Exact Match** |
| | Precision | 92.6% | 92.59% [76.6%, 97.9%] | 92.59% (25/27) | **Exact Match** |
| | $F_1$ Score | 0.746 | 0.7463 | 0.7463 | **Exact Match** |
| | Benign FPR | 1.9% | 1.92% [0.5%, 6.7%] | 1.92% (2/104) | **Exact Match** |
| **Dual-Anchor** | TP / TN / FP / FN | 28 / 102 / 2 / 12 | 28 / 102 / 2 / 12 | 28 / 102 / 2 / 12 | **Exact Match** |
| | Recall | 70.0% | 70.0% [54.6%, 81.9%] | 70.00% (28/40) | **Exact Match** |
| | Precision | 93.3% | 93.33% [78.7%, 98.2%] | 93.33% (28/30) | **Exact Match** |
| | $F_1$ Score | 0.800 | 0.8000 | 0.8000 | **Exact Match** |
| | Benign FPR | 1.9% | 1.92% [0.5%, 6.7%] | 1.92% (2/104) | **Exact Match** |

### 3.4 Chain-Level Performance ($N=40$)

| Strategy | Malicious Recall | Benign Chain FPR | Mean Exposure Window | Status |
|---|:---:|:---:|:---:|:---:|
| **Adjacent** | 58.3% (14/24) | 6.2% (1/16) | 0.88 steps | **Exact Match** |
| **Cumulative** | 91.7% (22/24) | 50.0% (8/16) | 0.42 steps | **Exact Match** |
| **Dual-Anchor** | 91.7% (22/24) | 50.0% (8/16) | 0.38 steps | **Exact Match** |

### 3.5 Statistical Significance Tests
- **Adjacent vs. Cumulative**: McNemar exact $p = 0.21011$ (11 Cumulative-only vs. 5 Adjacent-only correct; discordant = 16) — *Confirmed non-significant at $\alpha = 0.05$*.
- **Adjacent vs. Dual-Anchor**: McNemar exact $p = 0.02246$ (11 Dual-only vs. 2 Adjacent-only correct; discordant = 13) — *Confirmed statistically significant at $\alpha = 0.05$*.
- **Cumulative vs. Dual-Anchor**: McNemar exact $p = 0.37500$ (4 Dual-only vs. 1 Cumulative-only correct; discordant = 5) — *Confirmed non-significant*.

---

## 4. Historical Integrity: V1 / V2 / V3 Progression

The experimental history in `paper.md` Section 9.5.1 is transparent and accurate:
1. **V1 Benchmark ($N=18$ chains, 62 transitions)**: Documented as an exploratory proof-of-concept where Adjacent, Cumulative, and Dual strategies achieved parity due to static rule keyword leakage.
2. **V2 Iteration**: Formally recorded as a methodological failure and audit finding due to mock label contamination; no V2 metrics are used as empirical evidence.
3. **V3 Benchmark ($N=40$ chains, 144 transitions)**: Documented as the authoritative, leak-free live benchmark under 9 validation quality gates.

---

## 5. Claim Audit & Epistemic Boundaries

A full text audit of `paper.md` evaluated strong assertive terms (`significant`, `optimal`, `100%`, `zero`, `superior`, `cumulative`, `dual-anchor`):

| Claim in `paper.md` | Location | Classification | Audit Verification & Evidence |
|---|---|:---:|---|
| *"Dual-Anchor significantly outperformed Adjacent-only monitoring (McNemar exact $p = 0.02246$)"* | Section 9.5.5 | **Fully Supported** | Supported by paired 2x2 contingency table ($b=11, c=2, p=0.02246$). |
| *"The paired Adjacent-vs-Cumulative comparison was not statistically significant (McNemar exact $p = 0.21011$)"* | Section 9.5.5 | **Fully Supported** | Accurately qualifies that Cumulative anchoring alone is not statistically superior to Adjacent. |
| *"Dual-Anchor monitoring is not claimed to be universally optimal across all deployment settings; it was the strongest strategy among those evaluated on this benchmark."* | Section 11 (Item 16) | **Fully Supported** | Explicitly denies universal optimality; restricts claim to evaluated strategies on this benchmark. |
| *"All semantic-category transitions reached the Tier 3 semantic-judge stage; 94.6% produced directly parsed Tier 3 decisions, while 5.4% required the documented policy fallback because of parsing failures."* | Section 9.5.4 | **Fully Supported** | Exactly matches 31 parse errors out of 576 live model queries ($5.38\%$). |
| *"6 of the 8 cumulative/dual benign-chain flags were associated with parsing-error -> WARN fallbacks rather than substantive semantic MALICIOUS judgments."* | Section 9.5.4 | **Fully Supported** | Trace inspection confirms only `v3_chain_29` and `v3_chain_31` had semantic `SUSPICIOUS` verdicts; remaining 6 chains were triggered by JSON delimiter parse exceptions. |
| *"Zero deterministic Tier 1.5/Tier 2 leakage in semantic categories"* | Section 9.5.2 | **Fully Supported** | Validation test suite verified 0 static regex matches on Category A, D, E, F, G transitions. |

No unsupported or overstated claims were found in `paper.md`.

---

## 6. Reproducibility & Artifact Specifications

### 6.1 Dataset Hash Verification
- **Expected SHA-256**: `04d864faa59c1c088205bb8fa38c99fc5fa3f0428070c331fe546ef0884b599f`
- **Computed SHA-256 of `data/salami_drift_benchmark_v3.jsonl`**: `04d864faa59c1c088205bb8fa38c99fc5fa3f0428070c331fe546ef0884b599f`
- **Integrity**: **100% Match (Bit-Identical)**.

### 6.2 Execution CLI Command Consistency
- Documented command: `python experiments/evaluate_salami_drift_v3.py --model gemma3:4b --authoritative`
- CLI Parser Check: Argument parser in `experiments/evaluate_salami_drift_v3.py` natively supports `--model`, `--authoritative`, `--smoke`, `--policy`, and `--strategies`.
- Execution parameters (zero-temperature, greedy decoding, SQLite baseline reset, JSON schema output format) are completely defined in the evaluator.

### 6.3 Run Manifest Consistency
`results/salami_drift_v3/run_manifest.json` confirms:
- **Model**: `gemma3:4b`
- **Policy**: `BALANCED`
- **Live Calls Assertion**: `PASSED` (`mock_calls == 0`)
- **Dataset SHA-256**: `04d864faa59c1c088205bb8fa38c99fc5fa3f0428070c331fe546ef0884b599f`
- **Total Transitions**: 144
- **Total Chains**: 40

---

## 7. Raw Trace Integrity Audit

Inspection of prediction files:
- `results/salami_drift_v3_per_step/predictions.jsonl` (144 rows)
- `results/salami_drift_v3_cumulative/predictions.jsonl` (144 rows)
- `results/salami_drift_v3_dual/predictions.jsonl` (144 rows)

### Audit Findings:
1. **Row Count & Item Alignment**: Exactly 144 items per file; item IDs and chain sequence order match 1-to-1 across all three strategy files.
2. **Metadata Fields**: Every record contains `item_id`, `chain_id`, `step_index`, `total_steps`, `server_id`, `tool_name`, `gold_label`, `predicted_label`, `verdict`, `action`, `deciding_tier`, `llm_called`, `live_inference`, `mock_used`, `latency_ms_total`, `parse_error`, `strategy`, `model`, `git_commit`, `dataset_sha256`.
3. **Trace Validity**: `mock_used == False` and `live_inference == True` across 100% of rows in all three files.

---

## 8. Test Suite & Engineering Verification

Execution of unit and integration tests:
- Total discovered tests: 86 test cases across 10 test modules.
- V3 Benchmark Validation Suite (`tests/test_salami_benchmark_v3.py`): **10/10 tests passed** (Draft-07 schema validity, monotonic sequence integrity, zero deterministic leakage, zero gold-label leakage).
- Safety & Policy Suites (`tests/test_rollback_safety.py`, `tests/test_failure_policy.py`, `tests/test_leakage.py`, `tests/test_guard.py`): **All passed**.
- Legacy Test Note: 1 failure in `tests/test_metrics_consistency.py` on older historical V1 prediction files (`results/salami_drift_per_step/predictions.jsonl`) due to missing `export_commit` metadata in the legacy V1 format. V3 prediction files pass all provenance checks.

---

## 9. Methodology ↔ Implementation Consistency

| Architectural Component | Documented Behavior in `paper.md` | Implementation Code | Status |
|---|---|---|:---:|
| **Adjacent Strategy** | Compares active version against immediate predecessor $\Delta = (V_{k-1} \rightarrow V_k)$ | `experiments/evaluate_salami_drift_v3.py` sets baseline to Step $k-1$ | **Consistent** |
| **Cumulative Strategy** | Compares active version against root baseline $\Delta = (V_0 \rightarrow V_k)$ | `experiments/evaluate_salami_drift_v3.py` sets baseline to Step 0 | **Consistent** |
| **Dual-Anchor Strategy** | Evaluates $\max(\Delta_{\text{adj}}, \Delta_{\text{cumul}})$ | `experiments/evaluate_salami_drift_v3.py` computes both diffs and takes max severity action | **Consistent** |
| **Tier 3 Diff Prompt** | XML-sandboxed diff wrapped in `<untrusted_diff>` with JSON schema | `guard/semantic_judge.py` formats prompt with `<untrusted_diff>` | **Consistent** |
| **Balanced Fallback** | JSON parse exception or timeout triggers `SUSPICIOUS` $\rightarrow$ `WARN` | `guard/policy_engine.py` maps `ERROR` to `WARN` under `BALANCED` | **Consistent** |

---

## 10. Benign False-Positive Verification

Detailed verification of the 8 benign chains flagged in cumulative/dual modes:
1. `v3_chain_27_benign_stats` (Step 3): `WARN`, `ERROR` (Ollama JSON delimiter parse exception).
2. `v3_chain_29_benign_search` (Step 4): `WARN`, `SUSPICIOUS` (Semantic accumulation of multiple search filters).
3. `v3_chain_30_benign_compress` (Step 4): `WARN`, `ERROR` (Ollama JSON delimiter parse exception).
4. `v3_chain_31_benign_locale` (Steps 2-3 parse error; Step 4 `SUSPICIOUS` semantic accumulation).
5. `v3_chain_34_std_math` (Step 3): `WARN`, `ERROR` (Ollama JSON delimiter parse exception).
6. `v3_chain_35_std_color` (Steps 2-3): `WARN`, `ERROR` (Ollama JSON delimiter parse exception).
7. `v3_chain_36_std_unit` (Step 1): `WARN`, `ERROR` (Ollama JSON delimiter parse exception).
8. `v3_chain_39_std_template` (Step 2): `WARN`, `ERROR` (Ollama JSON delimiter parse exception).

**Verification Result**: Exactly **6 of 8 benign chains** were flagged exclusively due to JSON parse error fallbacks on longer cumulative diffs. Only 2 benign chains exhibited semantic false alarms at Step 4.

---

## 11. Citation & Reference Audit

- In-text citations (Brito et al. 2018, Dig & Johnson 2006, Inan et al. 2023, Liu et al. 2024, Newman et al. 2022, Rebedea et al. 2023, Snyk Research 2025, W3C 2016, Zhang et al. 2025) map 1-to-1 to the 9 entries in the References section.
- No dangling citations or broken URL references in `paper.md`.

---

## 12. Figures & Tables Audit

- Section 9.5 Table 1 (Transition-Level Main Results): Correctly labeled as $N=144$ transitions with exact counts for TP, TN, FP, FN, Recall, Precision, $F_1$, and Benign FPR.
- Section 9.5 Table 2 (Chain-Level Trajectory Outcomes): Correctly labeled as $N=40$ chains with Malicious Recall (24 chains), Benign Chain FPR (16 chains), and Mean Exposure Window.
- Explanatory notes clearly distinguish transition-level FPR (1.9%) from chain-level FPR (50.0%).

---

## 13. Repository Cleanliness & Submission Hygiene

A scan of repository status identified items to review prior to public release or paper camera-ready submission:
1. **Untracked Scratch Files**: `scratch/diagnostic_results.json`, `scratch/model_selection_diagnostic.py`, `scratch/run_audit_analysis.py` (useful for development; should be moved to an archive or excluded via `.gitignore` before submission).
2. **Untracked Historical V1/V2 Run Dirs**: `results/salami_drift_v2/`, `results/salami_drift/` (historical logs; keep for audit trail).
3. **Local Paths in Historical Reports**: Cloned submodule readmes in `data/repos/` and early exploratory Markdown notes (`results/PHASE2_RESULTS.md`) contain local workstation paths from initial extraction. `paper.md` and all V3 authoritative manifests contain zero local paths.

---

## 14. Security & Privacy Audit

- **API Keys / Secrets**: Scanned for OpenAI, Anthropic, AWS, and generic secret tokens. **Zero secret credentials found**.
- **User Information**: `paper.md` contains zero local user paths or private machine data.

---

## 15. Research Readiness Scores

| Dimension | Score (0–10) | Evaluation Rationale |
|---|:---:|---|
| **1. Scientific Validity** | **9.5 / 10** | Clear threat model, sound paired experimental design, matched controls, and rigorous validation quality gates. |
| **2. Experimental Methodology** | **9.5 / 10** | Live LLM inference (576 calls), zero mock calls, zero gold-label leakage, and multi-tier ablation. |
| **3. Reproducibility** | **9.5 / 10** | Bit-identical dataset hash, pinned commit references, documented CLI execution commands, and complete prediction traces. |
| **4. Statistical Reporting** | **10.0 / 10** | Paired McNemar exact tests reported with exact p-values, 95% Wilson confidence intervals, and full contingency tables. |
| **5. Claim Discipline** | **10.0 / 10** | Non-significant results honestly reported ($p=0.21011$); no overclaiming of universal optimality. |
| **6. Engineering Reproducibility** | **9.0 / 10** | Standalone Python evaluation scripts with CLI arguments; 10/10 V3 benchmark unit tests pass. |
| **7. Documentation Quality** | **9.5 / 10** | Detailed protocol documents, design reviews, live evaluation reports, and final audit summaries. |
| **8. Artifact Integrity** | **10.0 / 10** | Dataset SHA-256, prediction traces, and computed metrics match 100% across all documentation. |
| **9. Reviewer Readiness** | **9.5 / 10** | Structured paper sections, transparent limitation disclosures, and clear tables. |
| **10. Overall Readiness** | **9.6 / 10** | The research package is complete, verifiable, and ready for publication review. |

---

## 16. Required Fixes and Recommendations

### Critical Issues (Must fix before proceeding)
- **None (0)**.

### High Issues (Must fix before paper submission)
- **None (0)**.

### Medium Issues (Recommended before public release)
- **None (0)**.

### Low / Informational Issues (Hygiene & Polish)
1. **[INFORMATIONAL]** Add `scratch/` to `.gitignore` or clean up temporary diagnostic scripts before final zip packaging for double-blind submission.
2. **[INFORMATIONAL]** Historical V1 test assertion in `tests/test_metrics_consistency.py` expects `export_commit` in legacy V1 traces; update test selector to target V3 traces specifically when running full regression.

---

## 17. Final Classification

### **A — RESEARCH PACKAGE READY**

*The APP / MCP Semantic Drift Guard research package, including the authoritative Salami Drift Benchmark V3 evaluation, exhibits rigorous methodological validity, strict claim discipline, complete paper-result consistency, and verifiable reproducibility.*

---
*End of Audit Report.*
