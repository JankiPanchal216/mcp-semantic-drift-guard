# Reviewer Gap Analysis: MCP Semantic Drift Detection

## 1. Overview

This document presents a comprehensive gap analysis of the current research package (Phases 1–6) against rigorous peer-review evaluation criteria for AI security and software engineering venues. It delineates verified experimental strengths, identified vulnerabilities and methodological limitations, and maps out required upgrades.

---

## 2. Current Strengths of the Research Package

1. **First Real-World Empirical Corpus of MCP Tool Evolution**: Mined and indexed 594 version snapshots across 28 open-source servers and 621 release transitions, establishing the ground truth that ~5% of releases introduce tool contract evolution.
2. **Deterministic Baseline Reproduction**: Successfully reproduced the MCPTox baseline on `Qwen3-8B` (ASR = 41.76% Think / 13.97% No-Think across 1,348 instances), validating the "Capability Paradox".
3. **Structured Delta Abstraction (Mode B)**: Demonstrated that isolating JSON-aware diff fields (`params_added`, `description_diff_summary`) eliminates context bloat and output formatting errors on 8B models.
4. **Operational 4-Tier Middleware with Rollback**: Implemented and verified complete enforcement middleware with sub-millisecond fast paths, SQLite baseline persistence, JSON-RPC response interception, and automatic definition rollback.
5. **Cluster-Isolated Benchmarking**: Established zero-cluster-leakage partitioning (`server_id + tool_name`) on the 370-example dataset.

---

## 3. Identified Weaknesses & Methodological Gaps

1. **Class / Style Confound in Positive vs. Negative Data**: Malicious examples were predominantly synthetic MCPTox mutations on standard stubs, whereas benign examples were real open-source tool updates. A matched-pair evaluation using identical tool contracts is necessary.
2. **Over-Emphasis on Hash Pinning's 100% FPR**: Exact hashing detects any byte-level change by design. Framing this as a novel detection failure misrepresents hash pinning; it should be framed as quantifying the *alert burden* imposed by legitimate maintenance.
3. **Domination of Additions/Removals**: 110 of 123 recorded Phase 2 changes were tool additions/deprecations, with only 13 contract modifications to existing tools. Evaluation must evaluate existing-tool modifications separately.
4. **Adversarial Red-Team Evasion Surfaces**: Red-teaming revealed complete evasion (0/3 detected) on optional parameter default injections and low-signal boolean schema toggles (`readOnly: True` $\rightarrow$ `False`).
5. **Lack of Server-Level Cross-Validation**: While `server_id + tool_name` clusters were isolated, multiple tools from the same server could appear across train and test splits.
6. **Hard Negative and Static Rule Provenance**: Provenance and pre-registration of hard negatives and regex rules need explicit auditing to rule out post-hoc tuning.
7. **Rollback Safety Under Breaking Schema Changes**: Serving V1 contracts to clients when the server expects V2 can cause runtime parameter mismatches if parameters were renamed or made required.
8. **Single Model Dominance & Local CPU Latency**: Primary evaluation relied on `Qwen3-8B` on CPU (~30.5 s per changed tool). Comparison with alternative local models and thinking ablations is needed.

---

## 4. Status of Reviewer Recommendations

| Recommendation | Status | Required Action |
|---|---|---|
| Headline Reframing (Alert Burden vs. Semantic Drift) | **Pending** | Reframe narrative in `results/REVIEWER_REFRAMING.md` and report. |
| Matched-Pair Dataset Experiment | **Requires Experiment** | Generate controlled mutations on real tool contracts in `data/matched_pairs.jsonl`. |
| Hard Negative Provenance Audit | **Audit Required** | Document exact origins in `results/HARD_NEGATIVE_PROVENANCE.md`. |
| Static Rule Leakage Audit | **Audit Required** | Analyze regex rules vs. MCPTox templates in `results/STATIC_RULE_LEAKAGE_AUDIT.md`. |
| Server-Level Cross-Validation | **Requires Experiment** | Run Leave-One-Server-Out / Server-K-Fold CV and record in `results/CROSS_VALIDATION_RESULTS.md`. |
| Real Existing-Tool Modification Subset | **Requires Experiment** | Evaluate the 13 modified existing tools in `results/REAL_CONTRACT_MODIFICATION_EVALUATION.md`. |
| Deterministic Schema Security Checks | **Requires Implementation** | Implement `guard/schema_security_rules.py` and unit tests. |
| Fresh Adversarial Red-Team v2 Dataset | **Requires Experiment** | Construct expanded 14-category suite in `data/redteam_v2.jsonl`. |
| Judge-Attack Resilience | **Requires Experiment** | Test adversarial prompt overrides targeting the judge. |
| Salami Drift Evaluation | **Requires Experiment** | Multi-version incremental mutation test in `results/SALAMI_DRIFT_EVALUATION.md`. |
| New-Tool Poisoning Policy | **Requires Implementation** | Explicit handling of new tool additions in `guard/middleware.py`. |
| Rug-Pull Timing Test | **Requires Experiment** | Delayed poisoning test in `results/RUG_PULL_EVALUATION.md`. |
| Embedding / Cosine Baseline | **Requires Experiment** | Implement `experiments/baseline_embedding.py` and benchmark. |
| Full-Def vs. Diff-Only Extended Ablation | **Requires Experiment** | Run Mode A vs. Mode B across extended benchmark. |
| Model Comparison (`Qwen3-8B`, `Qwen2.5-1.5B`, `Gemma3-4B`) | **Requires Experiment** | Benchmark available local Ollama models. |
| Thinking ON/OFF Judge Ablation | **Requires Experiment** | Compare reasoning tokens on vs. off for semantic judge. |
| Full Tier Ablation (A through H) | **Requires Experiment** | Comprehensive component ablation in `results/TIER_ABLATION.md`. |
| Prompt Sensitivity Evaluation | **Requires Experiment** | Test equivalent prompt variations in `results/PROMPT_SENSITIVITY.md`. |
| Run-to-Run Determinism | **Requires Experiment** | Multi-run variance check in `results/DETERMINISM_EVALUATION.md`. |
| Latency & Staging Profiling | **Requires Experiment** | Component-by-component latency breakdown in `results/LATENCY_EVALUATION.md`. |
| Failure & Timeout Policy | **Requires Test** | Test 8 failure modes in `results/FAILURE_POLICY_EVALUATION.md`. |
| Rollback Safety & Schema Incompatibility | **Requires Test** | Analyze V1/V2 contract breakage in `results/ROLLBACK_SAFETY.md`. |
| Threat Model Adaptive Attacker Update | **Writing Required** | Update `results/THREAT_MODEL.md` with full adaptive capabilities. |
| Related Work Formal Literature Review | **Writing Required** | Comprehensive literature catalog in `results/RELATED_WORK_NOTES.md`. |
| Restructured Academic Report | **Writing Required** | Produce `results/FINAL_RESEARCH_REPORT_REVIEWER_READY.md`. |

---

## 5. Files to be Added and Maintained

### New Modules & Test Files
- `guard/schema_security_rules.py`
- `tests/test_schema_security.py`
- `tests/test_reviewer_scenarios.py`
- `experiments/baseline_embedding.py`
- `experiments/run_reviewer_evaluations.py`

### New Datasets
- `data/matched_pairs.jsonl`
- `data/redteam_v2.jsonl`

### New Reports & Analyses (in `results/`)
- `REVIEWER_GAP_ANALYSIS.md`
- `REVIEWER_REFRAMING.md`
- `MATCHED_PAIR_DATASET.md`
- `HARD_NEGATIVE_PROVENANCE.md`
- `STATIC_RULE_LEAKAGE_AUDIT.md`
- `CROSS_VALIDATION_RESULTS.md` & `cross_validation_results.json`
- `REAL_CONTRACT_MODIFICATION_EVALUATION.md`
- `SCHEMA_SECURITY_CHECKS.md`
- `REDTEAM_V2_DATASET.md`
- `SALAMI_DRIFT_EVALUATION.md`
- `RUG_PULL_EVALUATION.md`
- `EMBEDDING_BASELINE.md`
- `SEMANTIC_MODE_ABLATION.md`
- `MODEL_COMPARISON.md`
- `THINKING_ABLATION.md`
- `TIER_ABLATION.md`
- `PROMPT_SENSITIVITY.md`
- `DETERMINISM_EVALUATION.md`
- `LATENCY_EVALUATION.md`
- `FAILURE_POLICY_EVALUATION.md`
- `ROLLBACK_SAFETY.md`
- `RELATED_WORK_NOTES.md`
- `STATISTICAL_REPORTING.md`
- `FINAL_REVIEWER_COMPARISON.md`
- `FINAL_REVIEWER_ERROR_ANALYSIS.md`
- `REVIEWER_REPRODUCIBILITY.md`
- `FINAL_CLAIM_AUDIT.md`
- `REVIEWER_UPGRADE_DECISION.md`
- `FINAL_ABSTRACT_REVIEWER_READY.md`
- `FINAL_RESEARCH_REPORT_REVIEWER_READY.md`
