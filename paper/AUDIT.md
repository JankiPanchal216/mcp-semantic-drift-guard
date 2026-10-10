# Research Package Audit & Inventory (Phase 0)

**Date**: 2026-10-08  
**Scope**: Full codebase, results traces, and `paper.md` inventory.  
**Baseline Git Commit**: `93834f9` (HEAD) | Historical Data Commit: `381125b09dee2d05f23e170e32762a71f815305d`

---

## 1. Inventory of `[PENDING RE-RUN]` Sections & Items

The following experimental evaluations in `paper.md` are marked `[PENDING RE-RUN]` or `[PENDING]` because raw per-item traces are either unexecuted locally or missing verified trace logs:

| Section in `paper.md` | Target Evaluation | Dataset / Scale | Intended Model | Reason for Pending Status |
|---|---|---|---|---|
| **Section 6.2 & 8.8** | Standalone Semantic Judge Mode A (Full) | Held-out test split ($N=56$) | Local LLM ($T=0$) | Unexecuted locally with per-item trace logging |
| **Section 6.2 & 8.8** | Standalone Semantic Judge Mode B (Diff Only) | Held-out test split ($N=56$) | Local LLM ($T=0$) | Unexecuted locally with per-item trace logging |
| **Section 6.2 & 8.8** | Integrated Guard Middleware (BALANCED) | Held-out test split ($N=56$) | Full Multi-Tier | Unexecuted locally with per-item trace logging |
| **Section 7.1** | Matched-Pair Exploratory Pilot | Matched triplets ($N=24$) | Local LLM | Exploratory pilot unexecuted with trace logs |
| **Section 7.2** | Real Pre-Existing Modifications ($N=13$) | Real repo diffs ($N=13$) | Semantic Guard | Deterministic tiers recorded; LLM guard pending |
| **Section 7.4** | 5-Fold Server-Grouped Cross-Validation | All benchmark items ($N=370$) | Multi-Tier Guard | Requires 370 multi-tier evaluations across 5 folds |
| **Section 8.1** | Tier Ablations (Configs C, D, E, F, G) | Held-out test split ($N=56$) | Varied Subsystems | A, B, H completed; C–G require local sweeps |
| **Section 8.2** | Representation Ablation (Mode A vs Mode B) | Held-out test split ($N=56$) | Local LLM | Direct schema vs diff prompt comparison pending |
| **Section 8.4** | Local Model Comparison on Held-Out Split | Held-out test split ($N=56$) | Qwen3:8B, Gemma3:4B, Qwen2.5:1.5B | Requires multi-model execution sweep |
| **Section 8.5** | Thinking ON vs. OFF Ablation | Held-out test split ($N=56$) | Qwen3:8B | Reasoning token impact sweep pending |
| **Section 8.6** | Prompt Sensitivity & Instruction Robustness | Sensitivity split ($N=20$) | Local LLM | 3 prompt variants $\times$ 20 items pending |
| **Section 8.7** | Run-to-Run Determinism Under Q4_K_M | Held-out test split ($N=56$) | Local LLM | Repeated deterministic decoding sweep pending |
| **Section 9.1** | Adversarial Red-Team Suite v1 (10 Categories) | Red-team test cases ($N=30$) | Multi-Tier Guard | Requires execution with per-item trace logging |
| **Section 9.3** | Adversarial Red-Team Suite v2 (14 Categories) | Red-team v2 cases ($N=28$) | Multi-Tier Guard | Requires execution with per-item trace logging |
| **Section 9.4** | Judge Prompt Injection Sandboxing Pilot | Direct override cases ($N=4$) | Semantic Judge | Direct prompt override pilot pending |
| **Section 1.2 / 4** | Operator Alert-Burden Replay | 621 release transitions | Multi-Tier Guard | Full historical release replay pending |
| **Appendix A.1** | Phase 3 Representation Pilot ($N=10$) | Exploratory pilot ($N=10$) | Local LLM | Historical pilot unverified |
| **Appendix A.2** | Phase 4 Integrated Middleware Replay ($N=10$) | Stratified sample ($N=10$) | Multi-Tier Guard | Historical pilot unverified |

---

## 2. Experiment Configurations (A–H) Inventory

| Config | Architecture Definition | Current Status | Backing Trace / Result |
|---|---|:---:|---|
| **Config A** | Hash Pinning Only (Tier 0) | **Completed** | `results/main_test_hash/predictions.jsonl` (Prec=58.9%, Rec=100.0%, FPR=100.0%) |
| **Config B** | Static Regex Only (Tier 2) | **Completed** | `results/main_test_static/predictions.jsonl` (Prec=100.0%, Rec=75.8%, FPR=0.0%) |
| **Config C** | Hash + Static Regex | `[PENDING]` | Needs execution |
| **Config D** | Hash + Static Regex + Structured Diff | `[PENDING]` | Needs execution |
| **Config E** | Hash + Static Regex + Semantic Judge | `[PENDING]` | Needs execution |
| **Config F** | Full Guard Pipeline (Hash + Schema + Static + Judge) | `[PENDING]` | Needs execution |
| **Config G** | Guard without Deterministic Schema Check (Tier 1.5) | `[PENDING]` | Needs execution |
| **Config H** | Deterministic Fast Path (No LLM) | **Completed (Duplicate)** | Identical to Config B (Prec=100.0%, Rec=75.8%, FPR=0.0%, 0.217 ms) |

*Issue Identified*: Config H is functionally identical to Config B in operational logic (Tier 2 regex filter with unflagged defaulting to ALLOW). This duplication should be merged or clarified.

---

## 3. Judge Model Usage Across Sections

| Section | Model Specified | Execution Status | Observational Notes |
|---|---|:---:|---|
| **Abstract** | `Qwen3-8B` | Specified | Claimed as default architecture judge |
| **Section 2.2** | `Qwen3-8B` (Q4_K_M, T=0) | **Replication Complete** | 1,348 MCPTox instances (13.97% No-Think vs 41.76% Think) |
| **Section 5.2** | `Qwen3-8B` (Mode B, T=0) | Specified | Architecture pipeline specification |
| **Section 6.2 / 8.4** | `Qwen3-8B`, `Gemma3-4B`, `Qwen2.5-1.5B` | `[PENDING RE-RUN]` | Local comparison suite pending |
| **Section 9.5 (Salami V3)**| `gemma3:4b` | **Live Authoritative** | Selected after diagnostic: `qwen3:8b` had 0% parse success on CPU |

*Issue Identified*: The abstract and architecture state `Qwen3-8B`, but the only fully completed live semantic benchmark (Salami Drift V3, 576 calls) used `gemma3:4b`. The paper must unify its judge story and explicitly explain model selection.

---

## 4. Backing Results Files for Completed Tables

1. **Section 4 (Corpus Measurement, 621 releases)**:
   - Data source: `experiments/phase2_extract_corpus.py` output in `results/PHASE2_RESULTS.md`.
2. **Section 6.2 / 8.8 (Deterministic Baselines on Held-Out Test $N=56$)**:
   - `results/computed_metrics.json`
   - `results/main_test_hash/predictions.jsonl` (33 TP, 23 FP)
   - `results/main_test_static/predictions.jsonl` (25 TP, 0 FP, 8 FN)
   - `results/main_test_tfidf/predictions.jsonl` (31 TP, 17 FP, 2 FN)
   - `results/main_test_schema/predictions.jsonl` (0 TP, 0 FP, 33 FN)
3. **Section 7.2 (13 Real Contract Modifications)**:
   - `results/computed_metrics.json`
4. **Section 9.5 (Salami Drift Benchmark V3, $N=144$ transitions, 40 chains)**:
   - `results/salami_drift_v3/computed_metrics.json`
   - `results/salami_drift_v3/run_manifest.json`
   - `results/salami_drift_v3/model_input_audit.json`
   - `results/salami_drift_v3/validation_report.json`
   - `results/salami_drift_v3_per_step/predictions.jsonl` (Adjacent: 17 TP, 104 TN, 0 FP, 23 FN)
   - `results/salami_drift_v3_cumulative/predictions.jsonl` (Cumulative: 25 TP, 102 TN, 2 FP, 15 FN)
   - `results/salami_drift_v3_dual/predictions.jsonl` (Dual: 28 TP, 102 TN, 2 FP, 12 FN)

---

## 5. Audit of Claims vs. Evidence

1. **"Reduces operator reapproval burden"**:
   - *Status*: **Exceeds Evidence**. The full alert-burden replay across the 621 releases is marked `[PENDING: alert-burden replay, Gate 3.1]`. Must be qualified or deferred to future work until measured.
2. **"Capability Paradox" Framing**:
   - *Status*: **Overstated Novelty**. MCPTox (Wang et al.) already reported that reasoning tokens increase attack success rate by ~27.8 percentage points. Our +27.79% is a direct empirical replication and should be credited as such.
3. **Transition-Level McNemar Significance**:
   - *Status*: **Clustering Limitation**. McNemar test ($p=0.02246$ for Dual vs Adjacent; $p=0.21011$ for Cumulative vs Adjacent) treats 144 transitions as i.i.d., whereas transitions are nested within 40 chains. Paired chain-level tests and cluster-bootstrap CIs are required.
4. **Chain-Level False Positives**:
   - *Status*: **Properly Disclosed in V3 Audit, Needs Prominence**. Chain-level benign FPR is 50.0% (8/16 chains), where 6 of 8 flags were caused by JSON delimiter parsing errors rather than semantic false alarms.
5. **Mean Exposure Metric**:
   - *Status*: **Lacks Formal Definition**. The metric (Adjacent: 0.88, Cumulative: 0.42, Dual: 0.38) is reported without a mathematical equation or confidence intervals.
6. **Citation Discrepancies**:
   - MCPTox first author is Zhiqiang Wang (cited as Zhang et al.).
   - ToolHijacker arXiv ID `2407.12345` is a placeholder.
   - Sigstore authors should be Newman, Meyers, Torres-Arias.
   - Llama Guard year is cited as 2024 in text but 2023 in references.
7. **Missing Related Work**:
   - Omits key recent literature: Mas et al. (cryptographic signing against rug pulls, a direct competitor), MCP-SafetyBench, Hou et al., Shen et al., Hasan et al., Hu et al., Bhardwaj et al.
8. **Structural Inconsistencies**:
   - Two different commit hashes (`381125b...` and `d826a89...`) are cited in the paper.
   - Pipeline is introduced as "4-tier" but 5 distinct tiers (0, 1, 1.5, 2, 3) are diagrammed and numbered.
   - Config H duplicates Config B.
   - Repository URL is a generic placeholder (`https://github.com/anonymous-submission/mcp-semantic-drift`).

---

## 6. Commit Hash Canonicalization

- **Authoritative Head Commit**: `93834f9` (contains finalized V3 benchmark, test suite updates, and camera-ready status).
- **Historical Baseline Data Commit**: `381125b09dee2d05f23e170e32762a71f815305d` (produced deterministic baseline traces on held-out split).
- **Recommendation**: Standardize all repository references in Section 12 to commit `93834f9` while noting `381125b` for deterministic test trace provenance.

---

## 7. Prioritized Execution & Compute Plan

| Priority | Task / Phase | Estimated Compute / Duration | Dependencies |
|---|---|---|---|
| **P1** | **Phase 1: Paper-Only Corrections** (Citations, terminology, structural consistency, V1/V2 appendix relocation, claim qualification) | 0 min (Text edits only) | None |
| **P2** | **Phase 2: Related Work Rewrite** (Integrate Mas et al., MCP-SafetyBench, Hou, Shen, Hasan, Hu; build comparison table) | 0 min (Text / bibliography) | None |
| **P3** | **Phase 3: Statistical Rigor & `scripts/stats.py`** (Implement cluster bootstrap on chains, chain-level McNemar, formalize mean exposure) | ~1 min (CPU script execution) | V3 raw traces |
| **P4** | **Phase 4: Judge Robustness & Constrained Parsing** (Constrained JSON parsing, diagnostic on 100 probes, judge selection benchmarking) | ~15–30 min (Local Ollama inference) | Local LLM daemon |
| **P5** | **Phase 5: Re-Run Key Experiments** (Ablations C–G on held-out test split, 13 real modifications, baselines) | ~30–60 min (Local CPU/GPU) | Constrained Judge |
| **P6** | **Phase 6: Reframe Paper** (Salami Drift as lead contribution, new title proposals, rewrite abstract and introduction) | 0 min (Text edits) | Phase 3–5 numbers |
| **P7** | **Phase 7: Final QA & `make_tables.py`** (Regenerate all tables from raw traces, produce `CLAIMS_MATRIX.md`, final scoring) | ~2 min (Validation scripts) | Final tables |
