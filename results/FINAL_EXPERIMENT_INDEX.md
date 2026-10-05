# Master Experiment & Execution Pipeline Index

## 1. Overview

This document maps all experimental phases to their corresponding execution scripts, input datasets, generated output artifacts, and research purposes across the project lifecycle.

---

## 2. Phase-by-Phase Experiment Mapping

### Phase 1: Threat Baseline & Reproduction
- **Script**: `experiments/mcptox_reproduction.py`
- **Input Dataset**: `data/MCPTox/` (1,348 test instances, 45 MCP servers, commit `f85189f`)
- **Output Artifacts**:
  - `results/mcptox_qwen3_8b_pilot.jsonl`
  - `results/mcptox_qwen3_8b_full.json`
  - `results/MCPTox_REPRODUCTION_REPORT.md`
  - `data/mcp_scan_baseline.md`
- **Research Purpose**: Replicate published MCPTox attack success rates (ASR = 41.8% Think / 14.0% No-Think on `Qwen3-8B`), verify the "Capability Paradox", and audit exact SHA-256 tool pinning (`snyk-agent-scan` / `mcp-scan`).

---

### Phase 2: Real-World MCP Evolution Corpus
- **Scripts**:
  1. `experiments/phase2_extract_corpus.py` (Multi-version git tag snapshot extraction)
  2. `experiments/phase2_tool_diff.py` (Pairwise release diff generator & labeler)
- **Input Dataset**: Git commit histories of 28 open-source MCP repositories
- **Output Artifacts**:
  - `data/mcp_corpus.json` (28 indexed servers)
  - `data/mcp_versions.json` (594 tool snapshots)
  - `data/tool_changes.jsonl` (123 recorded definition changes across 621 transitions)
  - `results/PHASE2_RESULTS.md`, `results/PHASE2_CORPUS_REPORT.md`, `results/PHASE2_LABELING_GUIDE.md`
  - `results/figures/change_types_distribution.png`, `results/figures/release_change_rates.png`, `results/figures/changes_by_server.png`
- **Research Purpose**: Quantify the empirical rate of legitimate MCP tool definition evolution (4.99% of releases) and prove that exact hash pinning incurs a 100% false alarm rate on routine maintenance.

---

### Phase 3: Semantic Drift Detector Development & Benchmarking
- **Scripts**:
  1. `experiments/phase3_build_dataset.py` (Deterministic dataset construction & cluster-isolated splitting)
  2. `experiments/phase3_structured_diff.py` (JSON-aware delta engine)
  3. `experiments/evaluate_phase3.py` (Multi-detector exploratory benchmarking)
  4. `experiments/baseline_hash_pinning.py` (SHA-256 exact change baseline evaluator)
- **Input Datasets**:
  - `data/tool_changes.jsonl` (Phase 2 real updates)
  - `data/MCPTox/` (Poisoned tool injections)
- **Output Artifacts**:
  - `data/drift_train.jsonl` (259 examples, 144 clusters)
  - `data/drift_dev.jsonl` (55 examples, 34 clusters)
  - `data/drift_test.jsonl` (56 examples, 31 clusters)
  - `results/phase3_metrics.json`, `results/PHASE3_FINAL_REPORT.md`, `results/PHASE3_ERROR_ANALYSIS.md`, `results/PHASE3_REPRODUCIBILITY.md`
  - Figures in `results/figures/` (F1 comparison, Benign FPR, Ablation, Paradigms)
- **Research Purpose**: Develop and validate the zero-temperature local `qwen3:8b` Semantic Drift Judge, proving that Diff-Only Mode B ($F_1 = 92.3\%$) eliminates 75% of hash false alarms without JSON parse errors.

---

### Phase 4: Middleware Architecture & Replay Evaluation
- **Scripts**:
  1. `experiments/phase4_evaluate.py` (4-Tier middleware replay benchmark)
  2. `tests/test_middleware.py`, `tests/test_baseline.py`, `tests/test_rollback.py`, `tests/test_diff.py`, `tests/test_hash.py`, `tests/test_policy.py`, `tests/test_static_rules.py`
- **Input Dataset**: Stratified 10-example held-out test sample from `data/drift_test.jsonl`
- **Output Artifacts**:
  - `results/PHASE4_DESIGN.md`
  - `results/PHASE4_IMPLEMENTATION_PLAN.md`
  - `results/PHASE4_IMPLEMENTATION_REPORT.md`
  - `results/PHASE4_EVALUATION.md`
- **Research Purpose**: Implement the complete 4-tier pipeline (`MCPGuardMiddleware`), verify policy enforcement (`ALLOW`, `WARN`, `BLOCK`, `QUARANTINE`), persistent SQLite baseline storage, and automatic rollback across 28 unit tests.

---

### Phase 5: Master Benchmark, Red-Team Suite & Live Proxy Socket Interception
- **Scripts**:
  1. `experiments/phase5_red_team_suite.py` (30 adversarial cases across 10 mutation categories)
  2. `experiments/phase5_live_mcp_proxy.py` (Controlled local JSON-RPC socket proxy fixture)
  3. `experiments/phase5_evaluate_full.py` (Comprehensive master benchmark runner)
- **Input Datasets**:
  - `data/drift_test.jsonl` (56 held-out test split examples)
  - `data/drift_dataset_real_updates.jsonl` (123 Phase 2 updates)
  - `experiments/phase5_red_team_suite.py` (30 red-team cases)
- **Output Artifacts**:
  - `results/PHASE5_PLAN.md`
  - `results/PHASE5_RESULTS.md`
  - `results/PHASE5_ERROR_ANALYSIS.md`
  - `results/PHASE5_REPRODUCIBILITY.md`
  - `results/PHASE5_DECISION.md`
  - `results/figures/phase5/phase5_f1_comparison.png`
  - `results/figures/phase5/phase5_benign_fpr_comparison.png`
  - `results/figures/phase5/phase5_redteam_evasion_rates.png`
- **Research Purpose**: Perform full-scale benchmark evaluation across N=56 test split ($F_1 = 100.0\%$, Benign FPR = 0.0%), assess robustness across 30 adversarial red-team transformations (70.0% detection rate), and verify real-time `tools/list` JSON-RPC socket proxy interception and baseline rollback (Status: PASS).
