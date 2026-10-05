# Final Reproducibility Guide: MCP Semantic Drift Detection

## 1. System & Environment Specifications

The entire research pipeline is designed for strict deterministic reproduction on standard local workstations:

- **Host Operating System**: Windows 11 / Windows 10 (or Linux / macOS with path adjustments)
- **Python Version**: Python 3.12 (or 3.11)
- **Local LLM Engine**: Ollama (v0.35.1+) serving `qwen3:8b` (Quantization: `Q4_K_M`)
- **LLM Decoding Parameters**: Temperature $T = 0.0$, top_p $= 1.0$, fixed seed $= 42$
- **Database Engine**: Python standard library `sqlite3`
- **Plotting & Numerical Libraries**: `matplotlib >= 3.8.0`, `numpy >= 1.26.0`

---

## 2. Project Directory Structure

```
APP/
├── data/
│   ├── MCPTox/                           # MCPTox benchmark dataset files
│   ├── drift_dataset_real_updates.jsonl   # 123 authentic Phase 2 tool modifications
│   ├── drift_train.jsonl                  # 259 training examples (0 cluster leakage)
│   ├── drift_dev.jsonl                    # 55 development split examples
│   ├── drift_test.jsonl                   # 56 held-out test split examples
│   ├── mcp_corpus.json                    # 28 surveyed open-source MCP repositories
│   └── mcp_versions.json                  # 594 indexed tool snapshot records
├── experiments/
│   ├── baseline_hash_pinning.py           # SHA-256 exact tool definition hasher
│   ├── evaluate_phase3.py                 # Phase 3 exploratory judge evaluator
│   ├── mcptox_reproduction.py             # Phase 1 MCPTox Qwen3-8B reproduction script
│   ├── phase2_extract_corpus.py           # Phase 2 git tag multi-version extractor
│   ├── phase2_tool_diff.py                # Phase 2 pairwise version diff comparator
│   ├── phase3_build_dataset.py            # Deterministic dataset builder & cluster splitter
│   ├── phase3_structured_diff.py          # JSON-aware contract delta engine
│   ├── phase4_evaluate.py                 # Phase 4 middleware replay benchmark
│   ├── phase5_evaluate_full.py            # Phase 5 master benchmark runner
│   ├── phase5_live_mcp_proxy.py           # Controlled local JSON-RPC socket proxy fixture
│   └── phase5_red_team_suite.py           # 30-case adversarial red-team generator
├── guard/
│   ├── audit_logger.py                    # JSONL structured audit event logger
│   ├── baseline_store.py                  # SQLite database manager & normalizer
│   ├── config.py                          # GuardConfig dataclass configuration
│   ├── middleware.py                      # MCPGuardMiddleware 4-tier pipeline
│   ├── policy_engine.py                   # PolicyEngine enforcement logic
│   ├── semantic_judge.py                  # Mode B Ollama prompt builder & JSON parser
│   └── static_rules.py                    # Heuristic regex rules & evaluators
├── results/                               # Master reports, metrics, error analyses, decisions
│   └── figures/                           # Visualizations for Phase 2, Phase 3, and Phase 5
└── tests/                                 # 28 unit tests for all middleware components
```

---

## 3. Step-by-Step Reproduction Commands

### Step 1: Run Middleware Unit Test Suite (28 Tests)
```bash
# Verified: 28/28 tests passing in ~0.35s
python -m unittest discover tests
```

### Step 2: Reproduce Phase 1 (MCPTox Qwen3-8B Reproduction)
```bash
# Runs live pilot verification and calculates full ASR across 1,348 test instances
python experiments/mcptox_reproduction.py
```
*Output Artifacts*: `results/mcptox_qwen3_8b_pilot.jsonl`, `results/mcptox_qwen3_8b_full.json`, `results/MCPTox_REPRODUCTION_REPORT.md`

### Step 3: Reproduce Phase 2 (Real-World MCP Corpus Extraction & Diffing)
```bash
# 1. Extract tool snapshots across 28 repositories (594 snapshots)
python experiments/phase2_extract_corpus.py

# 2. Compute pairwise diffs across 621 transitions (123 changes)
python experiments/phase2_tool_diff.py
```
*Output Artifacts*: `data/mcp_corpus.json`, `data/mcp_versions.json`, `data/tool_changes.jsonl`, `results/PHASE2_RESULTS.md`

### Step 4: Reproduce Phase 3 (Dataset Generation & Exploratory Evaluation)
```bash
# 1. Build cluster-isolated 370-example dataset with fixed seed 42
python experiments/phase3_build_dataset.py

# 2. Run exploratory judge comparison across dev/test samples
python experiments/evaluate_phase3.py
```
*Output Artifacts*: `data/drift_train.jsonl`, `data/drift_dev.jsonl`, `data/drift_test.jsonl`, `results/phase3_metrics.json`, `results/PHASE3_FINAL_REPORT.md`

### Step 5: Reproduce Phase 4 (Middleware Replay Benchmark)
```bash
# Replay 10 stratified held-out test split examples through 4-tier pipeline
python experiments/phase4_evaluate.py
```
*Output Artifacts*: `results/PHASE4_EVALUATION.md`, `results/PHASE4_IMPLEMENTATION_REPORT.md`

### Step 6: Reproduce Phase 5 (Full Held-Out Benchmark, Red-Team Suite, and Proxy)
```bash
# 1. Inspect 30 adversarial red-team test cases
python experiments/phase5_red_team_suite.py

# 2. Run Live MCP JSON-RPC socket proxy fixture (Status: PASS)
python experiments/phase5_live_mcp_proxy.py

# 3. Execute full Phase 5 benchmark across N=56 test split and N=30 red-team suite
python -u experiments/phase5_evaluate_full.py
```
*Output Artifacts*: `results/PHASE5_RESULTS.md`, `results/PHASE5_ERROR_ANALYSIS.md`, `results/PHASE5_REPRODUCIBILITY.md`, `results/figures/phase5/`

---

## 4. Verification & Integrity Checklist

| Checkpoint | Verification Command | Verified Status |
|---|---|---|
| Middleware Unit Tests | `python -m unittest discover tests` | **PASS (28/28 OK)** |
| Live MCP Proxy Fixture | `python experiments/phase5_live_mcp_proxy.py` | **PASS (Status: PASS)** |
| Phase 3 Cluster Leakage | Split Cluster Overlap Check | **PASS (0 Overlap)** |
| Deterministic Outputs | Fixed Seed $42$, Temperature $T=0.0$ | **PASS** |
