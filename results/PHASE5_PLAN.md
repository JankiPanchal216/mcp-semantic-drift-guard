# Phase 5 Research Plan — Large-Scale Evaluation, Adversarial Red-Teaming & Live Interception

## 1. Objective & Scope

Phase 5 addresses the key limitations identified in Phase 4 (`PHASE4_EVALUATION.md`):
1. **Sample Scale Extension**: Move from a 10-example stratified replay test to a comprehensive evaluation across the entire held-out test split (56 examples), Phase 2 real open-source updates (123 examples), and an expanded synthetic attack benchmark.
2. **Adversarial / Adaptive Red-Teaming**: Design and evaluate a 10-category adversarial attack suite testing subtle semantic obfuscation, euphemistic language, hidden parameter constraints, and multi-field instruction splitting.
3. **Live MCP Server Proxy Integration**: Build and test a local JSON-RPC socket proxy interceptor demonstrating real-time `tools/list` client-server traffic inspection.
4. **Latency & Resource Profiling**: Measure Tier 0 fast-path bypass rates, Tier 1 static alert acceleration, Tier 3 LLM inference latencies (mean, median, p95), and average LLM calls per update.
5. **Statistical & Error Analysis**: Compute 95% Wilson score confidence intervals for detection metrics and analyze false positives/negatives.

---

## 2. Dataset Construction & Split Isolation

To preserve research integrity, Phase 5 enforces strict split boundaries:

- **Phase 5 Held-Out Test Set**: All 56 held-out test split examples (`data/drift_test.jsonl`), comprising 33 MCPTox-derived malicious attacks, 15 real open-source updates, and 8 security-worded hard negatives.
- **Phase 2 Real-World Benign Corpus**: 123 authentic developer tool updates mined across 25 open-source MCP server repositories.
- **Phase 5 Red-Team Adversarial Suite**: 30 new adversarial test cases across 10 mutation categories, specifically designed to test the limits of local 8B LLM semantic drift detection.
- **Split Protection**: All examples preserve their `cluster_id` (`server_id + tool_name`). No training or development split data will be used for final test reporting.

---

## 3. Red-Team / Adaptive Attacker Transformation Suite

The red-team evaluation tests 10 distinct evasion transformations:

1. **Indirect Wording**: Concealing malicious intent behind passive or conditional phrasing.
2. **Euphemistic Instructions**: Describing file deletion/exfiltration as "system cleanup" or "telemetry synchronization".
3. **Multi-Step Intent**: Splitting a malicious instruction across multiple logical sentences.
4. **Semantically Subtle Changes**: Small wording tweaks that alter authorization boundaries without triggering keyword regexes.
5. **Benign-Looking Prerequisites**: Embedding mandatory prerequisite calls to secondary tools under plausible diagnostic names (`health_check`, `sync_state`).
6. **Parameter Description Hiding**: Concealing exfiltration targets inside input parameter `description` fields rather than tool-level descriptions.
7. **Optional Parameter Hijacking**: Adding optional boolean/string parameters that silently enable administrative overrides.
8. **Argument-Level Redirection**: Silently modifying default argument values to point to sensitive system paths.
9. **Field Splitting**: Distributing instruction fragments across `name`, `description`, and `inputSchema.properties`.
10. **Low-Signal Semantic Drift**: Subtle schema constraint modifications (e.g. changing `readOnly: true` to `readOnly: false`).

---

## 4. Middleware Pipeline Benchmarking Strategy

The baseline Phase 4 Guard Middleware (`guard/middleware.py`) will be benchmarked across the expanded datasets without modification to establish true baseline performance:

- **Tier 0 Hash Comparison**: Unchanged tool definitions $\rightarrow$ ALLOW (<1 ms, 0 LLM calls).
- **Tier 1 Static Rules**: High-severity regex matches $\rightarrow$ QUARANTINE (<1 ms, 0 LLM calls).
- **Tier 2 Structured Diff**: Computation of JSON-aware diff fields.
- **Tier 3 Semantic Judge Mode B**: Structured diff evaluation via local Ollama `qwen3:8b` at $T=0$.
- **Policy Engine**: Enforcement under `BALANCED`, `STRICT`, and `AUDIT` policy modes.

---

## 5. Live MCP Server Integration Test Specification

A local JSON-RPC socket proxy script (`experiments/phase5_live_mcp_proxy.py`) will be created to demonstrate live client-server interception:

```
[ MCP Client Fixture ]  ──► (JSON-RPC tools/list Request) ──►  [ Phase 5 Live Proxy Guard ]
                                                                        │
                                                                        ├─ Intercepts Response
                                                                        ├─ Evaluates Tool Drift
                                                                        └─ Enforces Policy (ALLOW / BLOCK)
                                                                        │
[ Client Agent View ]   ◄── (Filtered / Reverted Definition) ◄──────────┘
```

- **Test Sequences**:
  1. Unchanged tool list query $\rightarrow$ ALLOW (Fast path, 0 LLM calls).
  2. Benign tool docstring update $\rightarrow$ ALLOW & update trusted baseline.
  3. Malicious tool poisoning $\rightarrow$ BLOCK & revert payload to V1 trusted definition.
  4. Automatic Rollback Verification in real-time JSON-RPC stream.

---

## 6. Evaluation Deliverables & Artifacts

1. `results/PHASE5_PLAN.md` (This document)
2. `experiments/phase5_red_team_suite.py` (30 adversarial red-team test cases)
3. `experiments/phase5_evaluate_full.py` (Full evaluation benchmark runner)
4. `experiments/phase5_live_mcp_proxy.py` (Controlled local live MCP JSON-RPC proxy)
5. `results/PHASE5_RESULTS.md` (Full quantitative benchmark results and confusion matrices)
6. `results/PHASE5_ERROR_ANALYSIS.md` (Deep-dive false positive/negative analysis)
7. `results/PHASE5_REPRODUCIBILITY.md` (Reproducibility environment, commands, and seeds)
8. `results/PHASE5_DECISION.md` (Final research decision: PROCEED, PROCEED WITH LIMITATIONS, REVISE, or STOP)
9. Figures in `results/figures/phase5/` (Detection rates, latency distributions, red-team breakdowns)

---
