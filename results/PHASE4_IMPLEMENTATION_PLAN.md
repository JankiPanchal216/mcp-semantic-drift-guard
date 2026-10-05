# Phase 4 Implementation Plan — MCP Semantic Drift Guard Middleware

## 1. Objective & Scope

Phase 4 implements the **MCP Semantic Drift Guard Middleware** specified in `results/PHASE4_DESIGN.md`. The middleware intercepts Model Context Protocol (MCP) tool definition changes, evaluates them across a 4-tier detection pipeline (Hash Comparison $\rightarrow$ Static Rules $\rightarrow$ Structured Diff $\rightarrow$ Semantic Drift Judge Mode B), applies configurable security policies, logs structured telemetry, and enforces automatic rollback when malicious drift is intercepted.

---

## 2. Reusable Phase 3 Components

The implementation reuses core Phase 3 research modules without duplicating logic or modifying Phase 3 benchmark results:

| Existing Module | Component Role | Reused Functions / Structures |
|---|---|---|
| `experiments/baseline_hash_pinning.py` | Tier 0 Hash Comparison | `normalize_def()`, `compute_sha256()` |
| `guard/static_rules.py` | Tier 1 Static Heuristics | `RULES`, `evaluate_static_rules()` |
| `experiments/phase3_structured_diff.py` | Tier 2 Structured Diff | `compute_structured_diff()` |
| `guard/semantic_judge.py` | Tier 3 Semantic Judge | `build_mode_b_prompt()`, `call_ollama_judge()`, `parse_judge_response()` |

---

## 3. New Component Modules Required

To convert research evaluation scripts into a functional middleware guard, the following new modules will be implemented:

```text
APP/
├── guard/
│   ├── config.py              # Configuration manager (policy tier, thresholds, timeouts)
│   ├── baseline_store.py      # Persistent SQLite store for trusted tool baselines & version lineage
│   ├── audit_logger.py        # Machine-readable JSONL audit logger
│   ├── policy_engine.py       # Policy decision matrix (ALLOW, WARN, BLOCK, QUARANTINE)
│   └── middleware.py          # Unified Guard Pipeline Manager & Interceptor Loop
│
├── experiments/
│   └── phase4_evaluate.py     # End-to-end benchmark evaluation script for Phase 4 guard
│
├── tests/
│   ├── test_hash.py           # Unit tests for Tier 0 fast path
│   ├── test_diff.py           # Unit tests for Tier 2 structured diff
│   ├── test_static_rules.py   # Unit tests for Tier 1 static heuristics
│   ├── test_policy.py         # Unit tests for policy decision engine
│   ├── test_baseline.py       # Unit tests for SQLite baseline persistence & history
│   ├── test_rollback.py       # Unit tests for automatic baseline reversion
│   └── test_middleware.py     # Unit tests for complete pipeline orchestration (with mocks)
│
└── results/
    ├── PHASE4_IMPLEMENTATION_PLAN.md    # (This document)
    ├── PHASE4_IMPLEMENTATION_REPORT.md  # Detailed implementation report
    └── PHASE4_EVALUATION.md             # Benchmark evaluation metrics on Phase 4 guard
```

---

## 4. Interfaces and Data Flow

### Data Flow Sequence

```
1. Client/Host Request (tools/list)
   │
   ▼
2. Interceptor captures current tool definitions from server
   │
   ▼
3. BaselineStore retrieves previous trusted definition (hash_old)
   │
   ▼
4. Tier 0 (Hash Comparison)
   ├── Match -> ALLOW (Fast Path, <1 ms, 0 LLM calls)
   └── Mismatch -> Proceed to Tier 1
   │
   ▼
5. Tier 1 (Static Rules Scan)
   ├── High-Severity Pattern Matched -> Block immediately (Fast Alert, <1 ms)
   └── No Match -> Proceed to Tier 2
   │
   ▼
6. Tier 2 (Structured Diff Computation)
   ├── Trivial Formatting Change -> Auto-Approve (Policy Tier 2)
   └── Semantically Relevant Diff -> Proceed to Tier 3
   │
   ▼
7. Tier 3 (Semantic Drift Judge Mode B)
   └── Returns: {label, confidence, reason, evidence}
   │
   ▼
8. Policy Engine (STRICT / BALANCED / AUDIT)
   ├── BENIGN     -> Action: ALLOW & Update Trusted Baseline Store
   ├── SUSPICIOUS -> Action: WARN (Retain Previous Baseline)
   └── MALICIOUS  -> Action: BLOCK / QUARANTINE (Revert to Previous Baseline)
   │
   ▼
9. Audit Logger writes machine-readable JSONL audit record
```

---

## 5. Configuration Requirements (`guard/config.py`)

Configuration will be managed via environment variables and `guard_config.json`:

- `POLICY_MODE`: `"BALANCED"` (Default), `"STRICT"`, or `"AUDIT"`.
- `OLLAMA_API_URL`: `http://localhost:11434/api/chat`
- `MODEL_NAME`: `qwen3:8b`
- `TEMPERATURE`: `0`
- `LLM_TIMEOUT_SECONDS`: `60`
- `FAIL_SAFE_MODE`: `"FAIL_CLOSED_ON_MALICIOUS"` (Default) vs `"FAIL_OPEN"`
- `AUDIT_LOG_PATH`: `results/phase4_audit_log.jsonl`
- `BASELINE_DB_PATH`: `data/trusted_baselines.db`

---

## 6. Rollback Strategy

When a tool update is evaluated as `MALICIOUS` (or `SUSPICIOUS` under Strict Policy):

1. The new definition is flagged as `QUARANTINED` in SQLite `baseline_store.db`.
2. The trusted baseline is **NOT updated**.
3. The previous trusted definition remains active in the `current_trusted` view.
4. If a client attempts to execute the tool, the middleware serves the **previous trusted version**, shielding the agent from prompt injection or parameter redirection.

---

## 7. Failure Handling Matrix

| Scenario | Primary Action | Fallback Action | Audit Log Status |
|---|---|---|---|
| **Ollama Timeout / Connection Error** | LLM Call Fails | Fallback to Static Rules verdict + Hash alert | `LLM_TIMEOUT_FALLBACK` |
| **Malformed LLM Output** | JSON Parse Failure | Extract regex label; if impossible $\rightarrow$ `SUSPICIOUS` | `MALFORMED_JSON_FALLBACK` |
| **Unknown / New Tool Addition** | No previous baseline | Run Tier 1 + Tier 3 on full definition | `NEW_TOOL_INITIALIZATION` |
| **DB Storage Failure** | SQLite Lock / Disk Error | In-memory baseline caching fallback | `STORAGE_WARNING` |

---

## 8. Test Strategy

1. **Unit Tests (Deterministic / No LLM Required)**:
   - Test Tier 0 hash matching and bypass logic.
   - Test Tier 1 static regex detection on sample payloads.
   - Test Tier 2 structured diff calculation.
   - Test Policy Engine decisions across matrix.
   - Test SQLite Baseline Store CRUD & rollback.
   - Mock LLM responses for full pipeline integration tests.
2. **Integration Tests (With Ollama `qwen3:8b`)**:
   - Test end-to-end evaluation on sample Phase 3 fixtures.
   - Test fault tolerance on simulated Ollama connection failure.
3. **Benchmark Evaluation**:
   - Run `phase4_evaluate.py` across Phase 3 dev and test dataset splits to verify $F_1$, precision, recall, benign FPR, and latency.

---
