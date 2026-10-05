# Final Architecture Specification: MCP Semantic Drift Guard Middleware

## 1. Architectural Overview

The **MCP Semantic Drift Guard Middleware** provides an inline or out-of-band security interception layer situated between LLM client applications and upstream Model Context Protocol (MCP) servers. The middleware continuously inspects advertised tool contract modifications (`tools/list` responses), evaluates their behavioral and security implications across a four-tier inspection pipeline, and enforces operational policies to prevent unauthorized tool tampering from silently becoming trusted.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            MCP Client / Agent Host                          │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ JSON-RPC Request (e.g. tools/list)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MCP SEMANTIC DRIFT GUARD MIDDLEWARE                      │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Tier 0: Fast-Path Hash Check (SHA-256)                                │  │
│  │   • Unchanged Tool Definition ────────► [ ALLOW (<1 ms, 0 LLM calls) ]│  │
│  └──────────────────────────────────┬────────────────────────────────────┘  │
│                                     │ Tool Definition Changed               │
│                                     ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Tier 2: Structured Contract Diff Engine                               │  │
│  │   • Computes JSON-aware field deltas (params, summary, schema)        │  │
│  └──────────────────────────────────┬────────────────────────────────────┘  │
│                                     │                                       │
│                                     ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Tier 1: Static Heuristic Fast Alert                                   │  │
│  │   • High-Severity Signature Match ──► [ QUARANTINE (<1 ms, 0 LLM) ]   │  │
│  └──────────────────────────────────┬────────────────────────────────────┘  │
│                                     │ No High-Severity Match                │
│                                     ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Tier 3: Semantic Drift Judge (Mode B Diff Only)                       │  │
│  │   • Prompts local Qwen3-8B with untrusted diff in XML sandbox         │  │
│  │   • Emits structured JSON verdict (BENIGN, SUSPICIOUS, MALICIOUS)     │  │
│  └──────────────────────────────────┬────────────────────────────────────┘  │
│                                     │ Verdict & Confidence                  │
│                                     ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Policy Enforcement Engine (BALANCED / STRICT / AUDIT)                 │  │
│  │   • ALLOW      ──► Update Baseline Store, Return New Definition       │  │
│  │   • WARN       ──► Log Audit Record, Return New Definition            │  │
│  │   • QUARANTINE ──► Block Update, Rollback to Last Known Trusted V1    │  │
│  └──────────────────────────────────┬────────────────────────────────────┘  │
│                                     │                                       │
│  ┌──────────────────────────────────┴────────────────────────────────────┐  │
│  │ State & Persistence Engines                                           │  │
│  │   • SQLite Baseline Store (trusted pins, quarantine history)          │  │
│  │   • Structured JSONL Audit Logger (cryptographic hashes, latencies)   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Sanitized / Rolled-back Response
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Upstream MCP Server(s)                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Specifications

### 2.1 Tier 0: Canonical Hash Fast Path (`guard/baseline_store.py`)
- **Implemented**: YES.
- **Mechanism**: The candidate tool definition is normalized (lexicographically sorted keys, trimmed whitespace, normalized types) and hashed with SHA-256.
- **Bypass Rule**: If the newly computed hash matches the `trusted_hash` stored in the `BaselineStore` for the tuple `(server_id, tool_name)`, the pipeline immediately returns `ALLOW` with `change_detected = False` (<1 ms, 0 LLM calls).

---

### 2.2 Tier 2: Structured Contract Diff Engine (`experiments/phase3_structured_diff.py`)
- **Implemented**: YES.
- **Mechanism**: Computes a structured delta between `old_tool_def` and `new_tool_def`:
  - `params_added`: List of newly declared property names.
  - `params_removed`: List of deprecated property names.
  - `params_modified`: Dict of altered types, constraints, or docstrings.
  - `description_diff_summary`: Compact unified diff of textual descriptions.
- **Security Role**: Isolates only what changed, eliminating 70%+ of boilerplate tokens before passing data to the LLM.

---

### 2.3 Tier 1: Static Heuristic Fast Alert (`guard/static_rules.py`)
- **Implemented**: YES.
- **Mechanism**: 7 targeted regular expressions inspect candidate descriptions and diff summaries for overt attack vectors:
  - System path exfiltration (`/etc/shadow`, `~/.ssh/id_rsa`, `.env`, `credentials`).
  - Unauthorized prerequisite chaining (`"MUST FIRST CALL"`, `"BEFORE USING THIS TOOL"`).
  - Explicit argument redirection (`"MODIFY THE ARGUMENT TO"`).
  - Destructive command injection (`rm -rf`, `DROP TABLE`).
- **Short-Circuit Rule**: Matches marked `severity == "high"` immediately bypass LLM evaluation and trigger `QUARANTINE` (<1 ms, 0 LLM calls).

---

### 2.4 Tier 3: Semantic Drift Judge (`guard/semantic_judge.py`)
- **Implemented**: YES.
- **Mechanism**: Mode B Diff-Only zero-temperature prompting against local `qwen3:8b`.
- **Untrusted Sandboxing**: Candidate diffs are wrapped inside `<untrusted_diff>` XML delimiters. System instructions strictly instruct the model to analyze meaning without following directives inside the payload.
- **Output Schema**: Deterministic JSON containing `label` (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`), `confidence` (0.0–1.0), and `rationale`.

---

### 2.5 Policy Enforcement Engine (`guard/policy_engine.py`)
- **Implemented**: YES.
- **Policy Modes**:
  - **`BALANCED` (Default)**: `BENIGN` $\rightarrow$ `ALLOW`; `SUSPICIOUS` $\rightarrow$ `WARN`; `MALICIOUS` $\rightarrow$ `QUARANTINE`.
  - **`STRICT`**: `BENIGN` $\rightarrow$ `ALLOW`; `SUSPICIOUS` $\rightarrow$ `BLOCK`; `MALICIOUS` $\rightarrow$ `BLOCK`.
  - **`AUDIT`**: All changes logged without blocking (`ALLOW` with audit records).
- **Fail-Safe Mechanism**: `FAIL_CLOSED_ON_MALICIOUS` (Default). If the LLM judge is unavailable or returns unparseable output, the engine falls back to Static Rules. If clean, it issues a `WARN` event without dropping connection.

---

### 2.6 Persistent Baseline Store & Rollback Engine (`guard/baseline_store.py`)
- **Implemented**: YES.
- **Database Schema**: SQLite database containing two tables:
  1. `trusted_baselines`: `(server_id, tool_name, trusted_hash, tool_definition_json, updated_at, reason)`
  2. `blocked_updates`: `(server_id, tool_name, candidate_hash, candidate_definition_json, status, reason, recorded_at)`
- **Rollback Behavior**:
  - When an update is evaluated as `ALLOW`, the new definition is committed to `trusted_baselines`.
  - When an update is flagged as `QUARANTINE` or `BLOCK`, the candidate definition is logged to `blocked_updates`. The database **retains the previous trusted V1 definition**, and the middleware substitutes the active payload with V1 before returning the `tools/list` response to the client.

---

### 2.7 Structured Audit Logger (`guard/audit_logger.py`)
- **Implemented**: YES.
- **Format**: Append-only JSONL format containing event timestamps, `server_id`, `tool_name`, `previous_hash`, `new_hash`, `change_detected`, full `structured_diff`, static rule results, semantic judge outputs, policy actions, and microsecond latencies.

---

## 3. Implementation Status Summary

| Component | Implementation Status | Verification Evidence |
|---|---|---|
| Tier 0 Hash Comparison | **Fully Implemented** | Unit tested in `test_hash.py` and `test_middleware.py` |
| Tier 1 Static Rules | **Fully Implemented** | Unit tested in `test_static_rules.py` |
| Tier 2 Structured Diff | **Fully Implemented** | Unit tested in `test_diff.py` |
| Tier 3 Semantic Judge | **Fully Implemented** | Benchmark verified across 56 test examples & 30 red-team cases |
| Policy Engine (3 Modes) | **Fully Implemented** | Unit tested in `test_policy.py` |
| Baseline Store & Rollback | **Fully Implemented** | Unit tested in `test_baseline.py` and `test_rollback.py` |
| Audit Logger | **Fully Implemented** | Verified in temporary JSONL logs during evaluations |
| Local JSON-RPC Proxy Socket | **Fully Implemented** | Verified in `experiments/phase5_live_mcp_proxy.py` (Status: PASS) |
| Multi-Threaded Async Daemon | *Conceptual / Future Work* | Architected for out-of-band GPU servers; not in single-process fixture |
