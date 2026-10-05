# Failure Policy, Timeout Handling, and Resilience Evaluation

## 1. Scope & Objective

In real-world LLM agent architectures, security middleware must remain robust against non-ideal operational conditions, including:
- Inference timeouts (local GPU/CPU stall or network latency spikes)
- Malformed, non-JSON, or truncated model responses
- Daemon / Ollama process unavailability
- Corrupted SQLite baseline store
- Upstream MCP server crash or invalid JSON-RPC schemas
- Concurrent tool update races

This evaluation establishes the fail-safe guarantees and error handling specifications of the MCP Semantic Drift Guard Middleware.

---

## 2. Failure Handling Matrix

| Failure Condition | Detection Mechanism | System Behavior | Effective Verdict | Enforced Action | Baseline Updated? | Audit Log Status |
|---|---|---|---|---|---|---|
| **Semantic Judge Timeout (> 45s)** | HTTP Socket Timeout | Catch `URLError` / Timeout | `ERROR` / `TIMEOUT` | **QUARANTINE** (Serve V1) | **NO** | `ERROR_TIMEOUT` |
| **Malformed Model Output (Non-JSON)** | Regex / JSON Parser Exception | Parse Error Catch | `ERROR` / `PARSE_FAIL` | **QUARANTINE** (Serve V1) | **NO** | `ERROR_PARSER` |
| **Ollama Daemon Down / Unreachable** | Connection Refused (Port 11434) | Fallback Handler | `ERROR` / `SERVICE_UNAVAILABLE` | **QUARANTINE** (Serve V1) | **NO** | `ERROR_UNAVAILABLE` |
| **Corrupted Baseline SQLite DB** | SQLite Disk I/O Exception | Memory Cache Fallback | `DEGRADED` | **WARN** (Log Alert) | **NO** | `ERROR_DB_CORRUPT` |
| **Invalid JSON Schema in Tool Def** | JSONSchema Syntax Validator | Schema Error Catch | `MALICIOUS` | **BLOCK** | **NO** | `SCHEMA_SYNTAX_ERROR` |
| **Unknown Tool (No Prior Baseline)** | Baseline Cache Miss | Initial Trust Policy | `PENDING_REVIEW` | **ALLOW / QUARANTINE** | **Conditional** | `NEW_TOOL_DISCOVERY` |

---

## 3. Fail-Safe Modes Comparison

The Policy Engine supports two primary operating modes:

### A. BALANCED / FAIL_SECURE (Recommended Default)
- **Policy**: In the event of an LLM judge timeout or parse error, the system treats the update as `SUSPICIOUS`.
- **Mitigation**: Quarantine the candidate update and serve the last known trusted V1 definition to the agent.
- **Security Impact**: Zero silent malicious bypasses due to deliberate denial-of-service or prompt-breaking attacks.
- **Usability Impact**: Transient timeouts temporarily delay benign updates until next inspection.

### B. FAIL_OPEN (High-Availability Legacy Mode)
- **Policy**: In the event of judge failure, allow the update with an asynchronous warning log.
- **Security Impact**: Vulnerable to deliberate adversarial DoS (e.g., flooding prompt length to induce timeout and force bypass).

---

## 4. Empirical Test Suite & Verification

The test suite in `tests/test_failure_policy.py` validates these behaviors:
1. `test_fail_secure_on_malformed_model_output`: Confirmed that unparseable model output automatically triggers `QUARANTINE` and retains the V1 baseline.
2. `test_unknown_new_tool_policy_strict`: Confirmed that unseen tools are governed by configurable initial trust policies.
