# Rollback Safety & Schema Incompatibility Analysis

## 1. Executive Summary & Reviewer Problem Statement

When the MCP Semantic Drift Guard detects a malicious update or unverified drift in an incoming tool manifest (`tools/list`), its automated mitigation policy serves the **last known trusted definition (V1)** to the LLM agent client while retaining the candidate (V2) in quarantine.

However, a critical reviewer concern arises:
> **If the upstream MCP server runtime has already transitioned to V2, does serving V1 to the client agent cause runtime call failures during subsequent `tools/call` invocations?**

This document provides a formal compatibility analysis, experimental validation, and architectural mitigations for rollback safety.

---

## 2. Incompatibility Taxonomy

We analyze the four primary schema evolution scenarios when the client executes a tool using V1 schema while the backend server expects V2:

| Scenario | Server V2 Evolution | Client Action (V1 Schema) | Runtime Result on `tools/call` | Rollback Safe? |
|---|---|---|---|---|
| **Case 1: Optional Parameter Addition** | Added optional parameter `limit: int = 10` | Client passes only V1 arguments | **Success**: Backend applies default value | **YES (Call Compatible)** |
| **Case 2: Required Parameter Addition** | Added required parameter `auth_token: str` | Client omits `auth_token` | **Failure**: Server JSON-RPC schema validator rejects call | **NO (Breaking)** |
| **Case 3: Parameter Renaming / Deletion** | Renamed `filePath` $\rightarrow$ `target_path` (or deleted) | Client passes `filePath` | **Failure**: Server misses required `target_path` or rejects unknown key | **NO (Breaking)** |
| **Case 4: Type Mutation** | Changed `id: int` $\rightarrow$ `id: list[int]` | Client passes scalar integer | **Failure**: Server type error / schema failure | **NO (Breaking)** |

---

## 3. Empirical Verification & Test Suite

We implemented dedicated unit tests in `tests/test_rollback_safety.py` verifying JSON-RPC dispatch behavior across these scenarios:
1. `test_optional_parameter_addition_remains_compatible`: **PASSED** (Non-breaking evolution allows seamless V1 rollback).
2. `test_removed_parameter_breaks_v1_call`: **PASSED** (Server with `additionalProperties: false` correctly caught as breaking).
3. `test_new_required_parameter_in_v2_breaks_v1_call`: **PASSED** (Missing required arguments flagged immediately).

---

## 4. Architectural Mitigation & Guard Policy

Because rollback is **not universally call-safe** for breaking structural changes, the Guard Middleware implements a multi-tiered safety protocol:

```
Malicious / Drifted Tool Update Detected
                   │
                   ▼
       Is change schema-breaking?
       (Required added, props deleted, types changed)
        ├── NO (Docstring-only or optional param) ──► Transparent V1 Rollback (Safe)
        │
        └── YES (Breaking Schema Change)
                   │
                   ├── Option A (Default: FAIL_SECURE):
                   │   Quarantine tool entirely & notify agent runtime ("Tool Disabled: Security Policy")
                   │
                   └── Option B (Proxy Adaptation):
                       Middleware intercepts `tools/call` and applies parameter default synthesis
```

### Recommendation for Production Deployments
In high-security environments, breaking schema changes accompanying malicious drift should trigger **Full Tool Quarantine** rather than naive transparent rollback, preventing latent runtime RPC exceptions from crashing downstream agent workflows.
