# Guard Code Implementation Audit & Delivery-Layer Analysis

**Date:** 2026-10-09  
**Audit Scope:** `guard/baseline_store.py`, `guard/middleware.py`, `guard/policy_engine.py`, `guard/semantic_judge.py`, `experiments/phase5_live_mcp_proxy.py`  
**Auditors:** Skeptical Co-Author Team  

---

## 1. Executive Summary & Item-by-Item Verification

| Audit Item | Property Description | File & Line Reference | Finding Status | Architectural Behavior & Evidence |
|:---|:---|:---|:---:|---|
| **1a (i)** | **Baseline Promotion on BENIGN (Ratcheting)** | [`guard/middleware.py:324-328`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/guard/middleware.py#L324-L328), [`guard/baseline_store.py:188-215`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/guard/baseline_store.py#L188-L215) | **PRESENT** | When policy action is `ALLOW`, `update_trusted_baseline()` promotes candidate definition to current trusted baseline in SQLite table `baselines`, ratcheting $V_{i-1} \rightarrow V_i$. Previous version is archived in `baseline_history` with status `SUPERSEDED`. |
| **1a (ii)** | **Immutable Root Anchor ($V_1$) Storage** | [`guard/baseline_store.py:91-148`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/guard/baseline_store.py#L91-L148) | **PRESENT** | Stored separately via persistent history tracking. `get_root_definition()` retrieves the original $V_1$ definition (`version_id = 1` or earliest record in `baseline_history`), ensuring the root anchor is preserved across ratcheting updates. |
| **1b (i)** | **Baseline Namespace Keying** | [`guard/baseline_store.py:40-50`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/guard/baseline_store.py#L40-L50), [`guard/baseline_store.py:74-76`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/guard/baseline_store.py#L74-L76) | **PRESENT** | Keyed strictly by `(server_id, tool_name)` as composite PRIMARY KEY in SQLite. |
| **1b (ii)** | **Connection / Session & Transport Keying** | [`guard/baseline_store.py:40-65`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/guard/baseline_store.py#L40-L65) | **ABSENT** | Baselines do not track `session_id`, `connection_id`, or `transport_type`. Persistent across reconnects if `server_id` is unchanged; resets to uninitialized if dynamic/ephemeral `server_id` is used. |
| **1c** | **Single vs. Double Fetch on `tools/list`** | [`experiments/phase5_live_mcp_proxy.py:54-88`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/experiments/phase5_live_mcp_proxy.py#L54-L88) | **ABSENT (Single Fetch)** / **UNCLEAR (Object vs. Byte Forwarding)** | Proxy calls `server.handle_tools_list()` exactly once (single fetch). Vetted tool dictionary objects are re-serialized into new JSON-RPC response; raw wire byte forwarding is not implemented. |
| **1d** | **Judge Timeout Behavior & Fail-Safe** | [`guard/semantic_judge.py:18-20`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/guard/semantic_judge.py#L18-L20), [`guard/middleware.py:270-277`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/guard/middleware.py#L270-L277), [`guard/policy_engine.py:35-55`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/guard/policy_engine.py#L35-L55) | **PRESENT (Fail-Safe Caught)** / **ABSENT (Transport Specificity)** | Timeout exceptions in Ollama judge HTTP client trigger `verdict = "ERROR"`. `PolicyEngine` enforces fail-closed behavior (`action = "BLOCK"` / `"WARN"`). Timeout threshold is a global 120s HTTP timeout rather than per-transport adaptive timeout. |
| **1e** | **Comprehensive Path Interception (`list_changed`)** | [`experiments/phase5_live_mcp_proxy.py:49-93`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/experiments/phase5_live_mcp_proxy.py#L49-L93) | **ABSENT** | Mock proxy only implements synchronous `tools/list` request processing. Server-to-client JSON-RPC notification `notifications/tools/list_changed` is not explicitly intercepted or queued in proxy logic. |

---

## 2. Detailed Technical Audit Findings

### 2.1 Baseline Ratcheting & Anchor Separation (§1a)
- **Ratcheting Mechanism:** In `guard/middleware.py:324-328`:
  ```python
  if action == "ALLOW":
      self.baseline_store.update_trusted_baseline(
          server_id, tool_name, new_tool_def, reason=f"BENIGN_VERDICT ({rationale})"
      )
  ```
  This creates true ratcheting: once an adjacent step is judged `BENIGN` and allowed by policy, it becomes the new reference point ($V_{i-1}$) for all subsequent adjacent comparisons.
- **Root Anchor Preservation:** In `guard/baseline_store.py:91-148`, `get_root_definition()` retrieves the immutable $V_1$ record from `baseline_history` using `version_id = 1`. Thus, the cumulative strategy compares against $V_1$ even after multiple intermediate promotions.

### 2.2 Keying & Reconnection Semantics (§1b)
- **Storage Schema:** SQLite table `baselines` defines `PRIMARY KEY (server_id, tool_name)`.
- **Reconnect Invariance:** Reconnecting a client over stdio or restarting a transport session maintains the baseline state in SQLite as long as the same database file and `server_id` are supplied.
- **Vulnerability:** If an attacker restarts an MCP server with a dynamically altered `server_id` (e.g. `mcp-server-git-v2`), the guard treats it as a brand-new tool and initializes trust at $V_1$ without history.

### 2.3 Double-Fetch vs. Byte Forwarding (§1c)
- **Inspection Flow:** `LiveMCPGuardProxy.process_tools_list_request()` receives a single JSON-RPC payload from upstream. It iterates through `tools`, evaluates each, and constructs a sanitized JSON-RPC response `{"jsonrpc": "2.0", "result": {"tools": filtered_tools}}`.
- **Risk Analysis:** Because the proxy does not re-fetch from upstream, there is no TOCTOU (time-of-check to time-of-use) double-fetch vulnerability. However, serialization occurs via Python's `json.dumps`, which standardizes formatting rather than passing verbatim raw wire bytes.

### 2.4 Timeout Handling (§1d)
- **Exception Catching:** In `guard/middleware.py:273-276`:
  ```python
  except Exception as e:
      return "ERROR", 0.5, {"error": str(e), "skipped": False}, str(e)
  ```
- **Policy Enforcement:** When `verdict == "ERROR"`, `PolicyEngine` defaults to `FAIL_CLOSED_ON_MALICIOUS`, emitting `BLOCK` or `WARN` and refusing to promote the baseline.

### 2.5 Notification & Out-of-Band Paths (§1e)
- **Notification Gap:** In MCP spec 2024-11-05 / 2025-03, dynamic tool registration occurs via server notification `notifications/tools/list_changed`.
- **Proxy Status:** Current `phase5_live_mcp_proxy.py` simulates request-reply polling but does not encapsulate bidirectional streaming / SSE notification forwarding. In a live deployment, unmediated notification forwarding could cause clients to bypass proxy vetting unless all inbound notifications trigger an active re-inspection barrier.
