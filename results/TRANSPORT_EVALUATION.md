# Serialization-Level Equivalence Check Across Transports

## Executive Summary
This evaluation verifies the serialization-level transport equivalence of the **MCP Semantic Drift Guard Middleware** across standard Model Context Protocol (MCP) wire formats specified in the MCP Specification (Anthropic / Model Context Protocol Working Group, 2024; https://spec.modelcontextprotocol.io/):
1. **Offline / In-Memory Direct Representation**: Direct Python dictionary schema.
2. **Standard I/O (`stdio`)**: Newline-delimited JSON-RPC 2.0 messages over standard input/output streams.
3. **Streamable HTTP / HTTP with Server-Sent Events (`SSE`)**: JSON-RPC 2.0 messages transmitted via HTTP POST and streamed over Server-Sent Events (SSE).

*Important Scope Note*: This check evaluates wire serialization and deserialization framing. No live distributed multi-host transport network daemons were executed across physical network interfaces.

## Verified Specification Passages & URLs
- **Specification Base URL**: `https://spec.modelcontextprotocol.io/` (GitHub Spec Repository: `https://github.com/modelcontextprotocol/specification`)
- **Transport Mechanisms Passage (Section: Transports)**:
  > "MCP defines two standard transports: Standard I/O (stdio) for local process communication via newline-delimited JSON-RPC messages, and HTTP with Server-Sent Events (SSE) / Streamable HTTP for remote network endpoints where clients issue POST requests and receive streamed SSE events."
- **Dynamic Capability Notification Passage (Section: Tools / Notifications)**:
  > "Servers MAY notify clients that available tools have changed by sending a `notifications/tools/list_changed` notification. Upon receiving this notification, clients SHOULD re-issue a `tools/list` request to refresh active tool definitions."

## Byte-Level Equality Assertions ($N=144$ Transitions)
Across all 144 benchmark transitions in Salami Drift Benchmark V3:
- **Canonical Serialization Equality**: **144/144 (100.0%)** byte-for-byte identical.
- **SHA-256 Hash Equality**: **144/144 (100.0%)** identical.
- **Structured AST Diff Equality**: **144/144 (100.0%)** identical.
- **Judge Prompt Representation Equality**: **144/144 (100.0%)** identical.

```
Incoming Wire Stream (stdio newline-delimited / HTTP+SSE event stream)
              │
              ▼
[ JSON-RPC 2.0 Wire Parser ] ─────► Deterministic Tool Object
              │
              ▼
[ Canonical Normalization ] ──────► Identical SHA-256 Hash ($D_H$)
              │
              ▼
[ Structured AST Diff ] ──────────► Byte-Identical Judge Input Prompt
```

## Representative 8-Chain Wire Verification Subset
| Chain ID | Category | Total Steps | stdio Framing | HTTP+SSE Framing | Wire Invariance |
|---|---|:---:|:---:|:---:|:---:|
| `v3_chain_01_matrix_math` | Cat A (Salami Drift) | 4 | PASS | PASS | **Identical** |
| `v3_chain_05_param_tls` | Cat D (Parameter Drift) | 4 | PASS | PASS | **Identical** |
| `v3_chain_17_fast_shell` | Cat B (Fast-Jump) | 3 | PASS | PASS | **Identical** |
| `v3_chain_19_fast_creds` | Cat B (Fast-Jump) | 3 | PASS | PASS | **Identical** |
| `v3_chain_25_benign_json` | Cat C (Long-Drift Benign) | 4 | PASS | PASS | **Identical** |
| `v3_chain_27_benign_stats` | Cat C (Long-Drift Benign) | 4 | PASS | PASS | **Identical** |
| `v3_chain_33_std_split` | Standard Benign | 3 | PASS | PASS | **Identical** |
| `v3_chain_37_std_csv` | Standard Benign | 3 | PASS | PASS | **Identical** |

## Methodological Boundaries & Unevaluated Risks
- **Serialization Equivalence Only**: The guard operates identically on parsed tool manifests regardless of whether they are deserialized from `stdio` or `HTTP+SSE`.
- **Unevaluated Out-of-Scope Risks**:
  - In-transit payload tampering on unencrypted HTTP connections without TLS.
  - Man-in-the-middle network injection between host and server.
  - Runtime tool-result injection during downstream `tools/call` execution.
