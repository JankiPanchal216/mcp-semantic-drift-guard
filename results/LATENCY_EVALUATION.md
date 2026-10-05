# Latency, Deployment Benchmarks, and Asynchronous Staging Architecture

## 1. Experimental Environment & Hardware Specifications

All latency measurements were performed in the following controlled local test environment:
- **Operating System**: Microsoft Windows 11 Enterprise (x86_64)
- **Host Architecture**: Multi-core x86_64 host CPU
- **Local Inference Engine**: Ollama (llama.cpp backend with AVX-512 optimization)
- **Primary Model**: `qwen3:8b` (GGUF `Q4_K_M`, 5.22 GB resident)
- **Evaluation Timing Methodology**: High-resolution monotonic timers (`time.perf_counter()`), warm cache state (5 warm-up iterations prior to recording).

---

## 2. Component-by-Component Latency Breakdown

| Pipeline Stage / Component | Operation Performed | Mean Latency | Median (P50) | P95 Latency | Invocations / Update |
|---|---|---:|---:|---:|---:|
| **Tier 0: Hash Pinning (Fast Path)** | SHA-256 Digest of Normalized Tool Manifest | **0.024 ms** | 0.022 ms | 0.038 ms | 100% (All tools) |
| **Tier 1: Static Keyword Scanner** | Regex compilation & pattern matching | **0.041 ms** | 0.039 ms | 0.065 ms | If Changed (~5%) |
| **Tier 1.5: Schema Security Checker** | JSON Schema property & default value audit | **0.078 ms** | 0.072 ms | 0.112 ms | If Changed (~5%) |
| **Tier 2: Structured JSON Diff Engine** | Recursive dict difference & summary synthesis | **0.095 ms** | 0.088 ms | 0.145 ms | If Changed (~5%) |
| **Tier 3: Semantic Judge (`qwen2.5:1.5b`)** | Lightweight LLM Mode B Diff Classification | **290 ms** | 275 ms | 340 ms | Ambiguous updates |
| **Tier 3: Semantic Judge (`gemma3:4b`)** | Midweight LLM Mode B Diff Classification | **780 ms** | 760 ms | 920 ms | Ambiguous updates |
| **Tier 3: Semantic Judge (`qwen3:8b`)** | Primary LLM Mode B Diff Classification | **1,420 ms** | 1,380 ms | 1,750 ms | Ambiguous updates |

---

## 3. End-to-End Pipeline Throughput Scenarios

### Scenario A: Steady-State Runtime (95.01% of Requests)
In normal operation, 95.01% of MCP tool handshakes encounter **unchanged tools**.
- **Execution Path**: Tier 0 Fast Path (SHA-256 Hash Match)
- **End-to-End Latency**: **0.024 ms** (~41,600 tool lookups/sec).
- **LLM Compute Overhead**: 0.0%.

### Scenario B: High-Severity Attack / Obvious Injection
- **Execution Path**: Tier 0 (Mismatch) $\rightarrow$ Tier 2 (Diff) $\rightarrow$ Tier 1 (Static High-Severity Rule Trigger)
- **End-to-End Latency**: **0.160 ms**.
- **Action**: Immediate Block & Rollback to V1 without LLM invocation.

### Scenario C: Ambiguous Tool Evolution / Refactoring Update
- **Execution Path**: Tier 0 (Mismatch) $\rightarrow$ Tier 2 (Diff) $\rightarrow$ Tier 1 (Clean) $\rightarrow$ Tier 1.5 (Clean) $\rightarrow$ Tier 3 (LLM Judge)
- **End-to-End Latency**: **1,420 ms** (using `qwen3:8b`) or **290 ms** (using `qwen2.5:1.5b`).
- **Action**: Detailed structured audit log & automated classification.

---

## 4. Production Staging Architecture: Asynchronous Background Inspection

To prevent the 1.42-second LLM latency from stalling synchronous client application startup, we design an **Asynchronous Staging & Fast-Path Protocol**:

```
MCP Server Handshake (tools/list)
            │
            ▼
   Is Hash in Trusted DB?
     ├── YES ──► Serve Tool to Agent Immediately (< 0.05 ms Fast Path)
     │
     └── NO (New / Modified Version Detected)
            │
            ├── Fast Check: Tier 1 Static & Tier 1.5 Schema (< 0.2 ms)
            │      └── If Flagged: BLOCK & Rollback to V1 Immediately
            │
            └── If Clean: Serve Last Known Trusted V1 to Agent (Instant Handshake)
                   │
                   └── [ Spawn Asynchronous Background Worker ]
                              │
                              ▼
                   Tier 3 Semantic LLM Inspection (~1.4s in Background)
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
                 BENIGN              MALICIOUS / SUSPICIOUS
                    │                   │
         Promote V2 to Trusted DB    Quarantine V2 & Alert Security Admin
```

This staging design ensures that **zero user-facing latency** is added to normal tool calls, while still guaranteeing that uninspected modifications are isolated until verified.
