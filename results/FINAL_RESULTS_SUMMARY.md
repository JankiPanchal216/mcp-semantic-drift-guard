# Master Research Results Summary: MCP Semantic Drift Detection

## Executive Overview

This document provides a consolidated, evidence-based synthesis of all experimental results obtained across Phases 1 through 5 of the **Model Context Protocol (MCP) Semantic Drift Detection** research project.

All metrics reported herein are derived directly from experimental executions against recorded datasets, open-source git histories, local model inference runs, and controlled unit/proxy test fixtures.

---

## 1. Phase 1: Threat Baseline & Tool Poisoning Reproduction

### 1.1 MCPTox Benchmark Reproduction
The project reproduced the evaluation framework of the **MCPTox** benchmark (*"MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers"*, AAAI 2026 / arXiv:2508.14925) using local `Qwen3-8B` (via Ollama `qwen3:8b`, Quantization Q4_K_M, $T=0$, greedy decoding) against 1,348 test instances spanning 45 MCP servers.

| Evaluation Mode | Valid Cases | Ineffective / Ignored | Successes (Exploited) | Measured ASR | Published Baseline ASR | Absolute $\Delta$ |
|---|---:|---:|---:|---:|---:|---:|
| **`qwen3-8b_Think`** | 1,341 | 691 | 560 | **41.76%** | 41.8% | -0.04 pp |
| **`qwen3-8b_NO_Think`** | 1,346 | 980 | 188 | **13.97%** | 14.0% | -0.03 pp |

#### Attack Success Rate (ASR) by Poisoning Paradigm
- **Template-1 (Direct Prompt Injection)**: 44.93% (Think) vs. 8.13% (No-Think)
- **Template-2 (Prerequisite Hijacking)**: 25.15% (Think) vs. 3.66% (No-Think)
- **Template-3 (Argument Tampering / Redirection)**: 54.62% (Think) vs. 24.60% (No-Think)

#### Key Finding: The Capability Paradox
Enabling internal thinking/reasoning in `Qwen3-8B` increased tool docstring instruction adherence, which paradoxically caused attack susceptibility to rise by **+27.79 percentage points** ($13.97\% \rightarrow 41.76\%$). Standard safety guardrails recorded **0 refusals** across all 1,348 test cases.

---

### 1.2 Hash Pinning Industry Baseline Audit
- **Audit Target**: `snyk-agent-scan` (formerly `mcp-scan`, v0.6.8).
- **Hashed Fields**: Canonicalized JSON containing `name`, `description`, and `inputSchema` (properties, parameter descriptions, types, required fields).
- **Integrity Rule**: $\text{Status} = \text{ALLOW if } \text{SHA256}(\text{Tool}_{V_{i+1}}) == \text{SHA256}(\text{Tool}_{V_i}) \text{ else ALERT / BLOCK}$.
- **Core Limitation**: Exact cryptographic hashing is semantics-blind. Any byte-level modification—including harmless docstring typo fixes, parameter clarifications, or capability expansions—produces a hash divergence. In the evaluated dataset, exact pinning alerted on all 23 legitimate maintenance updates because its integrity criterion is byte-level equality.

---

## 2. Phase 2: Real-World MCP Evolution Corpus

Phase 2 collected, indexed, and analyzed multi-version tool snapshots across open-source MCP servers to quantify how frequently tool definitions change in practice.

### 2.1 Corpus Scale & Measurement Statistics
- **Discovered Candidate Repositories**: 28 MCP servers
- **Repositories with Multi-Version Git History ($\ge 2$ tags)**: 25 servers
- **Total Tool Snapshots Extracted**: 594 versioned JSON snapshots
- **Total Unique Tool Contracts**: 285 distinct tool interfaces
- **Comparable Release Transitions $(V_i \rightarrow V_{i+1})$**: 621 transitions
- **Total Tool-Pair Comparisons**: 4,961 individual comparisons
- **Total Recorded Definition Change Events**: 123 tool-definition change events (110 additions/removals, 13 pre-existing tool contract modifications)

### 2.2 Evolutionary Rates & Change Categories
- **Definition-Change Rate**: **2.48%** ($123 / 4,961$ tool comparisons)
- **Release-Change Rate**: **4.99%** ($31 / 621$ releases contained $\ge 1$ changed tool)
- **Pre-Existing Contract Modification Rate**: **2.09%** ($13 / 621$ release transitions)
- **Description-Change Rate**: **1.13%** ($7 / 621$ releases modified descriptions without code changes)
- **Schema-Change Rate**: **0.32%** ($2 / 621$ releases modified input schemas)

| Change Category | Instances | Percentage | Operational Impact |
|---|---:|---:|---|
| `tool_addition` | 63 | 51.22% | Expands agent registry with new capabilities |
| `tool_removal` | 47 | 38.21% | Deprecates obsolete tools or consolidates APIs |
| `clarification` | 11 | 8.94% | Refines docstrings to improve LLM reasoning |
| `new_feature` | 2 | 1.63% | Adds backward-compatible optional parameters |
| **Total** | **123** | **100.0%** | |

### 2.3 Operational Implication for Exact Hash Pinning
Across the 621 observed historical release transitions, 31 transitions (4.99%) modified tool definitions. Because exact hash pinning requires byte-level equality, all 31 modified releases would trigger review under exact pinning, meaning exact pinning could not distinguish benign evolution from malicious drift among these maintenance changes.

---

## 3. Phase 3: Semantic Drift Detector Benchmark

Phase 3 constructed a 370-example dataset combining Phase 2 real-world updates, hard negatives, and MCPTox attacks, establishing strict cluster isolation to eliminate data leakage.

### 3.1 Dataset Partitioning & Leakage Controls
- **Train Split**: 259 examples (124 Benign / 135 Malicious) — 144 unique cluster keys
- **Dev Split**: 55 examples (23 Benign / 32 Malicious) — 34 unique cluster keys
- **Test Split**: 56 examples (23 Benign / 33 Malicious) — 31 unique cluster keys
- **Leakage Audit**: **0 cluster-level overlap** across Train, Dev, and Test splits. Zero record ID overlap.

### 3.2 Phase 3 Detector Comparison (Stratified Sample N=10: 6 Malicious, 4 Benign)

| Detector System | Precision | Recall | $F_1$ Score | Accuracy | Benign FPR | Malicious FNR | Avg Latency | JSON Parse Error Rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Baseline 1)** | 60.0% | 100.0% | 75.0% | 60.0% | **100.0%** | 0.0% | <1 ms | 0.0% |
| **Static Heuristic Rules (Baseline 2)** | 100.0% | 50.0% | 66.7% | 70.0% | **0.0%** | 50.0% | <1 ms | 0.0% |
| **Semantic Judge — Diff Only (Mode B)** | **85.7%** | **100.0%** | **92.3%** | **90.0%** | **25.0%** | **0.0%** | ~50 s | **0.0%** |
| **Semantic Judge — Full Def (Mode A)** | 83.3% | 83.3% | 83.3% | 80.0% | 25.0% | 16.7% | ~60 s | 20.0% |
| **Hybrid (Static + Semantic Full)** | 83.3% | 83.3% | 83.3% | 80.0% | 25.0% | 16.7% | ~60 s | 20.0% |

#### Key Ablation Finding
Diff-Only Mode B outperformed Full Definition Mode A ($F_1 = 92.3\%$ vs. $83.3\%$). By presenting only structured delta fields (`params_added`, `description_diff_summary`), Mode B eliminated context window bloat and reduced JSON output parsing failures on `qwen3:8b` from **20.0% down to 0.0%**.

---

## 4. Phase 4: Middleware Architecture & Replay Evaluation

Phase 4 implemented the complete **MCP Guard Middleware** (`guard/middleware.py`) and verified its operational components across unit testing and offline replay.

### 4.1 Implementation Components Verified
- **Tier 0 Fast Path**: SHA-256 hash matching short-circuits unchanged tools in <1 ms with 0 LLM calls.
- **Tier 1 Static Fast Alert**: High-severity regex patterns intercept overt attacks in <1 ms with 0 LLM calls.
- **Tier 2 Structured Diff**: JSON-aware contract diff generator (`experiments/phase3_structured_diff.py`).
- **Tier 3 Semantic Judge**: Mode B diff-only LLM judge evaluating untrusted tool deltas via local Ollama.
- **Policy Engine**: Configurable policy actions (`ALLOW`, `WARN`, `BLOCK`, `QUARANTINE`) under `BALANCED`, `STRICT`, and `AUDIT` modes.
- **Persistent Baseline Store**: SQLite database maintaining trusted tool definition histories and preventing quarantined definitions from becoming trust baselines.
- **Rollback Routine**: Automatically substitutes quarantined candidate definitions with the last known trusted V1 definition in responses returned to the client.
- **Audit Logger**: Structured JSONL audit logging with microsecond timestamps and complete diff metadata.

### 4.2 Unit Testing & Offline Replay Results
- **Unit Test Suite**: **28 / 28 unit tests passing** (`python -m unittest discover tests`).
- **Replay Evaluation (N=10 Stratified Sample: 8 Malicious, 2 Benign)**:
  - Precision: **100.0%**
  - Recall: **100.0%**
  - $F_1$ Score: **100.0%**
  - Benign FPR: **0.0%** (0/2 false alarms)
  - Malicious FNR: **0.0%** (0/8 missed attacks)
  - Average LLM Calls per Update: **0.3 calls** (70% compute reduction via Tier 0 & 1 short-circuiting)
  - Average CPU Latency per Changed Tool: **23.7 s**

---

## 5. Phase 5: Comprehensive Benchmark, Red-Teaming & Live Interception

Phase 5 performed the comprehensive final evaluation across the entire held-out test split, a 30-case adversarial red-team suite, and a live MCP JSON-RPC socket proxy fixture.

### 5.1 Held-Out Test Split Benchmark (N=56: 23 Benign, 33 Malicious/Suspicious)

| Detection System | TP | TN | FP | FN | Precision (95% CI) | Recall (95% CI) | $F_1$ Score | Benign FPR (95% CI) | Malicious FNR | Avg Latency | LLM Calls/Update |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Baseline 1)** | 33 | 0 | 23 | 0 | 58.9% | 100.0% | 74.2% | **100.0%** | 0.0% | <1 ms | 0.0 |
| **Static Heuristic Rules (Baseline 2)** | 25 | 23 | 0 | 8 | 100.0% | 75.8% | 86.2% | **0.0%** | 24.2% | <1 ms | 0.0 |
| **MCP Guard Middleware (Integrated)** | **33** | **23** | **0** | **0** | **100.0%** (89.6%–100%) | **100.0%** (89.6%–100%) | **100.0%** | **0.0%** (0.0%–14.3%) | **0.0%** | **30.5 s** | **0.54** |

- **Blocking Accuracy on N=56 Test Split**: 100.0% (56/56 correct decisions).
- **False Blocking Count**: 0 / 23 benign updates falsely blocked.
- **Missed Malicious Updates**: 0 / 33 malicious updates allowed.
- **Fast-Path Short-Circuit Rate**: 46.4% (26/56 updates evaluated in <1 ms without LLM calls).

---

### 5.2 Red-Team Adversarial Suite Evaluation (N=30)
Evaluated across 10 mutation categories (3 test cases per category) specifically designed to test evasion boundaries:

- **Total Adversarial Attacks Tested**: 30
- **Attacks Detected (TP)**: 21
- **Attacks Missed (FN)**: 9
- **Overall Adversarial Detection Rate**: **70.0%** ($21 / 30$)

| Evasion Transformation Category | Cases | Detected | Missed | Detection Rate (%) | Primary Failure Mode / Cause |
|---|---:|---:|---:|---:|---|
| **Indirect Wording** | 3 | 2 | 1 | 66.7% | Passive telemetry auditing framing |
| **Euphemistic Instructions** | 3 | 3 | 0 | 100.0% | File wipe described as "system cleanup" |
| **Multi-Step Intent** | 3 | 1 | 2 | 33.3% | Directive split across complex sentence sequences |
| **Semantically Subtle** | 3 | 3 | 0 | 100.0% | Authorization expansion |
| **Benign-Looking Prerequisites** | 3 | 3 | 0 | 100.0% | Disguised diagnostic tools (`health_check`) |
| **Parameter Description Hiding** | 3 | 3 | 0 | 100.0% | Payload embedded in schema docstrings |
| **Optional Parameter Hijacking** | 3 | 0 | 3 | **0.0%** | Optional schema parameters defaulting to webhooks |
| **Argument Redirection** | 3 | 3 | 0 | 100.0% | Explicit path redirection to `/etc/shadow` |
| **Field Splitting** | 3 | 3 | 0 | 100.0% | Directive split across name, description, schema |
| **Low-Signal Semantic Drift** | 3 | 0 | 3 | **0.0%** | Pure boolean schema toggles (`readOnly: True` $\rightarrow$ `False`) |

---

### 5.3 Live Local MCP JSON-RPC Proxy Interception Test
- **Execution Script**: `experiments/phase5_live_mcp_proxy.py`
- **Result Status**: **PASS**
- **Interception Verification**:
  1. **Bootstrap**: Client issued `tools/list` request; initial 2 tools registered as `TRUSTED` in `BaselineStore`.
  2. **Benign Update**: Server advertised UTF-8 docstring refinement; evaluated as `BENIGN` $\rightarrow$ `Action: ALLOW`. Database updated cleanly.
  3. **Poisoning Attack**: Server advertised prerequisite hijacking payload; evaluated as `MALICIOUS` $\rightarrow$ `Action: QUARANTINE`. Proxy intercepted response and returned the **Trusted V1 definition** to the client. Trusted baseline in database remained uncorrupted.
