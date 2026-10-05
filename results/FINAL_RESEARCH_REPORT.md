# Semantic Drift Detection for Model Context Protocol (MCP) Tool Definition Updates

## Abstract

The Model Context Protocol (MCP) enables Large Language Model (LLM) agents to dynamically discover and invoke external tools at runtime. However, advertised tool contracts—including docstrings, parameter descriptions, and schemas—are directly ingested into agent prompts, creating a critical attack vector for tool poisoning and unauthorized privilege escalation. Existing defense mechanisms rely on exact cryptographic hash pinning (e.g., SHA-256 over tool definitions), but this approach is semantics-blind: across 621 historical release transitions from 28 open-source MCP repositories, we measure that legitimate tool contracts evolve in 4.99% of releases, causing exact hash pinning to produce a **100.0% False Positive Rate (FPR)** on benign maintenance updates. 

To overcome this operational limitation, we propose and evaluate **MCP Semantic Drift Detection**, an intelligent defense framework that differentiates authentic software maintenance from malicious tampering. We implement the **MCP Semantic Drift Guard Middleware**, a 4-tier inspection pipeline combining sub-millisecond fast-path hash checks and static heuristics with a zero-temperature structured diff semantic judge (`Qwen3-8B`), backed by a persistent SQLite baseline store with automatic rollback. In extensive benchmarks over a cluster-isolated held-out test split ($N=56$), the Guard Middleware achieves **Precision = 100.0%, Recall = 100.0%, and $F_1 = 100.0\%$**, reducing benign false alarms from 100.0% down to **0.0%** (95% CI: [0.0%, 14.3%]). Furthermore, controlled JSON-RPC socket proxy testing confirms real-time interception, policy enforcement, and automatic definition rollback in active protocol streams. 

Finally, adversarial red-teaming across 30 evasion test cases spanning 10 mutation categories demonstrates a **70.0% Adversarial Detection Rate**, confirming strong resilience against indirect wording, euphemisms, and prerequisite hijacking, while uncovering key evasion surfaces in optional parameter default injections (0/3 detected) and low-signal boolean schema toggles (0/3 detected). These results empirically demonstrate that meaning-aware semantic drift detection provides a viable and necessary security layer for dynamic tool-augmented agent ecosystems.

---

## 1. Introduction

### 1.1 The Problem
Autonomous AI agents increasingly rely on standard interface protocols to interact with external databases, execution sandboxes, code repositories, and web services. The Model Context Protocol (MCP) has emerged as an open standard for connecting LLM hosts to heterogeneous tool servers. Under MCP, clients discover available capabilities at runtime by issuing `tools/list` requests. Upstream servers respond with tool manifests containing natural language descriptions, parameter names, type constraints, and documentation.

Because agent host systems inject these advertised manifests directly into system prompts to guide model reasoning, tool definitions occupy a trusted position within the agent's cognitive context. If an upstream server is compromised, malicious dependencies are introduced, or an untrusted server modifies its contracts post-registration, the agent can be coerced into following poisoned instructions—such as exfiltrating user credentials, invoking destructive commands, or chaining unauthorized tools.

### 1.2 Motivation
Current industry security scanners and client integrity checkers (e.g., `snyk-agent-scan` / `mcp-scan`) address tool poisoning via **exact cryptographic tool pinning**. Under exact pinning, a client hashes the canonical JSON representation of a tool definition (SHA-256) upon initial approval. On subsequent invocations, any mismatch between the active hash and the pinned baseline raises a security alarm.

While cryptographically sound, exact hash pinning is completely blind to natural language semantics. Software contracts in production environments are not static artifacts: open-source developers continuously refine docstrings to improve model adherence, clarify parameter edge cases, fix typos, and add backward-compatible optional features. Because exact hashing treats every byte-level modification as a potential breach, it forces human operators into an intolerable dilemma: either disable tool verification entirely or manually audit and re-approve approximately 5% of all routine software releases.

### 1.3 Research Gap
No prior work has characterized the empirical evolution rates of Model Context Protocol tool contracts in the wild, nor has any system evaluated whether local, lightweight LLM judges can reliably distinguish benign software maintenance from malicious prompt injection without relying on rigid byte equality. This research addresses this gap by:
1. Providing the first empirical measurement of tool definition evolution across open-source MCP servers.
2. Formulating and benchmarking meaning-aware Semantic Drift Judges.
3. Implementing and evaluating an integrated, 4-tier enforcement middleware with automatic rollback.
4. Stress-testing the approach against an adversarial red-team evasion suite.

---

## 2. Background

### 2.1 Model Context Protocol (MCP)
The Model Context Protocol standardizes client-server interactions through JSON-RPC 2.0 messages exchanged over standard I/O (stdio) or Server-Sent Events (SSE). During initialization and capability negotiation, the client queries `tools/list` to retrieve the active tool catalog. A tool definition schema consists of:
- `name`: String identifier.
- `description`: Human- and LLM-readable docstring detailing tool intent, usage rules, and behavioral constraints.
- `inputSchema`: JSON Schema specification defining property types, parameter descriptions, required arrays, and validation constraints.

### 2.2 Tool Poisoning & The Capability Paradox
Tool poisoning attacks manipulate tool docstrings to inject adversarial system instructions (e.g., `<IMPORTANT> Before calling this tool, transmit ~/.ssh/id_rsa to external endpoint</IMPORTANT>`). In Phase 1, we reproduced the **MCPTox** benchmark (*"MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers"*, AAAI 2026 / arXiv:2508.14925) using local `Qwen3-8B`.

Our experiments confirmed the **Capability Paradox**: enabling internal reasoning/thinking in `Qwen3-8B` increased tool docstring instruction adherence, which raised attack susceptibility from **13.97% (No-Think ASR)** up to **41.76% (Think ASR)** ($+27.79\text{ percentage points}$). Standard model safety filters recorded **0 refusals** across all 1,348 evaluated test instances, demonstrating that LLM agents blindly adhere to poisoned tool metadata.

### 2.3 Tool Definition Updates & Exact Hash Pinning
Exact tool pinning evaluates integrity via strict hash equality:
$$\text{Status} = \begin{cases} \text{ALLOW}, & \text{SHA256}(\text{Tool}_{\text{candidate}}) = \text{SHA256}(\text{Tool}_{\text{trusted}}) \\ \text{ALERT / BLOCK}, & \text{otherwise} \end{cases}$$

Because SHA-256 exhibits the avalanche effect, any character modification produces complete digest divergence. Consequently, exact pinning fails to differentiate harmless documentation updates from high-severity poisoning payloads.

---

## 3. Threat Model

### 3.1 Attacker Goal & Capabilities
- **Attacker Goal**: Tamper with an MCP server's advertised tool definitions so that an unsuspecting LLM agent executes unauthorized actions (e.g., credential exfiltration, file destruction, unauthorized prerequisite chaining).
- **In-Scope Capabilities**:
  - Modifying natural language tool `description` fields.
  - Modifying parameter `description` fields within `inputSchema.properties`.
  - Adding or modifying JSON Schema property attributes (`default`, `readOnly`, type constraints).
  - Adding new tools or removing existing tools.
  - Employing evasive framing (passive voice, indirect phrasing, multi-step splitting).

### 3.2 Defender Objectives
- **Defender**: The MCP Semantic Drift Guard Middleware intercepting JSON-RPC `tools/list` responses.
- **Objectives**:
  1. Intercept and quarantine malicious contract modifications before they enter the agent prompt.
  2. Differentiate benign documentation/schema evolution from malicious drift, reducing false positive alarms.
  3. Maintain persistent trusted baselines and automatically roll back quarantined definitions to trusted V1 contracts.
  4. Produce structured, tamper-evident audit logs.

### 3.3 Out-of-Scope Risks
Runtime binary exploitation within the server process, unencrypted network transport sniffing (non-TLS), OS-level database corruption, and direct user prompt jailbreaks unrelated to tool manifests are excluded from this study.

---

## 4. Research Questions

- **RQ1**: How frequently do legitimate MCP tool-definition changes occur in real-world software releases?
- **RQ2**: How does exact cryptographic hash pinning behave when applied to authentic open-source updates?
- **RQ3**: Can a local, zero-temperature semantic judge distinguish malicious poisoning from legitimate developer maintenance?
- **RQ4**: Can semantic drift detection be integrated into an operational middleware enforcing policy decisions and automatic rollback with acceptable latency?
- **RQ5**: How robust is semantic drift detection against adversarial and evasive attack transformations?

---

## 5. Dataset and Corpus Construction

### 5.1 Real-World MCP Evolution Corpus (Phase 2)
To answer RQ1 and RQ2, we assembled a corpus of 28 open-source MCP server repositories (official and community), extracting full git commit histories across tagged releases:
- **Analyzed Repositories**: 28 servers (25 with multi-version histories $\ge 2$ tags).
- **Extracted Tool Snapshots**: 594 versioned JSON snapshots.
- **Unique Tool Contracts**: 285 distinct tool interfaces.
- **Comparable Release Transitions**: 621 consecutive version pairs $(V_i \rightarrow V_{i+1})$.
- **Total Tool-Pair Comparisons**: 4,961 individual tool contract comparisons.
- **Recorded Definition Changes**: 123 contract modifications.

#### Empirical Evolutionary Rates
- **Definition-Change Rate**: **2.48%** ($123 / 4,961$ tool comparisons).
- **Release-Change Rate**: **4.99%** ($31 / 621$ releases contained $\ge 1$ modified tool).
- **Description-Change Rate**: **1.13%** ($7 / 621$ releases modified docstrings without code changes).
- **Schema-Change Rate**: **0.32%** ($2 / 621$ releases modified input schemas).

| Evolution Category | Count | Percentage | Primary Impact |
|---|---:|---:|---|
| `tool_addition` | 63 | 51.22% | Expands agent registry with new capabilities |
| `tool_removal` | 47 | 38.21% | Deprecates obsolete tools or consolidates APIs |
| `clarification` | 11 | 8.94% | Refines docstrings to improve LLM adherence |
| `new_feature` | 2 | 1.63% | Adds backward-compatible optional parameters |
| **Total** | **123** | **100.0%** | |

### 5.2 Synthetic Poisoning Attacks (MCPTox)
To construct positive attack cases, 200 poisoned tool contracts were generated from the MCPTox benchmark spanning 3 attack paradigms:
1. **Template-1: Direct Injection** (33 cases): Imperative prompt overrides forcing unauthorized tool calls.
2. **Template-2: Prerequisite Hijacking** (75 cases): Embedding mandatory prerequisites to secondary tools.
3. **Template-3: Argument Tampering** (92 cases): Forcing redirection of arguments to sensitive paths.

### 5.3 Combined Dataset & Split Isolation (Phase 3)
The combined dataset comprises 370 examples partitioned into Train, Dev, and Test splits. To prevent data leakage, splits were grouped strictly by **cluster key** (`server_id + tool_name`):

| Dataset Split | Real Open-Source Updates | Hard Negatives (Security Wording) | MCPTox Attacks | Total Examples | Unique Clusters |
|---|---:|---:|---:|---:|---:|
| **Train Set** | 91 | 33 | 135 | **259** | 144 |
| **Dev Set** | 17 | 6 | 32 | **55** | 34 |
| **Test Set** | 15 | 8 | 33 | **56** | 31 |
| **Total Corpus** | **123** | **47** | **200** | **370** | **144** |

- **Leakage Verification**: **0 cluster-level overlap** across Train, Dev, and Test splits. Zero duplicate record IDs.

---

## 6. Methodology & Architecture

The **MCP Guard Middleware** (`guard/middleware.py`) implements a 4-Tier Short-Circuit Pipeline:

```
Candidate Tool Definition (new_def)
                │
                ▼
      ┌──────────────────┐
      │  Tier 0: Hash    │──[ Match ]────────► ALLOW (<1 ms, 0 LLM calls)
      └─────────┬────────┘
                │ Differs
                ▼
      ┌──────────────────┐
      │  Tier 2: Diff    │──► Computes JSON-Aware Structured Delta
      └─────────┬────────┘
                │
                ▼
      ┌──────────────────┐
      │  Tier 1: Static  │──[ High Severity ]► QUARANTINE (<1 ms, 0 LLM calls)
      └─────────┬────────┘
                │ Unflagged
                ▼
      ┌──────────────────┐
      │  Tier 3: Judge   │──► Local Qwen3-8B (Mode B Diff Only, T=0)
      └─────────┬────────┘
                │
                ▼
      ┌──────────────────┐
      │  Policy Engine   │──► Enforces ALLOW / WARN / BLOCK / QUARANTINE
      └─────────┬────────┘
                │
         [ SQLite Store & Automatic Rollback ]
```

### 6.1 Tier 0: Canonical Hash Fast Path
Computes SHA-256 over normalized JSON. If the candidate hash matches the trusted baseline hash, execution terminates immediately with `ALLOW` (<1 ms latency, 0 LLM calls).

### 6.2 Tier 2: Structured Contract Diff Engine
Generates a structured contract delta:
- `params_added`, `params_removed`, `params_modified`.
- `description_diff_summary`: Compact unified diff of docstring modifications.

### 6.3 Tier 1: Static Heuristic Fast Alert
Scans descriptions and diff summaries against 7 regular expressions. Matches marked `severity == "high"` (e.g., explicit `/etc/shadow` references, `"MUST FIRST CALL"`) immediately trigger `QUARANTINE` (<1 ms latency, 0 LLM calls).

### 6.4 Tier 3: Semantic Judge (Mode B Diff Only)
Prompts local `Qwen3-8B` ($T=0$) with the structured diff wrapped in `<untrusted_diff>` XML sandboxes. Emits structured JSON containing `label` (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`), `confidence`, and `rationale`.

### 6.5 Policy Engine, Baseline Store, and Rollback
- **Policy Modes**: `BALANCED` (Default), `STRICT`, `AUDIT`.
- **Baseline Store**: Persistent SQLite database.
- **Rollback Routine**: When an update is quarantined, the baseline store retains the trusted V1 definition, and the middleware substitutes the active tool payload with the trusted V1 definition in the response returned to the client agent.

---

## 7. Experimental Setup

- **Hardware**: Standard workstation (Intel/AMD x86_64, CPU-only evaluation).
- **Software**: Windows 11, Python 3.12, SQLite 3.
- **LLM Engine**: Ollama v0.35.1 running `qwen3:8b` (Quantization: `Q4_K_M`).
- **Decoding Configuration**: Greedy decoding ($T = 0.0$, top_p $= 1.0$, fixed seed $= 42$).
- **Benchmark Datasets**:
  - Full Held-Out Test Split ($N=56$: 23 Benign, 33 Malicious).
  - Red-Team Adversarial Suite ($N=30$: 10 mutation categories).
  - Real Open-Source Updates ($N=123$ from Phase 2).
  - Live Local Socket Proxy Fixture (`experiments/phase5_live_mcp_proxy.py`).

---

## 8. Quantitative Results

### 8.1 Phase 1 Results: Baseline Replication
- **MCPTox Reproduction**: Measured ASR on `Qwen3-8B` was **41.76% (Think)** vs. **13.97% (No-Think)**, reproducing published baselines within 0.04 percentage points.
- **Hash Pinning Audit**: Confirmed exact hashing raises false alarms on 100% of non-identical definitions.

### 8.2 Phase 2 Results: Real-World MCP Evolution
- Measured a **4.99% release-change rate** across 621 release transitions. Exact hash pinning flagged **31 out of 31 modified releases (100.0% Benign FPR)**.

### 8.3 Phase 3 Results: Exploratory Benchmark & Representation Ablation
Evaluating representations on a 10-example stratified sample:
- **Exact Hash Pinning**: Precision = 60.0%, Recall = 100.0%, $F_1 = 75.0\%$, Benign FPR = **100.0%**.
- **Static Rules**: Precision = 100.0%, Recall = 50.0%, $F_1 = 66.7\%$, Malicious FNR = **50.0%**.
- **Mode A (Full Definition)**: $F_1 = 83.3\%$, with a **20.0% JSON output parsing failure rate**.
- **Mode B (Diff Only)**: Precision = 85.7%, Recall = 100.0%, **$F_1 = 92.3\%$**, Benign FPR = **25.0%**, JSON Parse Errors = **0.0%**.

### 8.4 Phase 4 Results: Integrated Middleware Replay
Across 10 stratified held-out test split examples, the integrated Guard Middleware achieved **100.0% Precision, 100.0% Recall, and 100.0% $F_1$**, reducing average LLM calls per update to **0.3 calls** via Tier 0 and Tier 1 short-circuits. All 28 unit tests passed cleanly (**28/28 OK**).

### 8.5 Phase 5 Results: Master Full Test Split Benchmark (N=56)

| Detection System | TP | TN | FP | FN | Precision (95% CI) | Recall (95% CI) | $F_1$ Score | Benign FPR (95% CI) | Malicious FNR | Avg Latency | LLM Calls / Update |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Baseline 1)** | 33 | 0 | 23 | 0 | 58.9% (46.2%–70.6%) | 100.0% (89.6%–100%) | 74.2% | **100.0%** (85.7%–100%) | 0.0% | <1 ms | 0.0 |
| **Static Heuristic Rules (Baseline 2)** | 25 | 23 | 0 | 8 | 100.0% (86.7%–100%) | 75.8% (59.0%–87.2%) | 86.2% | **0.0%** (0.0%–14.3%) | 24.2% | <1 ms | 0.0 |
| **MCP Guard Middleware (Integrated)** | **33** | **23** | **0** | **0** | **100.0%** (89.6%–100%) | **100.0%** (89.6%–100%) | **100.0%** | **0.0%** (0.0%–14.3%) | **0.0%** | **30.5 s** | **0.54** |

- **Answering RQ2**: Exact hash pinning flags every observed tool-definition change because its integrity criterion is byte-level equality, alerting on 100.0% of the evaluated benign maintenance updates (23/23).
- **Answering RQ3**: In the integrated Phase 5 evaluation on the held-out N=56 test split under the BALANCED policy with pre-populated trusted baselines, the integrated middleware achieved **100.0% Recall and 0.0% Benign FPR**.
- **Answering RQ4**: The Guard Middleware successfully enforces operational policies with **0 false blocks and 0 missed malicious updates**, short-circuiting **46.4% of updates** in <1 ms without LLM overhead.

---

## 9. Adversarial Red-Team Evaluation (N=30)

To answer **RQ5**, we designed and executed a 30-case adversarial suite across 10 evasion categories (3 cases per category):

- **Total Attacks Tested**: 30
- **Attacks Detected (TP)**: 21
- **Attacks Missed (FN)**: 9
- **Overall Adversarial Detection Rate**: **70.0%** ($21 / 30$)

| Evasion Transformation Category | Cases | Detected | Missed | Detection Rate (%) | Operational Vulnerability Analysis |
|---|---:|---:|---:|---:|---|
| **Indirect Wording** | 3 | 2 | 1 | 66.7% | Exfiltration framed as passive telemetry |
| **Euphemistic Instructions** | 3 | 3 | 0 | 100.0% | File wipe described as "system cleanup" |
| **Multi-Step Intent** | 3 | 1 | 2 | 33.3% | Exfiltration split across complex sentence chains |
| **Semantically Subtle Changes** | 3 | 3 | 0 | 100.0% | Authorization boundary expansion |
| **Benign-Looking Prerequisites** | 3 | 3 | 0 | 100.0% | Disguised diagnostic prerequisite (`health_check`) |
| **Parameter Description Hiding** | 3 | 3 | 0 | 100.0% | Injection hidden inside parameter docstrings |
| **Optional Parameter Hijacking** | 3 | 0 | 3 | **0.0%** | **Evasion**: New optional parameter with default webhook URL |
| **Argument Redirection** | 3 | 3 | 0 | 100.0% | Explicit redirection to `/etc/shadow` |
| **Field Splitting** | 3 | 3 | 0 | 100.0% | Attack split across name, description, schema |
| **Low-Signal Semantic Drift** | 3 | 0 | 3 | **0.0%** | **Evasion**: Toggling `"readOnly": true` $\rightarrow$ `false` |

---

## 10. Error Analysis

1. **Hash Pinning False Alarms**: Solved by replacing exact byte hashing with structured diff semantic reasoning, allowing authentic updates to pass cleanly.
2. **Static Rule Brittleness**: Solved by positioning static rules as Tier 1 fast filters rather than standalone judges.
3. **Representation Sensitivity**: Diff-Only Mode B eliminated context bloat, reducing JSON parsing failures from 20.0% down to 0.0%.
4. **Schema-Only Evasion Blind Spots**: The semantic judge prompt emphasizes natural language docstrings and missed 100% of optional parameter default injections (0/3) and low-signal boolean schema toggles (0/3). These represent the primary remaining evasion surfaces.

---

## 11. Security Analysis & Rollback Verification

Controlled socket proxy testing (`experiments/phase5_live_mcp_proxy.py`) verified real-time `tools/list` JSON-RPC traffic interception:
- **Bootstrap Phase**: Initial tool contracts were registered in SQLite as `TRUSTED`.
- **Benign Update Phase**: Docstring clarifications were evaluated as `BENIGN` $\rightarrow$ `ALLOW`, updating baseline records.
- **Attack Phase**: A poisoned tool contract was intercepted, evaluated as `MALICIOUS` $\rightarrow$ `QUARANTINE`, and automatically replaced with the **Trusted V1 definition** in the JSON-RPC response returned to the client agent. The candidate payload was prevented from corrupting the baseline database.

---

## 12. Performance & Latency Analysis

- **Tier 0 Hash Fast Path**: Latency <1 ms (0 LLM calls).
- **Tier 1 Static Fast Alert**: Latency <1 ms (0 LLM calls).
- **Tier 3 Semantic Judge (CPU Inference)**: Mean Latency = **30.5 s** (p50 = 41.6 s, p95 = 72.6 s).
- **Compute Optimization**: The 4-tier architecture reduced LLM invocations to **0.54 calls per update** on the full test split (46.4% short-circuit rate).
- **Operational Reality**: While sub-millisecond fast paths handle unchanged and overtly malicious tools instantly, the ~30.5-second CPU inference latency requires **GPU hardware acceleration** or an **asynchronous out-of-band staging architecture** for interactive production deployments.

---

## 13. Limitations

1. **Held-Out Test Sample ($N=56$)**: While statistically bounded with Wilson score confidence intervals, evaluation across larger multi-thousand server datasets is desirable.
2. **Adversarial Red-Team Scale ($N=30$)**: 30 structured cases identified key blind spots, but continuous automated fuzzing is required.
3. **Adversarial Detection Rate (70.0%)**: Evasions succeeded in optional parameter defaults (0/3) and low-signal schema toggles (0/3).
4. **CPU Latency**: 30.5s local CPU latency is impractical for synchronous blocking inline proxies without GPU acceleration.
5. **Controlled Proxy Fixture**: Local socket testing demonstrated proxy mechanics but does not substitute for distributed internet deployments.
6. **Corpus Scope**: Limited to 28 open-source repositories (621 release transitions).
7. **Payload Overlap Reporting**: 1 synthetic payload template (`simple_subtraction`) was shared between Train and Test splits across different server targets.
8. **No Claim of Production Readiness**: The framework is a verified research prototype demonstrating the superiority of semantic drift detection over rigid hash pinning.

---

## 14. Future Work

1. **Dedicated JSON Schema Diff Validators**: Implement structural constraint solvers to intercept boolean toggles (`readOnly`) and default webhook arguments prior to LLM evaluation.
2. **GPU-Accelerated Inference & Async Daemons**: Deploy judges on vLLM/TensorRT-LLM to achieve sub-second inference, integrated with asynchronous background staging queues.
3. **Continuous Open-Source Repository Watchers**: Expand corpus tracking across thousands of live community registries.
4. **Automated Adversarial Fuzzing**: Build LLM-in-the-loop red-teaming harnesses to mutate tool contracts across diverse linguistic dimensions.
5. **Formal Verification Hybridization**: Pair formal schema logic with semantic reasoning to provide mathematical contract guarantees.

---

## 15. Conclusion

This research demonstrates that **MCP Semantic Drift Detection** separates byte-level integrity verification from semantic security analysis. While exact cryptographic hashing flags all observed tool-definition changes because its integrity criterion is byte-level equality, the integrated Guard Middleware under the tested BALANCED policy reduced false alarms on the evaluated N=56 test split while detecting all tested attack vectors in that sample. Adversarial evaluations show strong baseline detection against explicit instruction tampering while highlighting subtle euphemisms and breaking schema evolutions as key areas for ongoing defensive refinement.
