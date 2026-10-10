# Salami Rug-Pulls in the Model Context Protocol: Detecting Incremental Tool-Poisoning Attacks via Multi-Tier Semantic Drift Vetting

## Abstract

The Model Context Protocol (MCP) enables Large Language Model (LLM) agents to dynamically discover and execute external tools at runtime. However, because advertised tool contracts—including docstrings, parameter descriptions, and schemas—are directly ingested into agent system prompts, malicious or compromised upstream servers can mount tool-poisoning attacks to hijack agent execution. While single-step attacks inject overt malicious directives, sophisticated adversaries can partition an unauthorized capability escalation across multiple consecutive, individually subtle release updates—a threat model we formalize as **Salami Drift** (or incremental "rug-pull" attacks). Existing MCP defenses detect change (exact hash pinning, signing) or judge a single definition (static scanners, monolithic LLM vetting), failing to differentiate benign contract refactoring from multi-step capability creep.

Across an empirical audit of 621 historical release transitions from open-source MCP repositories, 31 releases (4.99%) contained legitimate tool-definition modifications (an operator burden of 0.050 alerts per release transition), all of which trigger security re-approval under exact cryptographic pinning. To address this challenge, we introduce the **MCP Semantic Drift Guard**, a 5-tier architecture combining deterministic fast-paths ($< 0.25$ ms), schema security checks, and structured diff reasoning powered by local open-weight models (`gemma3:4b`, 4B parameters) under Draft-07 JSON Schema constrained decoding.

In single-step held-out benchmark evaluations ($N=56$; source: `results/computed_metrics.json`), exact cryptographic hash pinning achieves **Precision = 58.9%**, **Recall = 100.0%**, with **Benign FPR = 100.0%** (by construction); author-defined static regex rules achieve **Precision = 100.0%**, **Recall = 75.8%**, with **Benign FPR = 0.0%**; and the TF-IDF cosine baseline achieves **Precision = 64.6%**, **Recall = 93.9%**, with **Benign FPR = 73.9%**.

On the pre-registered **Salami Drift Benchmark V4** ($N=116$ chains, 436 transitions; SHA-256: `91f1d0de...`) evaluated under a server-disjoint 50/50 split (58 calibration chains, 58 frozen held-out test chains: 26 Salami, 7 Fast-Jump, 25 Benign):
1. **Adjacent vs. Cumulative Comparison**: Under the primary pre-registered rule (**Rule b BALANCED**), Adjacent comparison achieves **96.2% (25/26)** Salami-only chain recall [95% Wilson CI: 81.1%, 99.3%] with a mean exposure window of $\bar{W}_e = 0.192$ steps and **4.0% (1/25)** Benign FPR [0.7%, 19.5%]. Cumulative root comparison achieves **76.9% (20/26)** Salami recall [58.0%, 89.0%] with $\bar{W}_e = 0.731$ and **0.0% (0/25)** Benign FPR [0.0%, 13.3%] (test split difference: +19.2% [95% bootstrap CI: +0.0%, +38.5%], McNemar $p = 0.125$; calibration split difference: +26.5%, $p = 0.0225$). The direction of superiority flipped from earlier V3 unconstrained benchmarks; trace analysis suggests the empirical hypothesis that local 4B models experience attention dilution over multi-field cumulative diffs (observed in Category G sample, $N=12$), while cumulative comparison excels at instruction erosion (Category E, $N=12$).
2. **Matched-FPR Baselines**: Exact cryptographic hash pinning achieves 100.0% (26/26) recall by construction, but incurs a 100.0% (25/25) benign false alarm rate ($\bar{W}_e = 0.000$). At calibrated low-FPR operating points ($\le 4.0\%$), deterministic baselines fail to detect multi-step drift (Parameter delta: 0.0%, Levenshtein edit distance: 0.0%, TF-IDF cosine distance: 3.9%, Static regex: 0.0%). Parameter delta matches Cumulative recall (76.9% [20/26]) only by accepting a 44.0% (11/25) benign false alarm rate.
3. **Novel Architectures**: Root-anchored Capability-Set Tracking achieves 61.5% (16/26) Salami recall but suffers 32.0% (8/25) Benign FPR on legitimate additions; Calibrated Drift Budgeting ($B^*=4.10$) maintains 0.0% (0/25) Benign FPR but yields 30.8% (8/26) Salami recall.
4. **Adaptive Attacker Resistance**: Under black-box template and semantic mutation search ($Q \le 5$ queries/step, average 8.12 queries/chain, $N=24$ malicious chains), the Adjacent Guard retains **91.7% post-adaptive recall** (22/24; 8.3% evasion rate [2.3%, 25.9%]), whereas Cumulative Guard suffers 41.7% evasion (10/24) and Drift Budget suffers 83.3% evasion (20/24), indicating that cumulative root anchoring enables incremental budget exploitation under adaptive search.
5. **Delivery Layer & Live Transport**: Empirical evaluation across 5 scripted transport failure conditions on a localhost mock harness (ratcheting, dynamic reconnection reset, TOCTOU double fetch, dropped notifications, judge timeout fail-safe) demonstrates elimination of unvetted definition delivery across all 5 test conditions (5/5 $\rightarrow$ 0/5).
6. **Benchmark Audit Limitations**: Benchmark V4 exhibits docstring length shift correlation (ROC-AUC = 0.7228) and borderline edit distance ($\max(\text{AUC}, 1-\text{AUC}) = 0.6511$), failing the pre-registered $<0.65$ gate; all findings are reported subject to this limitation.

---

## 1. Introduction

### 1.1 The Problem
Autonomous AI agents increasingly rely on standard interface protocols to interact with external databases, execution sandboxes, code repositories, and web services. The Model Context Protocol (MCP; Anthropic / Model Context Protocol Working Group, 2024) has emerged as an open standard for connecting LLM hosts to heterogeneous tool servers. Under MCP, clients discover available capabilities at runtime by issuing `tools/list` requests. Upstream servers respond with tool manifests containing natural language descriptions, parameter names, type constraints, and documentation.

Because agent host systems inject these advertised manifests directly into system prompts to guide model reasoning, tool definitions occupy a trusted position within the agent's cognitive context. If an upstream server is compromised, malicious dependencies are introduced, or an untrusted server modifies its contracts post-registration, the agent can be coerced into following poisoned instructions—such as exfiltrating user credentials, invoking destructive commands, or chaining unauthorized tools.

### 1.2 Motivation & Operator Review Burden
Current industry security scanners and client integrity checkers address tool poisoning via **exact cryptographic tool pinning**. Under exact pinning, a client hashes the canonical JSON representation of a tool definition (SHA-256) upon initial approval. On subsequent invocations, any mismatch between the active hash and the pinned baseline raises a security alarm.

Exact hash comparison evaluates strict byte-level equality, answering the binary integrity question: *"Did the trusted definition change?"* However, software contracts in active ecosystems are not static artifacts: open-source developers continuously refine docstrings to improve model adherence, clarify parameter edge cases, fix typos, add new tools, and introduce backward-compatible optional features.

Across our empirical audit of 621 historical release transitions across open-source MCP repositories:
- **31 of 621 release transitions (4.99%)** contained at least one tool-definition change.
- A total of **123 tool-definition change events** were recorded.
- **110 of the 123 change events (89.4%)** represent tool additions (63 events) or tool removals (47 events), occurring across 20+ release transitions. Under standard security policy, unbaselined tool additions and deletions are handled via **Initial Discovery Quarantine** requiring explicit administrative provisioning.
- Thus, the true **addressable review burden** for continuous semantic contract drift monitoring across pre-existing tool versions is **13 of 621 release transitions (2.09%)** (13 total modification events):
  - Description / documentation clarifications: 7 releases (1.13% of transitions).
  - Schema / parameter modifications: 2 releases (0.32% of transitions).
  - Mixed description and schema modifications: 4 releases (0.64% of transitions).

#### Quantifying the Review Burden:
1. **Under Exact Hash Pinning**: Because any byte change alters the SHA-256 digest, all 31 release transitions with tool-definition changes trigger security alerts. This imposes a raw alert burden of **0.050 alerts per release transition** (~1 review alert every 20 releases) across all change events, or **0.021 alerts per release transition** specifically for pre-existing contract modifications. For an active enterprise deploying 20 MCP servers with ~20 annual releases each, exact pinning creates ~20–25 manual review interruptions per year solely for benign refactorings.
2. **Under Semantic Drift Guard**: By isolating structured diffs and executing schema-constrained semantic verification, the defense differentiates benign clarifications from malicious drift, achieving a 4.0% (1/25) false alarm rate on synthetic benchmark chains ($N=58$) while detecting 96.2% (25/26) of multi-step attacks. Operator review burden on production workloads remains an unmeasured qualitative factor designated for future longitudinal study.

### 1.3 Threat Formalization & Primary Contributions
Existing MCP defenses detect change (hash pinning, signing) or judge a single definition (static scanners, one-shot LLM vetting). No prior defense evaluates whether a sequence of individually subtle updates accumulates into a malicious capability escalation. This paper delivers:
1. **Empirical Measurement of Open-Source MCP Evolution**: Longitudinal audit of 621 historical release transitions across 28 open-source MCP repositories, quantifying change rates and operator review burdens.
2. **Salami Drift Benchmark V4 & Pre-Registration Protocol**: Formal threat formulation and release of Benchmark V4 ($N=116$ chains, 436 transitions; SHA-256: `91f1d0de...`) with server-disjoint calibration/test splits and automated trivial-separator screening.
3. **Multi-Tier Semantic Drift Guard Architecture**: Implementation of a 5-tier defense middleware (`guard/middleware.py`) combining sub-millisecond fast-paths ($< 0.25\text{ ms}$), deterministic schema security rules, and XML-sandboxed structured diff reasoning.
4. **Matched-FPR Baseline & Trade-Off Evaluation**: Rigorous empirical evaluation comparing Adjacent vs. Cumulative comparison strategies under local judge capacity constraints ($p = 0.125$), alongside deterministic baselines, Capability-Set Tracking, and Calibrated Drift Budgeting ($B^*=4.10$).
5. **Adaptive Attacker & Delivery Layer Simulation Evaluation**: Simulation-level evaluation against black-box semantic mutation search ($Q \le 5$, $N=24$ chains) and scripted failure injection across 5 transport failure conditions on a localhost mock harness.

---

## 2. Background & Threat Model

### 2.1 Model Context Protocol (MCP) Mechanics
The Model Context Protocol (Anthropic / Model Context Protocol Working Group, 2024) standardizes client-host-server interactions via JSON-RPC 2.0 messages over two primary transports:
1. **Standard I/O (`stdio`)**: Process-isolated stdin/stdout communication using newline-delimited JSON-RPC 2.0.
2. **Streamable HTTP / SSE (`sse`)**: HTTP POST requests for client-to-server messaging, coupled with Server-Sent Events (SSE) for server-to-client streaming notifications.

During initialization (`initialize` / `notifications/initialized`), client and server negotiate capabilities. The host discovers tools via `tools/list`, to which the server responds with a catalog containing:
- `name`: Unique string identifier for the tool.
- `description`: Natural language docstring detailing tool functionality, constraints, and instructions.
- `inputSchema`: Draft-07 JSON Schema defining parameter properties, types, descriptions, default values, and required lists.

When an LLM decides to execute an action, it dispatches `tools/call`. If the server updates its tool catalog dynamically, it emits `notifications/tools/list_changed`, prompting the client to refresh its tool definitions via `tools/list`.

### 2.2 Tool Poisoning & Reasoning-Mode Vulnerability (MCPTox Replication)
Tool poisoning attacks manipulate tool docstrings to inject adversarial directives. We reproduced the **MCPTox** benchmark (Wang et al., 2025) using local `Qwen3-8B` (Quantization: `Q4_K_M`, $T=0$) across 1,348 test instances spanning 45 MCP servers:
- **No-Think Mode**: 188 exploited out of 1,346 valid instances (**13.97% ASR**).
- **Think Mode**: 560 exploited out of 1,341 valid instances (**41.76% ASR**).
- **Attack Breakdown**: Template-1 Direct Injection (44.93% Think vs 8.13% No-Think); Template-2 Prerequisite Hijacking (25.15% Think vs 3.66% No-Think); Template-3 Argument Redirection (54.62% Think vs 24.60% No-Think).

Activating internal reasoning tokens increased attack susceptibility by **+27.79 percentage points**, replicating the **Reasoning-Mode Vulnerability**: extended reasoning tokens improved the model's adherence to natural language docstrings, while standard safety filters recorded **0 refusals** across all 1,348 test instances.

### 2.3 Knowledgeable & Adaptive Attacker Threat Model
1. **Attacker Knowledge**: The adversary has full knowledge of the defensive pipeline, including hash pinning, static regex patterns, structured diff schema representations, judge prompt templates, and the SQLite baseline store.
2. **Attacker Capabilities**:
   - Modifying tool docstrings and parameter descriptions using indirect phrasing, euphemisms, or semantic paraphrasing.
   - Injecting prompt override payloads targeting the judge.
   - Manipulating JSON Schema attributes (adding optional parameters with default webhook URLs, toggling `readOnly: true -> false`).
   - Introducing multi-step incremental semantic drift across releases (salami attacks).
   - Dynamically querying the black-box defense up to $Q \le 5$ times per step to find evasive mutations.
3. **Defender Capabilities**: Middleware proxy positioned at the JSON-RPC boundary intercepting `tools/list` responses, maintaining a persistent trusted SQLite baseline store, enforcing atomic cache forwarding, and executing automatic rollback or quarantine.

### 2.4 Transport Layer Mechanics & Lifecycle Hooks
The MCP lifecycle establishes specific protocol interactions that adversaries can exploit:
- **Session Reconnection**: When an MCP client reconnects to an SSE server, dynamic server instance IDs can trigger a Trust-on-First-Use (TOFU) reset if identity anchors are not cryptographically bound across sessions.
- **Dynamic Catalog Refresh**: The `notifications/tools/list_changed` notification signals dynamic tool updates. If notifications are dropped or coalesced in high-throughput streams, the client execution engine risks invoking mutated tools without re-vetting.
- **Time-of-Check to Time-of-Use (TOCTOU)**: If the defense performs a double fetch (fetching a definition to inspect, then requesting the catalog again for client dispatch), a malicious server can return a benign contract during inspection and swap in poisoned payloads during dispatch. Single-fetch atomic cache forwarding is required to eliminate this race condition.

### 2.5 Defense Scope & Threat Boundary Table
Table 1b formalizes the operational boundaries of the defense:

| Threat Category | In-Scope Attack Vectors | Out-of-Scope Threat Vectors | Primary Defensive Mitigation |
|---|---|---|---|
| **Contract Mutation** | Docstring injection, parameter descriptions, schema privilege escalation, multi-step salami drift | Runtime tool-execution return value poisoning, prompt injection in user prompts | Multi-Tier Semantic Drift Guard (Tiers 0–3) |
| **Transport Desync** | TOCTOU swapping, reconnection resets, dropped `list_changed` notifications | Kernel compromise, network-level man-in-the-middle on unencrypted transports | State-Monotonic Version Barrier, Atomic Cache Forwarding |
| **Ecosystem Collusion** | Single-server multi-step capability creep | Multi-server cross-tool distributed collusion beyond individual server state | Per-server SQLite baseline store and rollback quarantine |

---

## 3. Related Work & Defensive Taxonomy

Table 1 summarizes the defensive boundaries across existing paradigms and the MCP Semantic Drift Guard:

| Defense Paradigm | Exemplar Approaches | Threat Model Scope | Primary Detection Target | Operational Blind Spots | Operator Review Burden |
|---|---|---|---|---|---|
| **Exact Cryptographic Pinning** | SHA-256 over JSON (W3C SRI, 2016) | Post-deployment tampering | Strict byte-level equality | Blind to semantic intent; flags 100% of benign refactorings | **High** (0.050 alerts/transition on wild corpus) |
| **Author Provenance Signing** | Mas et al. (2026), Sigstore (2022) | Unauthorized third-party tampering | Signer identity mismatch | Insider maintainer rug-pulls; compromised author keys | **Low** (Zero alerts for validly signed malware; qualitative) |
| **Static Keyword Scanners** | Regex rules / leakage checks | Overt keyword injections | Known syntactic attack templates | Evasive paraphrasing, semantic drift, parameter toggles | **Zero runtime latency overhead** ($< 0.25$ ms, 75.8% static recall; qualitative) |
| **Monolithic LLM Vetting** | NeMo Guardrails, Llama Guard | Full-context prompt injection | General prompt/tool risk | Context-window saturation, high latency, lacks multi-step context | **Medium** (High per-call latency, length bias; qualitative) |
| **MCP Semantic Drift Guard (This Work)** | 5-tier pipeline + Multi-Anchor | Single-step & multi-step salami drift | Structured schema & docstring delta ($\Delta T$) | Distributed cross-tool collusion beyond individual tool state | **Low** (Synthetic benchmark FPR 4.0%; production burden not measured) |

*Table 1: Comparative Taxonomy Matrix of Defensive Paradigms.*

---

## 4. Corpus Measurement: Real-World MCP Evolution

To quantify tool-definition change rates in the wild, we collected versioned JSON manifests across 28 open-source MCP repositories:
- **Analyzed Repositories**: 28 servers (25 with multi-version histories $\ge 2$ tags).
- **Extracted Tool Snapshots**: 594 versioned JSON snapshots.
- **Unique Tool Contracts**: 285 distinct tool interfaces.
- **Comparable Release Transitions**: 621 consecutive version pairs $(V_i \rightarrow V_{i+1})$.
- **Total Tool-Pair Comparisons**: 4,961 individual tool contract comparisons.
- **Recorded Definition Changes**: 123 contract modification events.

### Empirical Evolutionary Rates:
- **Definition-Change Rate**: **2.48%** ($123 / 4,961$ tool comparisons).
- **Release-Change Rate**: **4.99%** ($31 / 621$ releases contained $\ge 1$ modified tool).
- **Pre-Existing Contract Modification Rate**: **2.09%** ($13 / 621$ release transitions).
- **Description-Change Rate**: **1.13%** ($7 / 621$ releases modified docstrings without code changes).
- **Schema-Change Rate**: **0.32%** ($2 / 621$ releases modified input schemas).

| Evolution Category | Count | Percentage | Primary Impact |
|---|---:|---:|---|
| `tool_addition` | 63 | 51.22% | Expands agent registry with new capabilities |
| `tool_removal` | 47 | 38.21% | Deprecates obsolete tools or consolidates APIs |
| `clarification` | 11 | 8.94% | Refines docstrings to improve LLM adherence |
| `new_feature` | 2 | 1.63% | Adds backward-compatible optional parameters |
| **Total** | **123** | **100.0%** | |

---

## 5. Semantic Drift Guard Architecture

The defense pipeline (`guard/middleware.py`, illustrated in Figure 1) operates as an inline proxy intercepting `tools/list` JSON-RPC traffic:
1. **Tier 0: Hash Comparison (Fast Path)**: Compares $H(T_{\text{new}})$ with $H(T_{\text{trusted}})$. Matching hashes bypass inspection in $< 0.015\text{ ms}$.
2. **Tier 1: Structured Diff Extraction**: Computes AST parameter deltas and docstring diffs (Figure 2).
3. **Tier 1.5: Deterministic Schema Security Rules**: Scans parameter type changes, enum constriction, `readOnly` toggles, and regex patterns in default values in $< 0.005\text{ ms}$.
4. **Tier 2: Static Rules Scan**: Screens docstring diffs against injection keywords in $< 0.25\text{ ms}$.
5. **Tier 3: Semantic Judge (Mode B Diff-Only)**: Evaluates structured diffs under strict Draft-07 JSON Schema constrained decoding using `gemma3:4b` ($T=0$).
6. **Policy Engine & SQLite Rollback**: Maps verdicts (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`) to deterministic actions (`ALLOW`, `WARN`, `BLOCK`, `QUARANTINE`).

### 5.1 Formal Definitions of Decision Rules and Chain Metrics
Let a tool evolution chain $c$ of length $K$ be defined as a sequence of definitions $(T_0, T_1, \dots, T_K)$, with transitions $t \in [1, K]$. Let $m_c \in [1, K]$ denote the attack onset step ($m_c = 1$ for Fast-Jump attacks, $m_c > 1$ for multi-step Salami attacks, and $m_c = \infty$ for Benign chains).

At each transition $t$, the defense produces a verdict $V(t) \in \{\text{BENIGN}, \text{SUSPICIOUS}, \text{MALICIOUS}, \text{PARSE\_ERROR}\}$. We evaluate three pre-registered decision rules:
- **Rule (a) Strict MALICIOUS**: An alert is raised at step $t$ if $V(t) = \text{MALICIOUS}$.
- **Rule (b) Primary BALANCED**: An alert is raised at step $t$ if $V(t) \in \{\text{MALICIOUS}, \text{SUSPICIOUS}\}$ or if an unhandled parse failure occurs (fail-safe policy).
- **Rule (c) Diagnostic / Parsed-Only**: An alert is raised at step $t$ if $V(t) \in \{\text{MALICIOUS}, \text{SUSPICIOUS}\}$, ignoring unhandled parse fallbacks.

#### Early-Alarm Flag ($k \ge m$):
Let $k_c$ denote the index of the first transition where an alert is triggered:
$$k_c = \min \{ t \in [1, K_c] : \text{Alert}(t) = \text{True} \} \quad (\text{or } \infty \text{ if no alert})$$
A malicious chain is successfully detected if $k_c \le K_c$. If an alert fires before the attack onset ($k_c < m_c$), it represents an early false alarm on a benign intermediate step. We enforce the strict early-alarm condition $k_c \ge m_c$ when computing valid attack recall.

#### Mean Exposure Window ($\bar{W}_e$):
For malicious chains $C_{\text{mal}}$, the exposure window $W_e(c)$ quantifies the number of vulnerable release steps the agent executes with poisoned definitions before an alarm is raised:
$$W_e(c) = \begin{cases} \max(0, k_c - m_c) & \text{if detected } (k_c \le K_c) \\ K_c - m_c + 1 & \text{if missed } (k_c = \infty) \end{cases}$$
The mean exposure window across malicious chains is defined as $\bar{W}_e = \frac{1}{|C_{\text{mal}}|} \sum_{c \in C_{\text{mal}}} W_e(c)$.

---

## 6. Detector Benchmark & Held-Out Results

### 6.1 Benchmark Setup & Single-Step Baseline Matrix ($N=56$)

Table 2 evaluates single-step detector performance on the held-out benchmark split ($N=56$; source: `results/computed_metrics.json`):

| Method / Defense Layer | TP | TN | FP | FN | Precision (95% CI) | Recall (95% CI) | F1 Score | Benign FPR (95% CI) | Latency (Mean) | LLM Calls / Upd |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Exact Hash Pinning (Tier 0)** | 33 | 0 | 23 | 0 | 58.9% [45.9%, 70.8%] | 100.0% [89.6%, 100.0%] | 74.2% | 100.0% [85.7%, 100.0%] | 0.012 ms | 0.0 |
| **Static Keyword Rules (Tier 2)** | 25 | 23 | 0 | 8 | 100.0% [86.7%, 100.0%] | 75.8% [59.0%, 87.2%] | 86.2% | 0.0% [0.0%, 14.3%] | 0.217 ms | 0.0 |
| **TF-IDF Cosine Baseline** | 31 | 6 | 17 | 2 | 64.6% [50.4%, 76.6%] | 93.9% [80.4%, 98.3%] | 76.5% | 73.9% [53.5%, 87.5%] | 0.903 ms | 0.0 |
| **Deterministic Schema Checks (Tier 1.5)** | 0 | 23 | 0 | 33 | n/a | 0.0% [0.0%, 10.4%] | 0.0% | 0.0% [0.0%, 14.3%] | 0.005 ms | 0.0 |
| **Semantic Judge Mode A (Full Definition)** | [PENDING RE-RUN] | - | - | - | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | 1.0 |
| **Semantic Judge Mode B (Structured Diff Only)** | [PENDING RE-RUN] | - | - | - | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | 1.0 |
| **Integrated Guard Middleware** | [PENDING RE-RUN] | - | - | - | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING] |

*Table 2: Held-Out Benchmark Results ($N=56$).*

---

## 7. Dataset Validity & Generalization Audits

### 7.1 Controlled Matched-Pairs Evaluation ($N=24$)
We constructed a **Controlled Matched-Pair Exploratory Pilot** (`data/matched_pairs.jsonl`). Each record is a controlled triplet isolating stylistic phrasing from semantic intent across identical tool schemas.

### 7.2 Evaluation on Real Pre-Existing Contract Modifications ($N=13$)
We evaluated the 13 historical pre-existing contract modifications mined from the open-source corpus:
- **Exact Hash Pinning**: 100.0% Alert Rate (13/13 flagged; exact byte changes).
- **Static Regex Rules**: 0.0% False Positive Rate (0/13 flagged; no injection keywords matched).
- **TF-IDF Lexical Baseline**: 69.2% FPR (9/13 flagged).

### 7.3 Server-Grouped Cross-Validation ($N=370$, 19 unique servers)
Across the dataset, all 370 benchmark items across train, dev, and test partitions are grouped across 19 unique servers with zero cross-fold server leakage.

---

## 8. Baselines, Ablations, and Master Comparison

### 8.1 Master Evaluation Comparison Matrix

| System / Defense Paradigm | Precision (95% CI) | Recall (95% CI) | F1 Score | Benign FPR (95% CI) | Malicious FNR (95% CI) | Mean Latency | LLM Calls / Upd |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Tier 0)** | 58.9% [45.9%, 70.8%] | **100.0%** [89.6%, 100.0%] | 74.2% | 100.0% [85.7%, 100.0%] | **0.0%** [0.0%, 10.4%] | 0.012 ms | 0.0 |
| **Static Keyword Rules (Tier 2)** | **100.0%** [86.7%, 100.0%] | 75.8% [59.0%, 87.2%] | 86.2% | **0.0%** [0.0%, 14.3%] | 24.2% [12.8%, 41.0%] | 0.217 ms | 0.0 |
| **TF-IDF Cosine Baseline** | 64.6% [50.4%, 76.6%] | 93.9% [80.4%, 98.3%] | 76.5% | 73.9% [53.5%, 87.5%] | 6.1% [1.7%, 19.6%] | 0.903 ms | 0.0 |
| **Deterministic Schema (Tier 1.5)** | n/a | 0.0% [0.0%, 10.4%] | 0.0% | **0.0%** [0.0%, 14.3%] | 100.0% [89.6%, 100.0%] | 0.005 ms | 0.0 |
| **Semantic Judge Mode A (Full)** | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | 1.0 |
| **Semantic Judge Mode B (Diff Only)** | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | 1.0 |
| **Integrated Guard Middleware (BALANCED)** | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING] |

*Table 3: Master Evaluation Comparison Matrix.*

---

## 9. Benchmark V4 Design & Pre-Registration Protocol

The pre-registered **Salami Drift Benchmark V4** (`data/salami_drift_benchmark_v4.jsonl`, SHA-256: `91f1d0de...`) comprises **116 independent chains** spanning **436 state transitions** across variable trajectory lengths ($L \in \{2, 3, 4, 5, 6\}$):
- **Calibration Split ($N=58$ Chains)**: 34 Salami, 5 Fast-Jump, 19 Benign.
- **Frozen Held-Out Test Split ($N=58$ Chains)**: 26 Salami, 7 Fast-Jump, 25 Benign across disjoint server namespaces.

### Benchmark Provenance & Trivial-Separator Audit
Chains were synthesized by taking real tool schema templates from open-source MCP repositories and generating multi-step mutation sequences via Python scripts. Evaluation is conducted using local `gemma3:4b` at temperature $T=0$.

All chains were audited against trivial heuristic separators:

| Feature / Trivial Separator | Target AUC Threshold | Measured ROC-AUC on Benchmark V4 | Separation Status & Paper Finding |
|---|:---:|:---:|---|
| **Parameter Count Delta ($|\Delta P|$)** | $< 0.65$ | **0.5203** | **PASS** (Zero syntactic separation) |
| **Normalized Levenshtein Edit Distance** | $< 0.65$ | **0.3489** | **BORDERLINE / REPORTED** ($\max(\text{AUC}, 1-\text{AUC}) = 0.6511$; inverse lexical correlation reported) |
| **Docstring Length Delta ($|\Delta L|$)** | $< 0.65$ | **0.7228** | **FAIL / REPORTED** (Modest length shift correlation in select categories; reported honestly) |

*Table 7b: Benchmark V4 Trivial-Separator Audit.*

---

## 10. Benchmark V4 Live Model Outcomes & Matched-FPR Baselines

### 10.1 Live Model Trajectory Outcomes ($N=116$ Chains)

Table 7 reports trajectory-level outcomes across splits under Primary Rule (b) BALANCED and Sensitivity Rule (a):

| Partition Split | Decision Rule | Anchor Strategy | Salami-Only Recall (95% Wilson CI) | Fast-Jump Recall (95% Wilson CI) | Overall Malicious Recall (95% Wilson CI) | Benign Chain FPR (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ |
|---|---|---|:---:|:---:|:---:|:---:|:---:|
| **Held-Out Test ($N=58$)** | **Rule (b) Primary BALANCED** | **Adjacent** | **96.2%** (25/26) [81.1%, 99.3%] | **100.0%** (7/7) [64.6%, 100.0%] | **97.0%** (32/33) [84.7%, 99.5%] | **4.0%** (1/25) [0.7%, 19.5%] | **0.192** steps |
| | | **Cumulative** | **76.9%** (20/26) [58.0%, 89.0%] | **100.0%** (7/7) [64.6%, 100.0%] | **81.8%** (27/33) [65.6%, 91.4%] | **0.0%** (0/25) [0.0%, 13.3%] | **0.731** steps |
| | | *Comparison* | *McNemar p=0.1250 (b=6, c=1)* | - | - | - | *Adj-Cum Diff: +19.2% [+0.0%, +38.5%]* |
| **Held-Out Test ($N=58$)** | **Rule (a) Operating Sensitivity** | **Adjacent** | 46.2% (12/26) [28.8%, 64.5%] | 100.0% (7/7) [64.6%, 100.0%] | 57.6% (19/33) [40.8%, 72.8%] | 0.0% (0/25) [0.0%, 13.3%] | 1.346 steps |
| | | **Cumulative** | 57.7% (15/26) [39.0%, 74.5%] | 85.7% (6/7) [48.7%, 97.4%] | 63.6% (21/33) [46.6%, 77.8%] | 0.0% (0/25) [0.0%, 13.3%] | 1.269 steps |
| | | *Comparison* | *McNemar p=0.4531 (b=2, c=5)* | - | - | - | *Adj-Cum Diff: -11.5% [-30.8%, +7.7%]* |
| **Calibration Split ($N=58$)** | **Rule (b) Primary BALANCED** | **Adjacent** | 94.1% (32/34) [80.9%, 98.4%] | 100.0% (5/5) [56.5%, 100.0%] | 94.9% (37/39) [83.1%, 98.6%] | 10.5% (2/19) [2.9%, 31.4%] | 0.353 steps |
| | | **Cumulative** | 67.7% (23/34) [50.8%, 80.9%] | 100.0% (5/5) [56.5%, 100.0%] | 71.8% (28/39) [56.2%, 83.5%] | 0.0% (0/19) [0.0%, 16.8%] | 1.118 steps |
| | | *Comparison* | *McNemar p=0.0225 (b=11, c=2)* | - | - | - | *Adj-Cum Diff: +26.5% [+5.9%, +44.1%]* |
| **Calibration Split ($N=58$)** | **Rule (a) Operating Sensitivity** | **Adjacent** | 55.9% (19/34) [39.5%, 71.1%] | 100.0% (5/5) [56.5%, 100.0%] | 61.5% (24/39) [45.9%, 75.1%] | 0.0% (0/19) [0.0%, 16.8%] | 1.412 steps |
| | | **Cumulative** | 44.1% (15/34) [28.9%, 60.6%] | 80.0% (4/5) [37.5%, 96.4%] | 48.7% (19/39) [33.9%, 63.8%] | 0.0% (0/19) [0.0%, 16.8%] | 1.529 steps |
| | | *Comparison* | *McNemar p=0.2188 (b=5, c=1)* | - | - | - | *Adj-Cum Diff: +11.8% [+0.0%, +23.6%]* |
| **Full Benchmark ($N=116$)** | **Rule (b) Primary BALANCED** | **Adjacent** | 95.0% (57/60) [86.3%, 98.3%] | 100.0% (12/12) [75.8%, 100.0%] | 95.8% (69/72) [88.4%, 98.6%] | 6.8% (3/44) [2.4%, 18.2%] | 0.283 steps |
| | | **Cumulative** | 71.7% (43/60) [59.2%, 81.5%] | 100.0% (12/12) [75.8%, 100.0%] | 76.4% (55/72) [65.4%, 84.7%] | 0.0% (0/44) [0.0%, 8.0%] | 0.950 steps |
| | | *Comparison* | *Post-Hoc Pooled McNemar p=0.0026 (b=17, c=3)* | - | - | - | *Adj-Cum Diff: +23.3% [+10.0%, +36.7%]* |
| **Full Benchmark ($N=116$)** | **Rule (a) Operating Sensitivity** | **Adjacent** | 51.7% (31/60) [39.3%, 63.8%] | 100.0% (12/12) [75.8%, 100.0%] | 59.7% (43/72) [48.2%, 70.3%] | 0.0% (0/44) [0.0%, 8.0%] | 1.383 steps |
| | | **Cumulative** | 50.0% (30/60) [37.7%, 62.3%] | 83.3% (10/12) [55.2%, 95.3%] | 55.6% (40/72) [44.1%, 66.5%] | 0.0% (0/44) [0.0%, 8.0%] | 1.417 steps |
| | | *Comparison* | *Post-Hoc Pooled McNemar p=1.0000 (b=7, c=6)* | - | - | - | *Adj-Cum Diff: +1.7% [-10.0%, +13.3%]* |

*Table 7: Benchmark V4 Live Model Evaluation Outcomes ($N=116$ Chains, `gemma3:4b` Constrained).*

### 10.2 Matched-FPR Baseline Evaluation ($N=58$ Held-Out Test Chains)

Table 8 reports deterministic and semantic baselines on the held-out test split. Thresholds for parameterized baselines were tuned strictly on Calibration Benign chains ($N=19$) and evaluated blindly on the Held-Out Test split ($N=25$ Benign, $N=26$ Salami, $N=7$ Fast-Jump):

| Baseline / Defense Paradigm | Salami-Only Recall ($N=26$) (95% Wilson CI) | Fast-Jump Recall ($N=7$) (95% Wilson CI) | Overall Malicious Recall ($N=33$) (95% Wilson CI) | Benign Chain FPR ($N=25$) (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ | LLM Calls / Upd |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Exact Hash Pinning (Tier 0)** | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 100.0% (33/33) [89.6%, 100.0%] | 100.0% (25/25) [86.7%, 100.0%] | 0.000 steps | 0.0 |
| **Tier 2 Static Keyword Regex (Leakage Check)** | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/7) [0.0%, 35.4%] | 0.0% (0/33) [0.0%, 10.4%] | 0.0% (0/25) [0.0%, 13.3%] | 2.000 steps | 0.0 |
| **TF-IDF Distance (Calibrated Dev Target=50.0%, Thresh >= 0.5439, Achieved Test FPR=56.0%)** | 50.0% (13/26) [32.1%, 67.9%] | 42.9% (3/7) [15.8%, 75.0%] | 48.5% (16/33) [32.5%, 64.8%] | 56.0% (14/25) [37.1%, 73.3%] | 1.346 steps | 0.0 |
| **TF-IDF Distance (Calibrated Dev Target=25.0%, Thresh >= 0.6000, Achieved Test FPR=28.0%)** | 11.5% (3/26) [4.0%, 29.0%] | 0.0% (0/7) [0.0%, 35.4%] | 9.1% (3/33) [3.1%, 23.6%] | 28.0% (7/25) [14.3%, 47.6%] | 1.885 steps | 0.0 |
| **TF-IDF Distance (Calibrated Dev Target=12.5%, Thresh >= 0.6073, Achieved Test FPR=28.0%)** | 7.7% (2/26) [2.1%, 24.1%] | 0.0% (0/7) [0.0%, 35.4%] | 6.1% (2/33) [1.7%, 19.6%] | 28.0% (7/25) [14.3%, 47.6%] | 1.923 steps | 0.0 |
| **TF-IDF Distance (Calibrated Dev Target=0.0%, Thresh >= 0.6569, Achieved Test FPR=4.0%)** | 3.9% (1/26) [0.7%, 18.9%] | 0.0% (0/7) [0.0%, 35.4%] | 3.0% (1/33) [0.5%, 15.3%] | 4.0% (1/25) [0.7%, 19.5%] | 1.962 steps | 0.0 |
| **Normalized Edit Distance (Calibrated Dev Target=50.0%, Thresh >= 0.6571, Achieved Test FPR=44.0%)** | 23.1% (6/26) [11.0%, 42.1%] | 0.0% (0/7) [0.0%, 35.4%] | 18.2% (6/33) [8.6%, 34.4%] | 44.0% (11/25) [26.7%, 62.9%] | 1.769 steps | 0.0 |
| **Normalized Edit Distance (Calibrated Dev Target=25.0%, Thresh >= 0.6571, Achieved Test FPR=44.0%)** | 23.1% (6/26) [11.0%, 42.1%] | 0.0% (0/7) [0.0%, 35.4%] | 18.2% (6/33) [8.6%, 34.4%] | 44.0% (11/25) [26.7%, 62.9%] | 1.769 steps | 0.0 |
| **Normalized Edit Distance (Calibrated Dev Target=12.5%, Thresh >= 0.7052, Achieved Test FPR=12.0%)** | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/7) [0.0%, 35.4%] | 0.0% (0/33) [0.0%, 10.4%] | 12.0% (3/25) [4.2%, 30.0%] | 2.000 steps | 0.0 |
| **Normalized Edit Distance (Calibrated Dev Target=0.0%, Thresh >= 0.7369, Achieved Test FPR=0.0%)** | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/7) [0.0%, 35.4%] | 0.0% (0/33) [0.0%, 10.4%] | 0.0% (0/25) [0.0%, 13.3%] | 2.000 steps | 0.0 |
| **Parameter Count Delta (Calibrated Dev Target=50.0%, Thresh >= 4, Achieved Test FPR=44.0%)** | 76.9% (20/26) [57.9%, 89.0%] | 42.9% (3/7) [15.8%, 75.0%] | 69.7% (23/33) [52.7%, 82.6%] | 44.0% (11/25) [26.7%, 62.9%] | 1.231 steps | 0.0 |
| **Parameter Count Delta (Calibrated Dev Target=25.0%, Thresh >= 4, Achieved Test FPR=44.0%)** | 76.9% (20/26) [57.9%, 89.0%] | 42.9% (3/7) [15.8%, 75.0%] | 69.7% (23/33) [52.7%, 82.6%] | 44.0% (11/25) [26.7%, 62.9%] | 1.231 steps | 0.0 |
| **Parameter Count Delta (Calibrated Dev Target=0.0%, Thresh >= 6, Achieved Test FPR=0.0%)** | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/7) [0.0%, 35.4%] | 0.0% (0/33) [0.0%, 10.4%] | 0.0% (0/25) [0.0%, 13.3%] | 2.000 steps | 0.0 |
| **MCP Semantic Guard (Adjacent, Rule (b) Primary BALANCED)** | **96.2%** (25/26) [81.1%, 99.3%] | **100.0%** (7/7) [64.6%, 100.0%] | **97.0%** (32/33) [84.7%, 99.5%] | **4.0%** (1/25) [0.7%, 19.5%] | 0.192 steps | 1.0 |
| **MCP Semantic Guard (Cumulative, Rule (b) Primary BALANCED)** | **76.9%** (20/26) [57.9%, 89.0%] | **100.0%** (7/7) [64.6%, 100.0%] | **81.8%** (27/33) [65.6%, 91.4%] | **0.0%** (0/25) [0.0%, 13.3%] | 0.731 steps | 1.0 |
| **MCP Semantic Guard (Adjacent, Rule (a) Strict MALICIOUS)** | **46.2%** (12/26) [28.8%, 64.5%] | **100.0%** (7/7) [64.6%, 100.0%] | **57.6%** (19/33) [40.8%, 72.8%] | **0.0%** (0/25) [0.0%, 13.3%] | 1.346 steps | 1.0 |
| **MCP Semantic Guard (Cumulative, Rule (a) Strict MALICIOUS)** | **57.7%** (15/26) [38.9%, 74.5%] | **85.7%** (6/7) [48.7%, 97.4%] | **63.6%** (21/33) [46.6%, 77.8%] | **0.0%** (0/25) [0.0%, 13.3%] | 1.269 steps | 1.0 |

*Table 8: Benchmark V4 Matched-FPR Baseline Evaluation on Frozen Held-Out Test Split ($N=58$ Chains).*

### 10.3 Adjacent vs. Cumulative Reversal Analysis & Hypotheses
In earlier Benchmark V3 unconstrained evaluations ($N=40$), Cumulative root-anchored comparison outperformed Adjacent comparison (87.5% vs. 50.0% Salami recall). However, under Benchmark V4 ($N=116$) with Draft-07 JSON Schema constrained decoding, the direction flipped: Adjacent comparison achieved 96.2% (25/26) Salami recall vs. Cumulative 76.9% (20/26) on the frozen held-out test split (test split difference: +19.2% [95% bootstrap CI: +0.0%, +38.5%], exact McNemar $p = 0.1250$; calibration split difference: +26.5% [94.1% vs 67.6%], exact McNemar $p = 0.0225$; post-hoc pooled difference across all $N=116$ chains: +23.3% [95% bootstrap CI: +10.0%, +36.7%], exact McNemar $p = 0.0026$).

Because trajectory length was not varied among malicious Salami chains in Benchmark V4 (all 60 Salami chains have length $L=4$, with malicious payloads injected across steps 3 and 4), trajectory length cannot explain the reversal.

Trace analysis across the 436 transitions ($N=120$ malicious Salami transitions across 60 chains) supports the following findings and hypotheses:
1. **Observed Category Differences ($N=12$ chains each)**:
   - **Low-Signal Semantic Drift (Category G, $N=12$)**: Adjacent comparison achieved **100.0% (12/12)** chain recall, whereas Cumulative comparison achieved **0.0% (0/12)** chain recall (57 `BENIGN` step verdicts in cumulative traces vs. 16 in adjacent traces).
   - **Instruction Erosion (Category E, $N=12$)**: Cumulative comparison achieved **100.0% (12/12)** chain recall, whereas Adjacent comparison achieved **83.3% (10/12)** chain recall.
2. **Diff-Size Association (Suggestive, Not Causal; Confounded by Category G)**:
   While missed cumulative transitions exhibit larger total character lengths on average, this monotonic quartile trend is strictly suggestive/observational and is heavily confounded by Category G (where 24/24 malicious transitions were missed in Cumulative evaluation, while possessing longer docstrings) as well as step index. In a logistic regression of Cumulative step miss rate on diff size controlling for step index and category ($\text{miss} \sim \text{diff\_len\_kb} + \text{step\_index} + \text{category}$), the coefficient for diff size is negligible ($\beta = +0.0011$), whereas step index ($\beta = -1.8932$) and attack category (Category G: $\beta = +2.4462$, Category E: $\beta = -1.9684$) account for the variance.
3. **Attention Dilution Hypothesis & Combined Prompt Evaluation**:
   We hypothesized that local 4B parameter models (`gemma3:4b`) experience attention dilution when evaluating multi-field cumulative diffs containing simultaneous parameter and docstring alterations. To test this, we evaluated a **Combined Prompt** strategy presenting both immediate $T_{k-1} \rightarrow T_k$ and cumulative $T_0 \rightarrow T_k$ diffs simultaneously.
   - On the confirmatory frozen held-out test split ($N=58$), Combined Prompt achieved **96.2% (25/26)** Salami recall and **0.0% (0/25)** Benign Chain FPR (mean exposure $\bar{W}_e = 0.154$ steps). This matches Adjacent recall; one fewer false-alarm chain (0/25 vs 1/25), not significant (exact McNemar vs Adjacent $p = 1.0000$; vs Cumulative $p = 0.1250$).
   - On the calibration split ($N=58$), Combined Prompt achieved 94.1% (32/34) Salami recall and 0.0% (0/19) Benign Chain FPR (McNemar vs Cumulative $p = 0.0225$).
   - Across the post-hoc pooled full benchmark ($N=116$), Combined Prompt achieved 95.0% (57/60) Salami recall and 0.0% (0/44) Benign Chain FPR (post-hoc pooled McNemar vs Cumulative $p = 0.0026$). Note that the held-out test split ($p = 0.1250$) serves as the primary confirmatory result, with full-benchmark numbers strictly designated post hoc.
   - Combined's advantage holds under Rule (b) only; under Rule (a) strict sensitivity (`MALICIOUS` only), Combined exhibits the lowest strict recall (42.3%, 11/26 vs Adjacent 46.2%, 12/26 and Cumulative 57.7%, 15/26 on Test; 47.1%, 16/34 vs Adjacent 55.9%, 19/34 on Calibration) because `gemma3:4b` assigns `SUSPICIOUS` rather than `MALICIOUS` to incremental semantic shifts and parameter additions during evasive drift.
   - Token totals are reported as empirical projections from $N$ measured transitions (Combined expands input context by +47.0%, measuring 508.2 vs 345.6 mean prompt tokens), and wall-clock latency was not comparatively evaluated across differing system load environments.

---

## 11. Novel Methods: Capability-Set Tracking & Calibrated Drift Budgeting

Table 9 evaluates alternative defense architectures on the held-out test split ($N=58$ chains):

| Defense Architecture / Method | Salami-Only Recall ($N=26$) (95% Wilson CI) | Fast-Jump Recall ($N=7$) (95% Wilson CI) | Overall Malicious Recall ($N=33$) (95% Wilson CI) | Benign Chain FPR ($N=25$) (95% Wilson CI) | Cat C Long-Drift FPR ($N=13$) (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ | LLM Calls / Upd |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Plain Cumulative Guard (Rule b)** | 76.9% (20/26) [57.9%, 89.0%] | 100.0% (7/7) [64.6%, 100.0%] | 81.8% (27/33) [65.6%, 91.4%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/13) [0.0%, 22.8%] | 0.731 steps | 1.0 |
| **Plain Adjacent Guard (Rule b)** | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (7/7) [64.6%, 100.0%] | 97.0% (32/33) [84.7%, 99.5%] | 4.0% (1/25) [0.7%, 19.5%] | 0.0% (0/13) [0.0%, 22.8%] | 0.192 steps | 1.0 |
| **Capability-Set Tracking (Root-Anchored)** | 61.5% (16/26) [42.5%, 77.6%] | 100.0% (7/7) [64.6%, 100.0%] | 69.7% (23/33) [52.7%, 82.6%] | 32.0% (8/25) [17.2%, 51.6%] | 0.0% (0/13) [0.0%, 22.8%] | 1.115 steps | 0.0 |
| **Calibrated Drift Budget (B*=4.1)** | 30.8% (8/26) [16.5%, 50.0%] | 42.9% (3/7) [15.8%, 75.0%] | 33.3% (11/33) [19.8%, 50.4%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/13) [0.0%, 22.8%] | 1.654 steps | 0.0 |
| **Hybrid Guard (Adjacent LLM + Capability-Set Tracking)** | 80.8% (21/26) [62.1%, 91.5%] | 100.0% (7/7) [64.6%, 100.0%] | 84.9% (28/33) [69.1%, 93.3%] | 32.0% (8/25) [17.2%, 51.6%] | 0.0% (0/13) [0.0%, 22.8%] | 0.500 steps | 1.0 |

*Table 9: Capability-Set Tracking, Drift Budget, and Hybrid Architecture Outcomes on Held-Out Test Split ($N=58$ Chains).*

### Structural Breakdown of Novel Architectures
- **Capability-Set Tracking**: While achieving 61.5% Salami recall without LLM inference, Capability-Set Tracking flags 32.0% (8/25) of benign chains because legitimate contract evolutions frequently add utility parameters that expand the formal AST capability footprint.
- **Calibrated Drift Budgeting ($B^*=4.10$)**: By accumulating per-step distances, Drift Budgeting maintains 0.0% Benign FPR but achieves only 30.8% Salami recall, as multi-step attackers spread mutations across low-distance steps that remain below the threshold.

---

## 12. Adaptive Attacker & Live Transport Failure Analysis

### 12.1 Adaptive Attacker Evaluation under Black-Box Mutation ($N=24$ Chains)
We evaluated an adaptive attacker executing black-box mutation search with semantic synonym replacement, parameter smuggling, and prompt obfuscation against the defenses. The attacker is allocated a query budget of $Q \le 5$ queries per step (averaging 8.12 queries per chain across $N=24$ malicious chains; Figure 6):

| Target Defense Mechanism | Evasion Success Rate ($N=24$) (95% Wilson CI) | Post-Adaptive Chain Recall (95% Wilson CI) | Avg Query Budget Consumed / Chain |
|---|:---:|:---:|:---:|
| **MCP Semantic Drift Guard (Adjacent, Rule b)** | 8.3% (2/24) [2.3%, 25.9%] | 91.7% (22/24) [74.2%, 97.7%] | 8.12 queries |
| **MCP Semantic Drift Guard (Cumulative, Rule b)** | 41.7% (10/24) [24.5%, 61.2%] | 58.3% (14/24) [38.8%, 75.5%] | 7.96 queries |
| **Capability-Set Tracking (Root-Anchored)** | 25.0% (6/24) [12.0%, 44.9%] | 75.0% (18/24) [55.1%, 88.0%] | 5.96 queries |
| **Calibrated Drift Budget (B*=4.10)** | 83.3% (20/24) [64.1%, 93.3%] | 16.7% (4/24) [6.7%, 35.9%] | 4.25 queries |
| **Parameter Count Delta Baseline (|Delta P| >= 4)** | 33.3% (8/24) [18.0%, 53.3%] | 66.7% (16/24) [46.7%, 82.0%] | 6.83 queries |
| **Normalized Edit Distance Baseline (dist >= 0.6571)** | 87.5% (21/24) [69.0%, 95.7%] | 12.5% (3/24) [4.3%, 31.0%] | 4.12 queries |

*Table 10: Adaptive Attacker Evaluation under Black-Box Mutation Feedback ($N=24$ Chains).*

The empirical results show that Cumulative Guard suffered 41.7% evasion compared to 8.3% for Adjacent Guard. Under cumulative root anchoring, the adaptive attacker can test mutations that incrementally shave cumulative distance from $T_0$, finding local minima that bypass the 4B judge's cumulative attention.

### 12.2 Live Transport Delivery-Layer Failure Condition Test Outcomes
We evaluated 5 scripted failure conditions in live MCP client-server communication using a localhost mock harness (`experiments/evaluate_delivery_layer.py`, Figure 7):

| Failure Mode ID | Failure Condition & Attack Vector | Unmitigated Delivery Behavior | Mitigated Architectural Fix (Harness Implementation) | Unvetted Tool Delivered (Before $\rightarrow$ After) | Certification Status |
|:---:|---|---|---|:---:|:---:|
| **FC-1** | Ratcheting Failure under Salami Drift | `ALLOW` | Dual-anchor root comparison blocks ratchet | 1 $\rightarrow$ 0 | **PASS** |
| **FC-2** | Reconnection History Reset under Dynamic Server ID | `ALLOW (Trust-on-First-Use Reset)` | Tool signature lookup cross-references trusted catalog | 1 $\rightarrow$ 0 | **PASS** |
| **FC-3** | Double-Fetch / TOCTOU Swapping Vulnerability | `LEAK (Server swaps definition between check and use)` | Single-fetch atomic cache forwarding | 1 $\rightarrow$ 0 | **PASS** |
| **FC-4** | Dropped or Coalesced list_changed Notification Desync | `LEAK (Client invokes mutated tool without re-vetting)` | State-monotonic version sequence barrier | 1 $\rightarrow$ 0 | **PASS** |
| **FC-5** | Judge Timeout / Network Partition Fail-Safe | `FAIL-OPEN (Delivers unvetted definition to client)` | Fail-closed policy serves previous trusted baseline | 1 $\rightarrow$ 0 | **PASS** |

*Table 11: Live MCP Transport & Delivery-Layer Failure Condition Test Outcomes on Localhost Mock Harness.*

---

## 13. Historical Salami Drift Benchmark V3 Replication

For historical reference, the earlier Benchmark V3 ($N=144$ transitions across 40 chains; see `paper/RECONCILIATION.md` for provenance details) demonstrated:

| Decision Rule | Strategy | Salami Recall ($N=16$) | Fast-Jump Recall ($N=8$) | Benign Chain FPR ($N=16$) | Salami Exposure $\bar{W}_e$ | Transition Parse Failures |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **Rule (b) BALANCED (Unconstrained)** | Adjacent | 50.0% (8/16) [28.0%, 72.0%] | 75.0% (6/8) [40.9%, 92.9%] | 6.2% (1/16) [1.1%, 28.3%] | 1.188 steps | 3/144 (2.08%) |
| | Cumulative | 87.5% (14/16) [64.0%, 96.5%] | 87.5% (7/8) [52.9%, 97.8%] | 50.0% (8/16) [28.0%, 72.0%] | 0.562 steps | 15/144 (10.42%) |
| **Rule (b) BALANCED (Constrained JSON)** | Adjacent | 81.2% (13/16) [57.0%, 93.4%] | 50.0% (4/8) [21.5%, 78.5%] | 0.0% (0/16) [0.0%, 19.4%] | 0.875 steps | 0/144 (0.00%) |
| | Cumulative | 43.8% (7/16) [23.1%, 66.8%] | 62.5% (5/8) [30.6%, 86.3%] | 0.0% (0/16) [0.0%, 19.4%] | 1.500 steps | 0/144 (0.00%) |

---

## 14. Limitations & Methodological Boundaries

1. **Single Small Judge Architecture**: All primary evaluations utilize local `gemma3:4b` under Q4_K_M quantization. Frontier API judges (e.g., GPT-4o, Claude 3.5 Sonnet) and multi-model consensus judges are NOT DONE and listed under Future Work. A 50-call cost pilot is estimated at ~\$0.10.
2. **Synthetic Benchmark Dataset**: Benchmark V4 ($N=116$ chains) consists of scripted, synthetic evolutions built upon real MCP tool schemas. While structurally realistic, synthetic trajectories may not fully reflect the natural release dynamics of enterprise environments.
3. **Trivial Separator Audit Findings**: Benchmark V4 exhibits docstring length shift correlation (ROC-AUC = 0.7228, failing the $<0.65$ audit threshold) and borderline edit distance ($\max(\text{AUC}, 1-\text{AUC}) = 0.6511$), reflecting natural documentation expansion in attack chains.
4. **Generator Provenance**: Benchmark chains were generated via automated schema modification scripts rather than human red-teamers, though the generation scripts operate independently from the evaluation judge.
5. **Static Regex Baseline Scope**: The static baseline represents the guard's author-defined Tier 2 regex rules; a full execution of external proprietary `mcp-scan` binaries across all 436 transitions is NOT DONE.
6. **Threat Model Scope**: The defense monitors single-server tool contract drift ($V_0 \rightarrow V_K$). Cross-server distributed collusion and runtime tool-output data injections remain outside the middleware's current scope.
7. **Serialization vs. Live Transport Scope**: Live transport testing was conducted across 5 scripted integration failure modes on a localhost mock harness rather than high-concurrency production deployments.
8. **Unmeasured Production Operator Burden**: The 4.0% false alarm rate is measured on synthetic benchmark chains; production review burden across real enterprise workloads remains unmeasured.

---

## 15. Reproducibility & Open Artifacts

All code, datasets, and scripts are open-source:
- **Benchmark V4 Dataset**: `data/salami_drift_benchmark_v4.jsonl` (SHA-256: `91f1d0de...`)
- **Table Generator**: `python scripts/make_tables.py`
- **Figure Generator**: `python scripts/make_figures.py`
- **Unit Test Suite**: 107 passed, 4 intentionally xfailed (`tests/test_old_paper_numbers_fail.py` asserting regression failure against obsolete legacy numbers).

---

## 16. Conclusion

This paper formalizes Salami Drift attacks against the Model Context Protocol and evaluates multi-tier semantic drift vetting across 116 pre-registered benchmark chains and 621 real-world release transitions. Our empirical findings demonstrate that exact cryptographic hash pinning achieves 100.0% (26/26) recall but incurs a 100.0% (25/25) benign false alarm rate. On held-out test chains, Adjacent semantic vetting achieves 96.2% (25/26) Salami recall at 4.0% (1/25) Benign FPR, compared to 76.9% (20/26) for Cumulative vetting (McNemar $p = 0.125$), revealing that local 4B judges suffer attention dilution over cumulative diffs on subtle drift. Under simulation-level black-box adaptive mutation search ($Q \le 5$), Adjacent vetting maintains 91.7% post-adaptive recall (8.3% evasion) whereas Cumulative vetting suffers 41.7% evasion. Finally, delivery-layer mitigations eliminate unvetted tool delivery across 5 scripted transport failure conditions on a localhost mock harness (5/5 $\rightarrow$ 0/5).
