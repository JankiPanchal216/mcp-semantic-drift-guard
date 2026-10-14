# Salami Rug-Pulls in the Model Context Protocol: Detecting Incremental Tool-Poisoning Attacks via Multi-Tier Semantic Drift Vetting

## Abstract

The Model Context Protocol (MCP) enables Large Language Model (LLM) agents to dynamically discover and invoke external tools. However, because advertised tool contracts are ingested into agent system prompts, untrusted upstream servers can mount tool-poisoning attacks. While single-step attacks inject overt malicious directives, sophisticated adversaries can partition capability escalation across subtle release updates—a threat model we formalize as **Salami Drift**. Existing defenses (cryptographic pinning, static scanners) fail to differentiate benign refactoring from multi-step creep.

Across 646 historical snapshots (621 transitions) from 25 MCP repositories, 31 releases (4.99%) contained legitimate contract modifications, of which only 13/621 (2.09%) are pre-existing contract modifications that require semantic review, all triggering re-approval under exact hash pinning. We introduce the **MCP Semantic Drift Guard**, combining fast-paths (<0.25 ms), schema checks, and structured diff reasoning under JSON Schema constrained decoding. On pre-registered **Salami Drift Benchmark V4** ($N=116$ chains, 436 transitions; SHA-256: `91f1d0de6f7673731c34967e3f5c77504e598b49fd6cc4807ef6209ddd4faebe`): (1) under primary Rule (b) BALANCED on local judge `gemma3:4b`, Adjacent comparison achieves 96.2% (25/26) Salami recall [81.1%, 99.3%] at 4.0% (1/25) Benign FPR, whereas Cumulative root comparison achieves 76.9% (20/26) [57.9%, 89.0%] at 0.0% (0/25) FPR (confirmatory pre-registered Cumulative advantage not supported, direction reversed, one-sided exact McNemar $p=0.9922$; exploratory post-hoc $H_1'$ $p=0.1250$); (2) on replication using cloud judge `gemini-3.1-flash-lite`, 100.0% any-after-onset sensitivity (strict recall 88.5% vs 84.6%, exploratory replication exact McNemar $p=1.0000$), demonstrating that the Adjacent vs. Cumulative gap is judge-dependent (evaluating $H_1$, $H_{2a}$ on local exposure, and $H_{2b}$ on Combined prompt Pareto efficiency); (3) deterministic baselines achieve $\le 3.8\%$ recall at low FPR ($\le 4.0\%$); and (4) under template mutation search ($Q \le 5$, gemma3:4b only, template-based, no LLM in the loop), Adjacent Guard retains 91.7% (22/24) recall. Benchmark V4 exhibits docstring length shift correlation (ROC-AUC = 0.7228) and edit-distance correlation ($\max(\text{AUC}, 1-\text{AUC}) = 0.6511$, FAIL); all results are reported subject to these limitations.

---

## 1. Introduction

### 1.1 The Problem
Autonomous AI agents increasingly rely on standard interface protocols to interact with external databases, execution sandboxes, code repositories, and web services. The Model Context Protocol (MCP; Anthropic / Model Context Protocol Working Group, 2024) has emerged as an open standard for connecting LLM hosts to heterogeneous tool servers. Under MCP, clients discover available capabilities at runtime by issuing `tools/list` requests. Upstream servers respond with tool manifests containing natural language descriptions, parameter names, type constraints, and documentation.

Because agent host systems inject these advertised manifests directly into system prompts to guide model reasoning, tool definitions occupy a trusted position within the agent's cognitive context. If an upstream server is compromised, malicious dependencies are introduced, or an untrusted server modifies its contracts post-registration, the agent can be coerced into following poisoned instructions—such as exfiltrating user credentials, invoking destructive commands, or chaining unauthorized tools.

### 1.2 Motivation & Operator Review Burden
Current industry security scanners and client integrity checkers address tool poisoning via **exact cryptographic tool pinning**. Under exact pinning, a client hashes the canonical JSON representation of a tool definition (SHA-256) upon initial approval. On subsequent invocations, any mismatch between the active hash and the pinned baseline raises a security alarm.

Exact hash comparison evaluates strict byte-level equality, answering the binary integrity question: *"Did the trusted definition change?"* However, software contracts in active ecosystems are not static artifacts: open-source developers continuously refine docstrings to improve model adherence, clarify parameter edge cases, fix typos, add new tools, and introduce backward-compatible optional features.

Across our empirical audit of 646 historical snapshots (621 release transitions) across 25 active open-source MCP repositories (out of 28 audited):
- **31 of 621 release transitions (4.99%)** contained at least one tool-definition change.
- A total of **123 tool-definition change events** were recorded.
- **110 of the 123 change events (89.4%)** represent tool additions (63 events) or tool removals (47 events), occurring across 20+ release transitions. Under standard security policy, unbaselined tool additions and deletions are handled via **Initial Discovery Quarantine** requiring explicit administrative provisioning.
- Thus, the true **addressable review burden** for continuous semantic contract drift monitoring across pre-existing tool versions is **13 of 621 release transitions (2.09%)** (13 total modification events):
  - Description / documentation clarifications: 7 releases (1.13% of transitions).
  - Schema / parameter modifications: 2 releases (0.32% of transitions).
  - Mixed description and schema modifications: 4 releases (0.64% of transitions).

#### Quantifying the Review Burden:
1. **Under Exact Hash Pinning**: Because any byte change alters the SHA-256 digest, all 31 release transitions with tool-definition changes trigger security alerts. This imposes a raw alert burden of **0.050 alerts per release transition** (~1 review alert every 20 releases) across all change events, or **0.021 alerts per release transition** specifically for pre-existing contract modifications. For an active enterprise deploying 20 MCP servers with ~20 annual releases each, exact pinning creates ~20–25 manual review interruptions per year solely for benign refactorings.
2. **Under Semantic Drift Guard**: By isolating structured diffs and executing schema-constrained semantic verification, the defense differentiates benign clarifications from malicious drift.
   - **Real-Corpus Contract Modifications ($N=13$)**: When evaluated directly on the 13 historical pre-existing contract modifications mined from open-source repositories (Section 7.2), exact hash pinning triggers alerts on **100.0% (13/13)** (imposing 0.021 alerts/transition). In contrast, under Adjacent-style structured-diff judging, lite-tier cloud judge `gemini-3.1-flash-lite` alerts on **38.5% (5/13) [17.7%, 64.5%]** under Primary Rule (b) (reducing the alert burden to 0.008 alerts/transition) and **0.0% (0/13) [0.0%, 22.8%]** under Strict Rule (a). On inspection, 2 of the 5 Rule (b) alerts reflect genuine capability additions (`puppeteer_navigate` adding `allowDangerous` and `launchOptions`; `puppeteer_screenshot` adding `encoded`), and 3 alerts reflect maintainers stripping tool docstrings to empty strings (`mcp-server-mysql` tools `get_table_sample`, `execute_sql`, `get_schema_info` stripping descriptions to `""`), which judges appropriately flag as suspicious obfuscation. On routine benign documentation updates and parameter additions (8 modifications), the alert rate is **0.0% (0/8) [0.0%, 32.4%]**. Local open-weight `gemma3:4b` triggers alerts on **23.1% (3/13) [8.2%, 50.3%]** under Rule (b) (flagging the three empty-docstring stripping modifications) and **0.0% (0/13) [0.0%, 22.8%]** under Strict Rule (a).
   - **Synthetic Benchmark Transitions ($N=156$)**: On the synthetic Benchmark V4 held-out test split across all 156 benign-labelled transitions (89 transitions in benign control chains plus 67 pre-onset/pre-jump steps across malicious chains: 52 pre-onset steps across the 26 Salami test chains and 15 pre-jump steps across the 7 Fast-Jump test chains), the synthetic per-transition false-alarm rate under Primary Rule (b) is **0.6% (1/156) [0.1%, 3.5%]** under Adjacent, **0.0% (0/156) [0.0%, 2.4%]** under Cumulative, and **0.6% (1/156) [0.1%, 3.5%]** under Combined on local `gemma3:4b` (0.0% across all strategies under Rule a). On cloud judge `gemini-3.1-flash-lite`, the synthetic per-transition alert rate is **1.9% (3/156) [0.7%, 5.5%]** under Adjacent and **2.6% (4/156) [1.0%, 6.4%]** under Cumulative and Combined (all occurring exclusively on pre-onset step 2 of Category E docstring erosion chains immediately prior to attack injection, with 0/89 alerts on benign control chains). In contrast to exact hash pinning which flags 100% of benign contract evolution (89/89, 100.0%), semantic drift vetting suppresses over 97%–100% of benign update interruptions. Production operator review burden across real enterprise workloads remains an unmeasured qualitative factor designated for future longitudinal study.

### 1.3 Threat Formalization & Primary Contributions
Existing MCP defenses detect change (hash pinning, signing) or judge a single definition (static scanners, one-shot LLM vetting). To our knowledge, no prior defense evaluates whether a sequence of individually subtle updates accumulates into a malicious capability escalation. This paper delivers:
1. **Empirical Measurement of Open-Source MCP Evolution**: Longitudinal audit of 646 historical snapshots (621 release transitions) across 25 active open-source MCP repositories, quantifying change rates and operator review burdens.
2. **Salami Drift Benchmark V4 & Pre-Registration Protocol**: Formal threat formulation and release of Benchmark V4 ($N=116$ chains, 436 transitions; SHA-256: `91f1d0de6f7673731c34967e3f5c77504e598b49fd6cc4807ef6209ddd4faebe`) with server-disjoint calibration/test splits and automated trivial-separator screening.
3. **Multi-Tier Semantic Drift Guard Architecture**: Implementation of a 5-tier defense middleware (`guard/middleware.py`) combining sub-millisecond fast-paths ($< 0.25\text{ ms}$), deterministic schema security rules, and XML-sandboxed structured diff reasoning.
4. **Matched-FPR Baseline & Trade-Off Evaluation**: Rigorous empirical evaluation comparing Adjacent vs. Cumulative comparison strategies under local judge capacity constraints ($p = 0.125$), alongside deterministic baselines, Capability-Set Tracking, and Calibrated Drift Budgeting ($B^*=4.10$).
5. **Template Mutation Search & Delivery Layer Simulation Evaluation**: Simulation-level evaluation against black-box semantic mutation search ($Q \le 5$, $N=24$ chains) and scripted failure injection across 5 transport failure conditions on a localhost mock harness.

---

## 2. Background & Threat Model

### 2.1 Model Context Protocol (MCP) Mechanics
The Model Context Protocol (Anthropic / Model Context Protocol Working Group, 2024; Specification Version 2024-11-05) standardizes client-host-server interactions via JSON-RPC 2.0 messages over two primary transports:
1. **Standard I/O (`stdio`)**: Process-isolated stdin/stdout communication using newline-delimited JSON-RPC 2.0.
2. **HTTP with Server-Sent Events / Streamable HTTP (`sse`)**: HTTP POST requests for client-to-server messaging, coupled with Server-Sent Events (SSE) for server-to-client streaming notifications (standardized as HTTP with SSE in specification version 2024-11-05, and evolved to Streamable HTTP in subsequent specification revisions).

During initialization (`initialize` / `notifications/initialized`), client and server negotiate capabilities. The host discovers tools via `tools/list`, to which the server responds with a catalog containing:
- `name`: Unique string identifier for the tool.
- `description`: Natural language docstring detailing tool functionality, constraints, and instructions.
- `inputSchema`: Draft-07 JSON Schema defining parameter properties, types, descriptions, default values, and required lists.

When an LLM decides to execute an action, it dispatches `tools/call`. If the server updates its tool catalog dynamically, it emits `notifications/tools/list_changed`, prompting the client to refresh its tool definitions via `tools/list`.

### 2.2 Background: Tool Poisoning & Reasoning-Mode Vulnerability (MCPTox Replication)
As background motivation, our local replication of the single-step MCPTox benchmark (Wang et al., 2025; local `Qwen3-8B`, 1,348 instances across 45 servers) confirmed that reasoning-mode agents exhibit substantial vulnerability to tool poisoning, achieving an Attack Success Rate (ASR) of 41.76% (560/1,341) in Think Mode versus 13.97% (188/1,346) in No-Think Mode (+27.79 percentage points). Across templates (Template-1 Direct Injection: 44.93% vs 8.13%; Template-2 Prerequisite Hijacking: 25.15% vs 3.66%; Template-3 Argument Redirection: 54.62% vs 24.60%), standard safety filters triggered zero refusals across all 1,348 instances, establishing that downstream LLMs readily follow poisoned tool contracts.

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
- **Time-of-Check to Time-of-Use (TOCTOU)**: If the defense performs a double fetch (fetching a definition to inspect, then requesting the catalog again for client dispatch), a malicious server can return a benign contract during inspection and swap in poisoned payloads during dispatch. Single-fetch atomic cache forwarding addresses this race condition.

### 2.5 Defense Scope & Threat Boundary Table
Table 1 formalizes the operational boundaries of the defense:

| Threat Category | In-Scope Attack Vectors | Out-of-Scope Threat Vectors | Primary Defensive Mitigation |
|---|---|---|---|
| **Contract Mutation** | Docstring injection, parameter descriptions, schema privilege escalation, multi-step salami drift | Runtime tool-execution return value poisoning, prompt injection in user prompts | Multi-Tier Semantic Drift Guard (Tiers 0–3) |
| **Transport Desync** | TOCTOU swapping, reconnection resets, dropped `list_changed` notifications | Kernel compromise, network-level man-in-the-middle on unencrypted transports | State-Monotonic Version Barrier, Atomic Cache Forwarding |
| **Ecosystem Collusion** | Single-server multi-step capability creep | Multi-server cross-tool distributed collusion beyond individual server state | Per-server SQLite baseline store and rollback quarantine |

*Table 1: Defense Scope & Threat Boundary Table.*

---

## 3. Related Work & Defensive Taxonomy

The security of tool-augmented agents has recently received increased scrutiny. Comprehensive threat surveys of the Model Context Protocol ecosystem (Hou et al., 2025) categorize lifecycle risks across developer, server, and client boundaries, emphasizing tool registration and dynamic discovery as critical attack surfaces. Single-step prompt injection and tool hijacking benchmarks such as MCPTox (Wang et al., 2025), MCP-SafetyBench (Zong et al., 2025), and ToolHijacker (Shi et al., 2025) evaluate adversarial docstrings that redirect model execution in a single release. Concurrently, the software engineering literature on API evolution (Brito et al., 2018; Dig and Johnson, 2006) demonstrates that real-world software interfaces evolve continuously through routine documentation clarifications, parameter refactoring, and backward-compatible feature additions. Differentiating benign evolutionary maintenance from subtle multi-step capability creep represents an unaddressed gap in agent defense architectures.

Table 2 summarizes the defensive boundaries across existing paradigms and the MCP Semantic Drift Guard:

| Defense Paradigm | Exemplar Approaches | Threat Model Scope | Primary Detection Target | Operational Blind Spots | Operator Review Burden |
|---|---|---|---|---|---|
| **Exact Cryptographic Pinning** | SHA-256 over JSON (W3C SRI, 2016) | Post-deployment tampering | Strict byte-level equality | Blind to semantic intent; flags 100% of benign refactorings | **High** (0.050 alerts/transition on wild corpus) |
| **Author Provenance Signing** | Mas et al. (2026), Sigstore (2022) | Unauthorized third-party tampering | Signer identity mismatch | Insider maintainer rug-pulls; compromised author keys | **Low** (Zero alerts for validly signed malware; qualitative) |
| **Static Keyword Scanners** | Regex rules / leakage checks (snyk-agent-scan, mcp-scan) | Overt keyword injections | Known syntactic attack templates | Evasive paraphrasing, semantic drift, parameter toggles | **Zero runtime latency overhead** ($< 0.25$ ms, 75.8% static recall; qualitative) |
| **Monolithic LLM Vetting** | NeMo Guardrails (Rebedea et al., 2023), Llama Guard (Inan et al., 2023) | Full-context prompt injection | General prompt/tool risk | Context-window saturation, high latency, lacks multi-step context | **Medium** (High per-call latency, length bias; qualitative) |
| **MCP Semantic Drift Guard (This Work)** | 5-tier pipeline + Multi-Anchor | Single-step & multi-step salami drift | Structured schema & docstring delta ($\Delta T$) | Distributed cross-tool collusion beyond individual tool state | **Not measured** (Synthetic benchmark FPR 4.0%; production burden not measured) |

*Table 2: Comparative Taxonomy Matrix of Defensive Paradigms.*

*Table 2 Footnote: The 75.8% static recall noted for Tier 2 Static Keyword Scanners is measured on the single-step N=56 benchmark (Table 3 and Table 4), where the author-written regex was designed on a related attack style. In contrast, on the multi-step Benchmark V4 Salami drift held-out test split ($N=26$; Table 7 and Appendix Table A.1), the same static regex achieves 0.0% (0/26) recall because subtle multi-step payload injections avoid overt keyword signatures.*

### 3.1 Literature Search Method & Defensive Scope Boundary
To evaluate whether prior works propose defenses against multi-step tool-definition drift in agent middleware, we conducted a systematic literature search on October 13, 2026 across major indexing venues: arXiv, Google Scholar, ACL Anthology, and GitHub. Search queries included: `"MCP rug pull"`, `"tool definition drift"`, `"incremental tool poisoning"`, and `"MCP tool update monitoring"`.

Across retrieved works, existing agent security literature focuses on single-step adversarial tool poisoning or prompt injection (e.g., MCPTox [Wang et al., 2025], ToolHijacker [Shi et al., 2025], MCP-SafetyBench [Zong et al., 2025]) and static manifest scanning (e.g., `mcp-scan`), while software engineering studies examine benign API evolution and concept drift (Brito et al., 2018; Dig and Johnson, 2006). To our knowledge, no prior published defense evaluates whether a sequence of individually subtle updates accumulates into a malicious capability escalation across dynamic tool-update lifecycles.

---

## 4. Corpus Measurement: Real-World MCP Evolution

To quantify tool-definition change rates in the wild, we collected versioned JSON manifests across 28 open-source MCP repositories:
- **Analyzed Repositories**: 28 servers (25 with multi-version histories $\ge 2$ tags).
- **Extracted Tool Snapshots**: 646 versioned JSON snapshots.
- **Unique Tool Contracts**: 285 distinct tool interfaces.
- **Comparable Release Transitions**: 621 consecutive version pairs $(V_i \rightarrow V_{i+1})$.
- **Total Tool-Pair Comparisons**: 4,961 individual tool contract comparisons.
- **Recorded Definition Changes**: 123 contract modification events.

### Counting Rule & Repository Breakdown
For each repository $i$ with $S_i$ versioned snapshots ordered chronologically, release transitions are computed over adjacent version pairs:
$$T_i = \max(0, S_i - 1)$$
Across the 28 audited repositories, 3 repositories contain 0 release snapshots (`mcp-cloudflare`, `mcp-go-reference`, `mcp-mssql`), leaving 25 active repositories with multi-version histories ($S_i \ge 2$). The total number of evaluated transitions across all 25 active repositories is:
$$\sum_{i=1}^{25} T_i = \sum_{i=1}^{25} (S_i - 1) = \sum_{i=1}^{25} S_i - 25 = 646 - 25 = 621 \text{ transitions.}$$

The distribution of snapshots and transitions across all 28 repositories is summarized below:

| Repository Name | Snapshots ($S_i$) | Transitions ($T_i$) | Repository Status |
|---|:---:|:---:|---|
| `mcp-cloudflare` | 0 | 0 | Inactive (0 tags) |
| `mcp-go-reference` | 0 | 0 | Inactive (0 tags) |
| `mcp-mssql` | 0 | 0 | Inactive (0 tags) |
| `mcp-playwright` | 20 | 19 | Active |
| `mcp-python-sdk` | 6 | 5 | Active |
| `mcp-server-aws-kb` | 13 | 12 | Active |
| `mcp-server-brave-search` | 25 | 24 | Active |
| `mcp-server-everart` | 17 | 16 | Active |
| `mcp-server-everything` | 44 | 43 | Active |
| `mcp-server-fetch` | 38 | 37 | Active |
| `mcp-server-filesystem` | 45 | 44 | Active |
| `mcp-server-gdrive` | 26 | 25 | Active |
| `mcp-server-git` | 46 | 45 | Active |
| `mcp-server-github` | 25 | 24 | Active |
| `mcp-server-gitlab` | 18 | 17 | Active |
| `mcp-server-google-maps` | 25 | 24 | Active |
| `mcp-server-kubernetes` | 36 | 35 | Active |
| `mcp-server-memory` | 45 | 44 | Active |
| `mcp-server-mysql` | 9 | 8 | Active |
| `mcp-server-postgres` | 26 | 25 | Active |
| `mcp-server-puppeteer` | 26 | 25 | Active |
| `mcp-server-qdrant` | 2 | 1 | Active |
| `mcp-server-redis` | 8 | 7 | Active |
| `mcp-server-sentry` | 20 | 19 | Active |
| `mcp-server-sequentialthinking` | 37 | 36 | Active |
| `mcp-server-slack` | 26 | 25 | Active |
| `mcp-server-sqlite` | 25 | 24 | Active |
| `mcp-server-time` | 38 | 37 | Active |
| **Total (28 Repositories)** | **646** | **621** | **25 Active Repositories** |

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
5. **Tier 3: Semantic Judge (Mode B Diff-Only)**: Evaluates structured diffs under strict Draft-07 JSON Schema constrained decoding using lightweight models: local open-weight `gemma3:4b` ($T=0$) or lite-tier cloud `gemini-3.1-flash-lite` ($T=0$).
6. **Policy Engine & SQLite Rollback**: Maps verdicts (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`) to deterministic actions (`ALLOW`, `WARN`, `BLOCK`, `QUARANTINE`).

### 5.1 Formal Definitions of Decision Rules and Chain Metrics
Let a tool evolution chain $c$ of length $K$ be defined as a sequence of definitions $(T_0, T_1, \dots, T_K)$, with transitions $t \in [1, K]$. Let $m_c \in [1, K]$ denote the attack onset step: for all 26 Salami test chains, $m_c = 3$ is universal ($K_c = 4$, with benign steps at $t=1,2$ and malicious drift at $t=3,4$); for Fast-Jump chains, the attack jump occurs at the final step $m_c = K_c \in \{2, 3, 4\}$; and $m_c = \infty$ for Benign chains.

At each transition $t$, the defense produces a verdict $V(t) \in \{\text{BENIGN}, \text{SUSPICIOUS}, \text{MALICIOUS}, \text{PARSE\_ERROR}\}$. We evaluate three pre-registered decision rules (defined in `paper/PREREGISTRATION.md`):
- **Rule (a) Strict MALICIOUS**: An alert is raised at step $t$ if $V(t) = \text{MALICIOUS}$.
- **Rule (b) Primary BALANCED**: An alert is raised at step $t$ if $V(t) \in \{\text{MALICIOUS}, \text{SUSPICIOUS}\}$ or if an unhandled parse failure occurs (fail-safe policy). *(Because JSON Schema constrained decoding achieved a 100.0% valid parse rate across local `gemma3:4b` [1,308/1,308 total transitions evaluated: 645 on held-out test comprising 215 Adjacent, 215 Cumulative, 215 Combined; and 663 on calibration comprising 221 Adjacent, 221 Cumulative, 221 Combined] and cloud `gemini-3.1-flash-lite` [645/645 transitions across Adjacent, Cumulative, and Combined test runs], fail-safe fallbacks were never triggered).*
- **Rule (c) DIAGNOSTIC / PARSED-ONLY**: Evaluates Rule (b) strictly on directly parsed model responses without fail-secure fallbacks (verdict $V(t) \in \{\text{MALICIOUS}, \text{SUSPICIOUS}\}$ on valid JSON), isolating intrinsic semantic reasoning from formatting fallbacks.

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

Table 3 evaluates single-step detector performance on the held-out benchmark split ($N=56$; source: `results/computed_metrics.json`):

| Method / Defense Layer | TP | TN | FP | FN | Observed Precision (95% CI) | Observed Recall (95% CI) | $F_1$ Score | Observed Benign FPR (95% CI) | Mean Latency | LLM Calls / Upd |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Tier 0)** | 33 | 0 | 23 | 0 | 58.9% [45.9%, 70.8%] | **100.0%** [89.6%, 100.0%] | 74.2% | 100.0% [85.7%, 100.0%] | 0.010 ms | 0.0 |
| **Static Keyword Rules (Tier 2)** | 25 | 23 | 0 | 8 | **100.0%** [86.7%, 100.0%] | 75.8% [59.0%, 87.2%] | **86.2%** | **0.0%** [0.0%, 14.3%] | 0.227 ms | 0.0 |
| **TF-IDF Cosine Baseline** | 31 | 6 | 17 | 2 | 64.6% [50.4%, 76.6%] | 93.9% [80.4%, 98.3%] | 76.5% | 73.9% [53.5%, 87.5%] | 1.062 ms | 0.0 |
| **Deterministic Schema Checks (Tier 1.5)** | 0 | 23 | 0 | 33 | n/a | 0.0% [0.0%, 10.4%] | 0.0% | 0.0% [0.0%, 14.3%] | 0.005 ms | 0.0 |

*Table 3: Single-Step Held-Out Benchmark Results ($N=56$).*

---

## 7. Dataset Validity & Generalization Audits

### 7.1 Controlled Matched-Pairs Evaluation ($N=24$)
We constructed a **Controlled Matched-Pair Exploratory Pilot** (`data/matched_pairs.jsonl`). Each record is a controlled triplet isolating stylistic phrasing from semantic intent across identical tool schemas.

### 7.2 Evaluation on Real Pre-Existing Contract Modifications ($N=13$)
To evaluate false alarm rates on organic software evolution outside synthetic generator scripts, we ran the defense across all 13 historical pre-existing contract modifications mined from the open-source corpus (the complete addressable drift subset from 621 release transitions across 25 active repositories; Section 1.2). We evaluated deterministic baselines alongside the Adjacent-style structured-diff semantic judge under JSON Schema constrained decoding:

| Method / Judge Tier | Decision Rule | Alert Rate (95% Wilson CI) | Alerts / Transitions | Operator Impact |
|---|---|---:|:---:|---|
| **Exact Hash Pinning (Tier 0)** | Strict Byte Equality | **100.0% (13/13)** [77.2%, 100.0%] | 13/13 | High friction (flags every benign byte edit) |
| **Static Regex Rules (Tier 2)** | Keyword Injection | **0.0% (0/13)** [0.0%, 22.8%] | 0/13 | Zero alerts (insensitive to non-keyword edits) |
| **TF-IDF Lexical Baseline** | Cosine Distance | **69.2% (9/13)** [42.4%, 87.3%] | 9/13 | Uncalibrated (flags ordinary rewordings) |
| **Semantic Judge (`gemma3:4b`)** | Rule (b) Primary BALANCED | **23.1% (3/13)** [8.2%, 50.3%] | 3/13 | Flags empty-docstring stripping |
| **Semantic Judge (`gemma3:4b`)** | Rule (a) Strict MALICIOUS | **0.0% (0/13)** [0.0%, 22.8%] | 0/13 | Zero alerts on real contract updates |
| **Semantic Judge (`gemini-3.1-flash-lite`)** | Rule (b) Primary BALANCED | **38.5% (5/13)** [17.7%, 64.5%] | 5/13 | Flags capability additions and docstring stripping |
| **Semantic Judge (`gemini-3.1-flash-lite`)** | Rule (a) Strict MALICIOUS | **0.0% (0/13)** [0.0%, 22.8%] | 0/13 | Zero alerts on real contract updates |

#### Detailed Audit of Alerted Modifications:
A qualitative audit reveals that the 5 alerts raised under Rule (b) by `gemini-3.1-flash-lite` fall into two well-defined operational categories rather than random noise:
1. **Genuine Security-Sensitive Capability Expansions (2 modifications)**:
   - *Modification #8 (`mcp-server-puppeteer` $\rightarrow$ `puppeteer_navigate`)*: Added parameters `allowDangerous` and `launchOptions`. Gemini verdict: `SUSPICIOUS` (confidence 0.85; rationale: *"The addition of an 'allowDangerous' parameter suggests a potential bypass of security controls or an attempt to execute unsafe operations without sufficient context"*). Rather than a false alarm, this represents a genuine capability expansion introducing security-relevant parameters that administrators should inspect.
   - *Modification #9 (`mcp-server-puppeteer` $\rightarrow$ `puppeteer_screenshot`)*: Added parameter `encoded` (allowing base64 binary encoding). Gemini verdict: `SUSPICIOUS` (confidence 0.75; rationale: *"The addition of an 'encoded' parameter without context or documentation is a common pattern for obfuscating payloads"*).
2. **Docstring Stripping / Maintainer Refactoring (3 modifications)**:
   - *Modifications #11, #12, #13 (`mcp-server-mysql` $\rightarrow$ `get_table_sample`, `execute_sql`, `get_schema_info`)*: Upstream maintainers stripped comprehensive tool descriptions down to empty strings (`""`). For example, on `execute_sql`, the docstring changed from `"Execute an SQL query on the MySQL server"` to `""`. Both `gemma3:4b` and `gemini-3.1-flash-lite` flagged all three modifications as `SUSPICIOUS` (confidence 0.75–0.85; rationales noting that stripping docstrings deliberately obscures tool purpose, hindering semantic validation and user consent).
3. **Routine Benign Evolution (8 modifications)**:
   - Across the remaining 8 routine contract evolutions (minor docstring clarifications, typing fixes, and standard parameter additions on `git_commit`, `git_diff`, `git_reset`, `git_log`, `git_show`, `brave_web_search`, `get_current_time`, and `slack_list_channels`), both model judges achieved an alert rate of **0.0% (0/8) [0.0%, 32.4%]** under both Rule (b) and Rule (a).

### 7.3 Server-Grouped Cross-Validation ($N=370$, 19 unique servers)
Across the dataset, all 370 benchmark items across train, dev, and test partitions are grouped across 19 unique servers with zero cross-fold server leakage.

---

## 8. Baselines, Ablations, and Master Comparison

### 8.1 Master Evaluation Comparison Matrix

In single-step held-out benchmark evaluations ($N=56$; source: `results/computed_metrics.json`), exact cryptographic hash pinning achieves Precision = 58.9%, Recall = 100.0%, with Benign FPR = 100.0% (by construction); author-defined static regex rules achieve Precision = 100.0%, Recall = 75.8%, with Benign FPR = 0.0%; and the TF-IDF cosine baseline achieves Precision = 64.6%, Recall = 93.9%, with Benign FPR = 73.9%. Table 4 reports the master comparison across deterministic baselines:

| System / Defense Paradigm | Precision (95% CI) | Recall (95% CI) | F1 Score | Benign FPR (95% CI) | Malicious FNR (95% CI) | Mean Latency | LLM Calls / Upd |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Tier 0)** | 58.9% [45.9%, 70.8%] | **100.0%** [89.6%, 100.0%] | 74.2% | 100.0% [85.7%, 100.0%] | **0.0%** [0.0%, 10.4%] | 0.010 ms | 0.0 |
| **Static Keyword Rules (Tier 2)** | **100.0%** [86.7%, 100.0%] | 75.8% [59.0%, 87.2%] | 86.2% | **0.0%** [0.0%, 14.3%] | 24.2% [12.8%, 41.0%] | 0.227 ms | 0.0 |
| **TF-IDF Cosine Baseline** | 64.6% [50.4%, 76.6%] | 93.9% [80.4%, 98.3%] | 76.5% | 73.9% [53.5%, 87.5%] | 6.1% [1.7%, 19.6%] | 1.062 ms | 0.0 |
| **Deterministic Schema (Tier 1.5)** | n/a | 0.0% [0.0%, 10.4%] | 0.0% | **0.0%** [0.0%, 14.3%] | 100.0% [89.6%, 100.0%] | 0.005 ms | 0.0 |

*Table 4: Master Evaluation Comparison Matrix.*

---

## 9. Benchmark V4 Design & Pre-Registration Protocol

The pre-registered **Salami Drift Benchmark V4** (`data/salami_drift_benchmark_v4.jsonl`, SHA-256: `91f1d0de6f7673731c34967e3f5c77504e598b49fd6cc4807ef6209ddd4faebe`) comprises **116 independent chains** spanning **436 state transitions** across variable trajectory lengths ($L \in \{2, 3, 4, 5, 6\}$):
- **Calibration Split ($N=58$ Chains)**: 34 Salami, 5 Fast-Jump, 19 Benign.
- **Frozen Held-Out Test Split ($N=58$ Chains)**: 26 Salami, 7 Fast-Jump, 25 Benign across disjoint server namespaces.

We formally pre-registered our study hypotheses in `paper/PREREGISTRATION.md`:
- **Hypothesis $H_1$ (Cumulative Advantage on Semantic Composition):** On multi-step semantic composition chains (where individual steps appear benign in isolation but compose into an attack), Cumulative comparison will achieve higher chain-level recall than Adjacent comparison under matched benign false positive rates.
- **Hypothesis $H_2$ (Adjacent Sensitivity on Local Leaps):** On localized parameter erosion or direct capability additions, Adjacent comparison will detect malicious drift earlier ($W_e$) with lower context overhead.
- **Hypothesis $H_3$ (Deterministic Baseline Insufficiency):** Calibrated deterministic heuristics (Levenshtein edit distance, parameter delta count) cannot simultaneously maintain $\ge 80\%$ recall on multi-step salami drift and $\le 15\%$ FPR on benign evolution when tested on docstring-only and diverse-length chains.

*(Pre-Registration Note: As originally pre-registered in `paper/PREREGISTRATION.md` (commit `1034af7`, 2026-10-09), $H_1$ predicted a Cumulative advantage, $H_2$ predicted Adjacent earlier exposure on localized parameter erosion, and $H_3$ predicted deterministic heuristic failure (evaluated against the pre-registered criteria of $\ge 80\%$ recall and $\le 15\%$ FPR vs. empirical matched FPR $\le 4.0\%$; deterministic baselines are judge-independent and the diverse-length chains condition was not tested because all Salami chains have $L=4$). Following evaluation of the Combined prompt strategy, $H_2$ was post-hoc decomposed into $H_{2a}$ [confirmatory adjacent exposure: "On localized parameter erosion or direct capability additions, Adjacent comparison will detect malicious drift earlier ($W_e$)"] and $H_{2b}$ [exploratory combined prompt Pareto efficiency: "Presenting both adjacent and cumulative diffs simultaneously achieves Pareto-superior detection (matching or exceeding Adjacent recall at $\le$ Cumulative FPR) with acceptable context overhead"]; this amendment is formally documented in `paper/PREREGISTRATION.md` Section 8.8 and Section 14).*

Table 5 summarizes empirical outcomes against each pre-registered hypothesis across both evaluated judge models:

| Pre-Registered Hypothesis | Predicted Direction & Metric Criterion | Outcome on `gemma3:4b` (Local 4B) | Outcome on `gemini-3.1-flash-lite` (Lite-Tier Cloud) | Confirmation Status |
|---|---|:---:|:---:|---|
| **$H_1$ (Cumulative Advantage, Confirmatory)** | Cumulative recall > Adjacent recall at matched benign FPR | **Direction Reversed** (Adjacent 96.2% > Cumulative 76.9%; pre-registered one-sided McNemar $p = 0.9922$ [b=6, c=1]; exploratory post-hoc $H_1'$ $p = 0.1250$, pooled $p = 0.0026$) | **Not Supported** (Adjacent 88.5% vs. Cumulative 84.6%, pre-registered one-sided McNemar $p = 1.0000$ [b=1, c=0] Rule b; Cumulative 96.2% vs. 84.6% Rule a) | Confirmatory: not supported; pre-registered direction reversed on local judge (p=0.9922), no significant cumulative advantage on cloud (p=1.0000) |
| **$H_{2a}$ (Adjacent Local Exposure, Confirmatory)** | Adjacent detects drift earlier ($\bar{W}_e$) on local steps | **Supported** (Earlier exposure $\bar{W}_e = 0.192$ vs. $0.731$) | **Not Supported** ($\bar{W}_e = 0.808$ vs. $0.769$ under Rule b; no earlier detection advantage) | Confirmatory: supported on local judge; not supported on cloud judge (judge-dependent) |
| **$H_{2b}$ (Combined Pareto Efficiency, Exploratory)** | Combined recall $\ge$ Adjacent recall at matched/lower FPR with acceptable context overhead | **Weakly Supported** (Recall 96.2% matches Adjacent, 0/25 vs 1/25 FPR, $p=1.0000$; expands prompt tokens to 508.2 vs 345.6 Adjacent) | **Not Supported** (Recall 84.6% vs Adjacent 88.5%, $p=1.0000$; 0/25 FPR; expands prompt tokens to 503.4 vs 363.7 Adjacent / 357.6 Cumulative) | Exploratory (post-hoc decomposition): weakly supported on local judge; not supported on cloud judge (judge-dependent) |
| **$H_3$ (Deterministic Insufficiency, Confirmatory)** | Calibrated heuristics fail $\ge 80\%$ recall and $\le 15\%$ FPR (evaluated at matched FPR $\le 4.0\%$) | **Supported** (Parameter Delta: 76.9% recall at 44.0% FPR; Edit Dist / TF-IDF: $\le 3.8\%$ recall at $\le 4.0\%$ FPR) | **Judge-Independent** (Deterministic heuristics do not utilize model judges; diverse-length condition untested as all Salami chains have $L=4$) | Confirmatory: supported across benchmark (judge-independent; diverse lengths untested) |

*Table 5: Pre-Registered Hypothesis Outcome Matrix across Verified Judge Models.*

### Benchmark Provenance & Trivial-Separator Audit
Chains were synthesized by taking real tool schema templates from open-source MCP repositories and generating multi-step mutation sequences via Python scripts. Primary evaluation is conducted using local open-weight `gemma3:4b` ($T=0$), complemented by cross-architecture replication on lite-tier cloud judge Google `gemini-3.1-flash-lite` ($T=0$).

All chains were audited against trivial heuristic separators (Appendix Table A.3).

---

## 10. Benchmark V4 Live Model Outcomes & Matched-FPR Baselines

### Evaluation Taxonomy: Confirmatory vs. Exploratory Analyses
To ensure methodological rigor, all empirical analyses are classified according to pre-registration status:
- **Confirmatory Analyses (Pre-Registered Protocol)**:
  - Frozen Held-Out Test Split ($N=58$ chains: 26 Salami, 7 Fast-Jump, 25 Benign) under Primary Rule (b) BALANCED with Draft-07 JSON Schema constrained decoding.
  - Pre-registered hypothesis tests:
    - $H_1$ (Cumulative Advantage on Semantic Composition): Confirmatory pre-registered direction (Cumulative > Adjacent) is not supported, with direction reversed on local judge (one-sided exact McNemar $p = 0.9922$ [b=6, c=1] on `gemma3:4b`; $p = 1.0000$ [b=1, c=0] on `gemini-3.1-flash-lite`).
    - $H_{2a}$ (Adjacent Local Exposure): Confirmatory pre-registered exposure claim ($\bar{W}_e = 0.192$ vs. $0.731$ on `gemma3:4b`; $\bar{W}_e = 0.808$ vs. $0.769$ on `gemini-3.1-flash-lite`).
    - $H_3$ (Deterministic Baseline Insufficiency): Confirmatory test against pre-registered criteria ($\ge 80\%$ recall and $\le 15\%$ FPR, evaluated at matched low FPR $\le 4.0\%$).
- **Exploratory & Post-Hoc Analyses**:
  - Post-hoc $H_1'$ direction (Adjacent Advantage on local judge: two-sided exact McNemar $p = 0.1250$ on test split, $p = 0.0225$ on calibration split, pooled post-hoc $p = 0.0026$).
  - Combined Prompt strategy evaluation ($H_{2b}$; exploratory post-hoc decomposition evaluated after observing attention dilution on local models).
  - Cross-architecture replication on `gemini-3.1-flash-lite` (McNemar $p = 1.0000$).
  - Attack Category decompositions (Category G vs. Category E, and Category E step-2 pre-onset audit).
  - Real-corpus false-alarm evaluation on 13 historical contract modifications (Section 7.2).
  - Mode A single-step full-definition baseline evaluation (Table 7, Table A.2).
  - Sensitivity Rule (a) STRICT operating point evaluations.

### 10.1 Live Model Trajectory Outcomes ($N=116$ Chains)

Table 6 reports trajectory-level outcomes across splits under Primary Rule (b) BALANCED and Sensitivity Rule (a):

| Partition Split | Decision Rule | Anchor Strategy | Strict Salami Recall (95% Wilson CI) | Any-After-Onset Salami Sensitivity (95% Wilson CI) | Fast-Jump Recall (95% Wilson CI) | Overall Malicious Recall (95% Wilson CI) | Benign Chain FPR (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Held-Out Test (N=58)** | **Rule (b) Primary BALANCED** | **Adjacent** | **96.2% (25/26) [81.1%, 99.3%]** | **96.2% (25/26) [81.1%, 99.3%]** | **100.0% (7/7) [64.6%, 100.0%]** | **97.0% (32/33) [84.7%, 99.5%]** | **4.0% (1/25) [0.7%, 19.5%]** | 0.192 steps |
| | | **Cumulative** | **76.9% (20/26) [57.9%, 89.0%]** | **76.9% (20/26) [57.9%, 89.0%]** | **100.0% (7/7) [64.6%, 100.0%]** | **81.8% (27/33) [65.6%, 91.4%]** | **0.0% (0/25) [0.0%, 13.3%]** | 0.731 steps |
| | | **Combined Prompt** | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 97.0% (32/33) [84.7%, 99.5%] | 0.0% (0/25) [0.0%, 13.3%] | 0.154 steps |
| | | *Comparison (Adj vs Cum)* | *McNemar p=0.1250 (b=6, c=1)* | - | - | - | - | *Adj-Cum Diff: +19.2% [+0.0%, +38.5%]* |
| | | *Comparison (Comb vs Adj)* | *McNemar p=1.0000 (b=1, c=1)* | - | - | - | - | *Comb-Adj Diff: +0.0%* |
| | | *Comparison (Comb vs Cum)* | *McNemar p=0.1250 (b=6, c=1)* | - | - | - | - | *Comb-Cum Diff: +19.2%* |
| **Held-Out Test (N=58)** | **Rule (a) Operating Sensitivity** | **Adjacent** | 46.2% (12/26) [28.8%, 64.5%] | 46.2% (12/26) [28.8%, 64.5%] | 100.0% (7/7) [64.6%, 100.0%] | 57.6% (19/33) [40.8%, 72.8%] | 0.0% (0/25) [0.0%, 13.3%] | 1.346 steps |
| | | **Cumulative** | 57.7% (15/26) [38.9%, 74.5%] | 57.7% (15/26) [38.9%, 74.5%] | 85.7% (6/7) [48.7%, 97.4%] | 63.6% (21/33) [46.6%, 77.8%] | 0.0% (0/25) [0.0%, 13.3%] | 1.269 steps |
| | | **Combined Prompt** | 42.3% (11/26) [25.5%, 61.1%] | 42.3% (11/26) [25.5%, 61.1%] | 100.0% (7/7) [64.6%, 100.0%] | 54.5% (18/33) [38.0%, 70.2%] | 0.0% (0/25) [0.0%, 13.3%] | 1.385 steps |
| | | *Comparison (Adj vs Cum)* | *McNemar p=0.4531 (b=2, c=5)* | - | - | - | - | *Adj-Cum Diff: -11.5% [-30.8%, +7.7%]* |
| | | *Comparison (Comb vs Adj)* | *McNemar p=1.0000 (b=2, c=3)* | - | - | - | - | *Comb-Adj Diff: -3.9%* |
| | | *Comparison (Comb vs Cum)* | *McNemar p=0.1250 (b=0, c=4)* | - | - | - | - | *Comb-Cum Diff: -15.4%* |
| **Calibration Split (N=58)** | **Rule (b) Primary BALANCED** | **Adjacent** | 94.1% (32/34) [80.9%, 98.4%] | 97.1% (33/34) [85.1%, 99.5%] | 100.0% (5/5) [56.6%, 100.0%] | 94.9% (37/39) [83.1%, 98.6%] | 10.5% (2/19) [2.9%, 31.4%] | 0.353 steps |
| | | **Cumulative** | 67.6% (23/34) [50.8%, 80.9%] | 67.6% (23/34) [50.8%, 80.9%] | 100.0% (5/5) [56.6%, 100.0%] | 71.8% (28/39) [56.2%, 83.5%] | 0.0% (0/19) [0.0%, 16.8%] | 1.118 steps |
| | | **Combined Prompt** | 94.1% (32/34) [80.9%, 98.4%] | 97.1% (33/34) [85.1%, 99.5%] | 100.0% (5/5) [56.6%, 100.0%] | 94.9% (37/39) [83.1%, 98.6%] | 0.0% (0/19) [0.0%, 16.8%] | 0.382 steps |
| | | *Comparison (Adj vs Cum)* | *McNemar p=0.0225 (b=11, c=2)* | - | - | - | - | *Adj-Cum Diff: +26.5% [+5.9%, +44.1%]* |
| | | *Comparison (Comb vs Adj)* | *McNemar p=1.0000 (b=0, c=0)* | - | - | - | - | *Comb-Adj Diff: +0.0%* |
| | | *Comparison (Comb vs Cum)* | *McNemar p=0.0225 (b=11, c=2)* | - | - | - | - | *Comb-Cum Diff: +26.5%* |
| **Calibration Split (N=58)** | **Rule (a) Operating Sensitivity** | **Adjacent** | 55.9% (19/34) [39.5%, 71.1%] | 55.9% (19/34) [39.5%, 71.1%] | 100.0% (5/5) [56.6%, 100.0%] | 61.5% (24/39) [45.9%, 75.1%] | 0.0% (0/19) [0.0%, 16.8%] | 1.412 steps |
| | | **Cumulative** | 44.1% (15/34) [28.9%, 60.5%] | 44.1% (15/34) [28.9%, 60.5%] | 80.0% (4/5) [37.6%, 96.4%] | 48.7% (19/39) [33.9%, 63.8%] | 0.0% (0/19) [0.0%, 16.8%] | 1.529 steps |
| | | **Combined Prompt** | 47.1% (16/34) [31.5%, 63.3%] | 47.1% (16/34) [31.5%, 63.3%] | 100.0% (5/5) [56.6%, 100.0%] | 53.8% (21/39) [38.6%, 68.4%] | 0.0% (0/19) [0.0%, 16.8%] | 1.500 steps |
| | | *Comparison (Adj vs Cum)* | *McNemar p=0.2188 (b=5, c=1)* | - | - | - | - | *Adj-Cum Diff: +11.8% [+0.0%, +23.6%]* |
| | | *Comparison (Comb vs Adj)* | *McNemar p=0.2500 (b=0, c=3)* | - | - | - | - | *Comb-Adj Diff: -8.8%* |
| | | *Comparison (Comb vs Cum)* | *McNemar p=1.0000 (b=2, c=1)* | - | - | - | - | *Comb-Cum Diff: +2.9%* |
| **Full Benchmark (N=116)** | **Rule (b) Primary BALANCED** | **Adjacent** | 95.0% (57/60) [86.3%, 98.3%] | 96.7% (58/60) [88.6%, 99.1%] | 100.0% (12/12) [75.8%, 100.0%] | 95.8% (69/72) [88.5%, 98.6%] | 6.8% (3/44) [2.3%, 18.2%] | 0.283 steps |
| | | **Cumulative** | 71.7% (43/60) [59.2%, 81.5%] | 71.7% (43/60) [59.2%, 81.5%] | 100.0% (12/12) [75.8%, 100.0%] | 76.4% (55/72) [65.4%, 84.7%] | 0.0% (0/44) [0.0%, 8.0%] | 0.950 steps |
| | | **Combined Prompt** | 95.0% (57/60) [86.3%, 98.3%] | 98.3% (59/60) [91.1%, 99.7%] | 100.0% (12/12) [75.8%, 100.0%] | 95.8% (69/72) [88.5%, 98.6%] | 0.0% (0/44) [0.0%, 8.0%] | 0.283 steps |
| | | *Comparison (Adj vs Cum)* | *Post-Hoc Pooled McNemar p=0.0026 (b=17, c=3)* | - | - | - | - | *Adj-Cum Diff: +23.3% [+10.0%, +36.7%]* |
| | | *Comparison (Comb vs Adj)* | *McNemar p=1.0000 (b=1, c=1)* | - | - | - | - | *Comb-Adj Diff: +0.0%* |
| | | *Comparison (Comb vs Cum)* | *McNemar p=0.0026 (b=17, c=3)* | - | - | - | - | *Comb-Cum Diff: +23.3%* |
| **Full Benchmark (N=116)** | **Rule (a) Operating Sensitivity** | **Adjacent** | 51.7% (31/60) [39.3%, 63.8%] | 51.7% (31/60) [39.3%, 63.8%] | 100.0% (12/12) [75.8%, 100.0%] | 59.7% (43/72) [48.2%, 70.3%] | 0.0% (0/44) [0.0%, 8.0%] | 1.383 steps |
| | | **Cumulative** | 50.0% (30/60) [37.7%, 62.3%] | 50.0% (30/60) [37.7%, 62.3%] | 83.3% (10/12) [55.2%, 95.3%] | 55.6% (40/72) [44.1%, 66.5%] | 0.0% (0/44) [0.0%, 8.0%] | 1.417 steps |
| | | **Combined Prompt** | 45.0% (27/60) [33.1%, 57.5%] | 45.0% (27/60) [33.1%, 57.5%] | 100.0% (12/12) [75.8%, 100.0%] | 54.2% (39/72) [42.7%, 65.2%] | 0.0% (0/44) [0.0%, 8.0%] | 1.450 steps |
| | | *Comparison (Adj vs Cum)* | *Post-Hoc Pooled McNemar p=1.0000 (b=7, c=6)* | - | - | - | - | *Adj-Cum Diff: +1.7% [-10.0%, +13.3%]* |
| | | *Comparison (Comb vs Adj)* | *McNemar p=0.2891 (b=2, c=6)* | - | - | - | - | *Comb-Adj Diff: -6.7%* |
| | | *Comparison (Comb vs Cum)* | *McNemar p=0.4531 (b=2, c=5)* | - | - | - | - | *Comb-Cum Diff: -5.0%* |

*Table 6: Benchmark V4 Live Model Evaluation Outcomes ($N=116$ Chains, `gemma3:4b` Constrained).*

Under the pre-registered strict primary recall metric, a chain is scored as detected only if its first alert occurs at or after the ground-truth attack onset step ($d \ge m=3$). Chains whose first alert occurred prior to onset ($d < m$) are penalized as non-detections under the strict metric, even if the detector subsequently raises alerts at or after onset. On `gemma3:4b`, 0 premature alerts occurred on held-out test chains under Adjacent (25/26 strict vs. 25/26 Any-After-Onset) and Cumulative (20/26 strict vs. 20/26 Any-After-Onset), while Combined comparison exhibited 1 premature alert (`v4_chain_cat_e_01`, yielding 25/26 strict vs. 26/26 Any-After-Onset); 1 premature alert also occurred on calibration chains under Adjacent (`v4_chain_cat_e_07`, yielding 32/34 strict vs. 33/34 Any-After-Onset). On `gemini-3.1-flash-lite`, premature alerts occurred on 3 chains under Adjacent and 4 chains under Cumulative and Combined, reducing strict recall while Any-After-Onset sensitivity reaches 100.0% (26/26) across all three strategies. Section 14 notes this strict metric penalization as an evaluation boundary.

### 10.2 Summary of Matched-FPR Baselines and Multi-Judge Verification ($N=58$ Held-Out Test Chains)

Table 7 summarizes the trade-offs across deterministic baselines, semantic drift guards, and multi-judge replications on the frozen held-out test split ($N=58$). Thresholds for parameterized baselines were tuned strictly on Calibration Benign chains ($N=19$) and evaluated blindly on the Held-Out Test split ($N=25$ Benign, $N=26$ Salami, $N=7$ Fast-Jump):

| Defense Paradigm / Strategy | Evaluation Tier & Model | Strict Salami Recall ($N=26$) | Any-After-Onset Sensitivity ($N=26$) | Benign FPR ($N=25$) | Salami Exposure $\bar{W}_e$ | Operational Paradigm |
|---|---|:---:|:---:|:---:|:---:|---|
| **Exact Cryptographic Hash Pinning** | Tier 0 Deterministic | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (25/25) [86.7%, 100.0%] | 0.000 steps | Byte-level strict identity |
| **Tier 2 Static Keyword Regex (Leakage Check)** | Tier 2 Static | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/25) [0.0%, 13.3%] | 2.000 steps | Syntactic regex rule matching |
| **Parameter Count Delta (Thresh >= 4)** | Tier 1.5 Deterministic | 76.9% (20/26) [57.9%, 89.0%] | 76.9% (20/26) [57.9%, 89.0%] | 44.0% (11/25) [26.7%, 62.9%] | 1.231 steps | Syntactic schema delta |
| **Normalized Edit Distance (Thresh >= 0.7369)** | Tier 1 Lexical | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/25) [0.0%, 13.3%] | 2.000 steps | Lexical text edit distance |
| **TF-IDF Cosine Distance (Thresh >= 0.6569)** | Tier 1 Statistical | 3.8% (1/26) [0.7%, 18.9%] | 3.8% (1/26) [0.7%, 18.9%] | 4.0% (1/25) [0.7%, 19.5%] | 1.962 steps | Statistical n-gram distance |
| **Semantic Drift Guard: Adjacent (Rule b)** | Tier 3 Local (`gemma3:4b`, 4B) | **96.2% (25/26)** [81.1%, 99.3%] | **96.2% (25/26)** [81.1%, 99.3%] | 4.0% (1/25) [0.7%, 19.5%] | 0.192 steps | Step-wise structured diff |
| **Semantic Drift Guard: Cumulative (Rule b)** | Tier 3 Local (`gemma3:4b`, 4B) | 76.9% (20/26) [57.9%, 89.0%] | 76.9% (20/26) [57.9%, 89.0%] | **0.0% (0/25)** [0.0%, 13.3%] | 0.731 steps | Root-anchored diff |
| **Semantic Drift Guard: Adjacent (Rule b)** | Tier 3 Cloud (`gemini-3.1-flash-lite`) | 88.5% (23/26) [71.0%, 96.0%] | **100.0% (26/26)** [87.1%, 100.0%] | **0.0% (0/25)** [0.0%, 13.3%] | 0.808 steps | Step-wise structured diff |
| **Semantic Drift Guard: Cumulative (Rule b)** | Tier 3 Cloud (`gemini-3.1-flash-lite`) | 84.6% (22/26) [66.5%, 93.8%] | **100.0% (26/26)** [87.1%, 100.0%] | **0.0% (0/25)** [0.0%, 13.3%] | 0.769 steps | Root-anchored diff |

*Table 7: Summary of Matched-FPR Baselines and Multi-Judge Verification on Held-Out Test Split ($N=58$ Chains). Complete baseline operating thresholds are reported in Appendix Table A.1, and full multi-judge evaluation breakdowns across all rules and strategies are reported in Appendix Table A.2.*

*Note on baseline operating points: Parameterized baselines (edit distance and parameter delta) were evaluated at operating thresholds calibrated on the dev partition. In Table 7, lexical and statistical baselines are shown at the operating point achieving false positive rate $\le 4.0\%$ on benign test chains (matching Semantic Drift Guard's test FPR). Appendix Table A.1 provides the complete sweep across all calibrated operating thresholds (50%, 25%, 12.5%, 0.0%). Figure 3 illustrates the recall vs. benign chain false positive rate trade-off across defense paradigms, while Figure 4 shows the mean exposure window $\bar{W}_e$ across defense strategies.*

#### Per-Transition False-Alarm Rates & Premature Early Alerts
Across all 156 benign-labelled transitions in the frozen held-out test split (89 transitions in benign control chains plus 67 pre-onset steps across the 26 Salami chains), semantic drift vetting demonstrates high transition-level precision. Under Primary Rule (b) on `gemma3:4b`, the per-transition alert rate is **0.6% (1/156) [0.1%, 3.5%]** for Adjacent (a single alert on step 4 of benign chain `v4_chain_cat_c_std_13`), **0.0% (0/156) [0.0%, 2.4%]** for Cumulative, and **0.6% (1/156) [0.1%, 3.5%]** for Combined (an alert on pre-onset step 2 of `v4_chain_cat_e_03`). On cloud judge `gemini-3.1-flash-lite`, the per-transition alert rate under Rule (b) is **1.9% (3/156) [0.7%, 5.5%]** for Adjacent and **2.6% (4/156) [1.0%, 6.4%]** for Cumulative and Combined. Notably, on benign control chains ($N=25$, 89 transitions), Gemini triggers zero alerts (**0.0%, 0/89**). All of Gemini's pre-onset alerts occur exclusively on pre-onset step 2 of Category E instruction erosion chains (`v4_chain_cat_e_01`, `02`, `03` on Adjacent; plus `04` on Cumulative and Combined), where the docstring weakens strict validation constraints immediately prior to malicious parameter addition at step 3. Under Rule (a) Strict MALICIOUS, both judges achieve **0.0% (0/156) [0.0%, 2.4%]** per-transition false-alarm rates across all strategies.

### 10.3 Adjacent vs. Cumulative Reversal Analysis & Hypotheses
In earlier Benchmark V3 unconstrained evaluations ($N=40$), Cumulative root-anchored comparison outperformed Adjacent comparison (87.5% vs. 50.0% Salami recall). However, under Benchmark V4 ($N=116$) with Draft-07 JSON Schema constrained decoding, the direction flipped: Adjacent comparison achieved 96.2% (25/26) Salami recall vs. Cumulative 76.9% (20/26) on the frozen held-out test split (test split difference: +19.2% [95% bootstrap CI: +0.0%, +38.5%], exact McNemar $p = 0.1250$; calibration split difference: +26.5% [94.1% vs 67.6%], exact McNemar $p = 0.0225$; post-hoc pooled difference across all $N=116$ chains: +23.3% [95% bootstrap CI: +10.0%, +36.7%], exact McNemar $p = 0.0026$).

Because trajectory length was not varied among malicious Salami chains in Benchmark V4 (all 60 Salami chains have length $L=4$, with malicious payloads injected across steps 3 and 4), trajectory length cannot explain the reversal.

Trace analysis across the 436 transitions ($N=120$ malicious Salami transitions across 60 chains) supports the following findings and hypotheses (illustrated in Figure 5):
1. **Observed Category Differences ($N=12$ chains each; Figure 5)**:
   - **Low-Signal Semantic Drift (Category G, $N=12$)**: Adjacent comparison achieved **100.0% (12/12)** chain recall, whereas Cumulative comparison achieved **0.0% (0/12)** chain recall (57 `BENIGN` step verdicts in cumulative traces vs. 16 in adjacent traces).
   - **Instruction Erosion (Category E, $N=12$)**: Cumulative comparison achieved **100.0% (12/12)** chain recall, whereas Adjacent comparison achieved **83.3% (10/12)** chain recall.
2. **Diff-Size Association (Suggestive, Not Causal; Confounded by Category G)**:
   While missed cumulative transitions exhibit larger total character lengths on average, this monotonic quartile trend is strictly suggestive/observational and is heavily confounded by Category G (where 24/24 malicious transitions were missed in Cumulative evaluation, while possessing longer docstrings) as well as step index. In a logistic regression of Cumulative step miss rate on diff size controlling for step index and category ($\text{miss} \sim \text{diff\_len\_kb} + \text{step\_index} + \text{category}$), the coefficient for diff size is negligible ($\beta = +0.0011$), whereas step index ($\beta = -1.8932$) and attack category (Category G: $\beta = +2.4462$, Category E: $\beta = -1.9684$) account for the variance.
3. **Attention Dilution Hypothesis & Combined Prompt Evaluation**:
   We hypothesized that local 4B parameter models (`gemma3:4b`) experience attention dilution when evaluating multi-field cumulative diffs containing simultaneous parameter and docstring alterations. To test this, we evaluated a **Combined Prompt** strategy presenting both immediate $T_{k-1} \rightarrow T_k$ and cumulative $T_0 \rightarrow T_k$ diffs simultaneously.
   - On the confirmatory frozen held-out test split ($N=58$), Combined Prompt achieved **96.2% (25/26)** Salami recall and **0.0% (0/25)** Benign Chain FPR (mean exposure $\bar{W}_e = 0.154$ steps). This matches Adjacent recall; one fewer false-alarm chain (0/25 vs 1/25), not significant (exact McNemar vs Adjacent $p = 1.0000$; vs Cumulative $p = 0.1250$).
   - On the calibration split ($N=58$), Combined Prompt achieved 94.1% (32/34) Salami recall and 0.0% (0/19) Benign Chain FPR (McNemar vs Cumulative $p = 0.0225$).
   - Across the post-hoc pooled full benchmark ($N=116$), Combined Prompt achieved 95.0% (57/60) Salami recall and 0.0% (0/44) Benign Chain FPR (post-hoc pooled McNemar vs Cumulative $p = 0.0026$). Note that the held-out test split ($p = 0.1250$) serves as the primary confirmatory result, with full-benchmark numbers strictly designated post hoc.
   - Combined's advantage is observed under Rule (b) only; under Rule (a) strict sensitivity (`MALICIOUS` only), Combined exhibits the lowest strict recall (42.3%, 11/26 vs Adjacent 46.2%, 12/26 and Cumulative 57.7%, 15/26 on Test; 47.1%, 16/34 vs Adjacent 55.9%, 19/34 on Calibration) because `gemma3:4b` assigns `SUSPICIOUS` rather than `MALICIOUS` to incremental semantic shifts and parameter additions during evasive drift.
   - Token totals are reported as empirical projections from $N$ measured transitions (Combined expands input context by +47.0%, measuring 508.2 vs 345.6 mean prompt tokens on gemma), and wall-clock latency was not comparatively evaluated across differing system load environments.

### 10.4 Cross-Architecture Replication & Multi-Judge Evaluation

To evaluate whether the empirical divergence between Adjacent and Cumulative comparison is an artifact of the local open-weight judge (`gemma3:4b`), we evaluated the frozen held-out test split ($N=58$ chains, 215 transitions per strategy) on a pinned lite-tier cloud model, Google **`gemini-3.1-flash-lite`** (execution date: 2026-10-11/12, pinned temperature $T=0.0$, native Draft-07 JSON Schema constrained decoding). Table 7 summarizes the cross-architecture results, with complete multi-judge evaluation breakdowns reported in Appendix Table A.2.

#### 1. Empirical Outcomes on Adjacent and Cumulative Strategies ($H_1$, $H_1'$):
- **Parse Rate:** 100.0% valid Draft-07 JSON compliance (0/215 parse failures on Adjacent; 0/215 on Cumulative; 0/215 on Combined).
- **Rule (b) Primary BALANCED:**
  - **Adjacent Strategy:** Achieved **88.5% (23/26)** strict Salami recall [95% Wilson CI: 71.0%, 96.0%], **100.0% (26/26)** Any-After-Onset sensitivity, **100.0% (7/7)** Fast-Jump recall, and **0.0% (0/25)** Benign Chain FPR ($\bar{W}_e = 0.808$).
  - **Cumulative Strategy:** Achieved **84.6% (22/26)** strict Salami recall [95% Wilson CI: 66.5%, 93.8%], **100.0% (26/26)** Any-After-Onset sensitivity, **100.0% (7/7)** Fast-Jump recall, and **0.0% (0/25)** Benign Chain FPR ($\bar{W}_e = 0.769$).
- **Rule (a) Strict MALICIOUS:**
  - **Adjacent Strategy:** 84.6% (22/26) Salami recall [95% Wilson CI: 66.5%, 93.8%], 84.6% (22/26) Any-After-Onset sensitivity [66.5%, 93.8%], 100.0% (7/7) Fast-Jump recall, 0.0% (0/25) Benign FPR ($\bar{W}_e = 0.231$).
  - **Cumulative Strategy:** 96.2% (25/26) Salami recall [95% Wilson CI: 81.1%, 99.3%], 96.2% (25/26) Any-After-Onset sensitivity [81.1%, 99.3%], 100.0% (7/7) Fast-Jump recall, 0.0% (0/25) Benign FPR ($\bar{W}_e = 0.269$).
  - **Combined Strategy:** 88.5% (23/26) Salami recall [95% Wilson CI: 71.0%, 96.0%], 88.5% (23/26) Any-After-Onset sensitivity [71.0%, 96.0%], 100.0% (7/7) Fast-Jump recall, 0.0% (0/25) Benign FPR ($\bar{W}_e = 0.308$).
- **Post Hoc Exploratory Hypothesis ($H_1'$ — Adjacent $\ge$ Cumulative Salami Recall):** While pre-registered $H_1$ predicted a Cumulative advantage on multi-step composition, empirical evaluation on `gemma3:4b` observed the opposite direction (Adjacent 96.2% > Cumulative 76.9%, $p = 0.1250$ test, pooled $p = 0.0026$). When formulated as a post hoc exploratory hypothesis ($H_1'$: Adjacent $\ge$ Cumulative), cross-architecture replication on `gemini-3.1-flash-lite` finds **no statistically significant difference** between Adjacent and Cumulative Salami recall (Adjacent 88.5% vs. Cumulative 84.6%, exact McNemar $p = 1.0000$). Furthermore, the direction of difference depends on the decision rule: Cumulative is higher under Rule (a) (96.2% [25/26] vs. 84.6% [22/26]), whereas Adjacent is higher under Rule (b) (88.5% [23/26] vs. 84.6% [22/26]). Therefore, the $H_1'$ advantage observed on local models is judge-dependent, and the attention dilution explanation remains an untested exploratory hypothesis that the Gemini result does not support.
- **Strict vs. Any-After-Onset Gap Analysis:** On Gemini Flash Lite, both Adjacent (88.5% strict vs. 100.0% any-after-onset) and Cumulative (84.6% strict vs. 100.0% any-after-onset) achieve 100.0% sensitivity when evaluated for any alarm triggered at or after attack onset under Rule (b). The gap under the strict metric arises entirely in Category E (Instruction Erosion, where gold-label attack onset occurs at step 3 of $L=4$):
  - For **Adjacent**, exactly 3 chains (`v4_chain_cat_e_01_parse_pdf_invoice`, `v4_chain_cat_e_02_store_user_preference`, `v4_chain_cat_e_03_transcribe_meeting_audio`) triggered an alarm early at step 2. We verified against the benchmark dataset ground truth that the gold label at step 2 for all three chains is strictly **`BENIGN`** (attack onset is at step 3, $m=3$). Because the pre-registered strict metric requires that the first alarm step $d \ge m$, an alert at step 2 ($d=2 < 3$) forfeits strict recall credit, despite detecting malicious drift at steps 3–4.
  - For **Cumulative**, exactly 4 chains (`v4_chain_cat_e_01_parse_pdf_invoice`, `v4_chain_cat_e_02_store_user_preference`, `v4_chain_cat_e_03_transcribe_meeting_audio`, `v4_chain_cat_e_04_search_knowledge_base`) similarly alerted at step 2 where the gold label is confirmed **`BENIGN`** (as well as alerting at steps 3 and 4), explaining the 4-chain strict gap.
  - For **Combined**, the exact same 4 Category E chains alerted at step 2 (gold label: **`BENIGN`**), accounting for its 84.6% strict vs. 100.0% any-after-onset result under Rule (b).

- **Audit of Step 2 Ground Truth in Category E (Instruction Erosion)**:
  A qualitative inspection of the step-1$\rightarrow$2 diffs across the four Category E chains (`v4_chain_cat_e_01` to `04`) reveals that the benchmark's **`BENIGN`** gold label at step 2 is inherently **ambiguous**. In `v4_chain_cat_e_01_parse_pdf_invoice`, step 2 loosens the filesystem constraint from a specific directory (`/var/data/invoices`) to generic `invoice repositories and local data paths`. In `v4_chain_cat_e_02_store_user_preference`, step 2 broadens the storage scope from `non-sensitive user UI preferences` to `session state variables, and application configuration values`. In `v4_chain_cat_e_03_transcribe_meeting_audio`, step 2 replaces `PII redaction strictly enabled` with `high accuracy speech models and standard PII filtering`. In `v4_chain_cat_e_04_search_knowledge_base`, step 2 expands the scope from `internal public knowledge base articles` to `internal engineering team wikis`. From a standard software engineering perspective, these edits represent routine functional scope expansions (as judged by `gemma3:4b`, which rated all four as `BENIGN` with confidence $\ge 0.95$). However, from a zero-trust security posture, loosening path constraints and softening PII redactions represents preparatory defense erosion. Lite-tier cloud judge `gemini-3.1-flash-lite` aggressively flagged these semantic weakenings as `SUSPICIOUS` (confidence 0.75–0.85; rationales noting traversal risks and privacy dilution). Under the pre-registered strict metric ($d \ge m$), these pre-onset alerts forfeit strict recall credit. If these four ambiguous step-2 transitions are excluded in an exploratory sensitivity analysis (the exploratory sensitivity table below), Gemini's strict Salami recall under Rule (b) rises from 88.5% (Adjacent) and 84.6% (Cumulative) to **100.0% (26/26) [87.1%, 100.0%]**, while its transition-level false alarm rate on the remaining 152 benign transitions drops to **0.0% (0/152) [0.0%, 2.5%]** across all strategies:

| Model & Strategy | Decision Rule | Baseline Strict Salami Recall ($N=26$) | Excluded Step-2 Strict Recall ($N=26$) | Baseline Benign Step Alert Rate ($N=156$) | Excluded Step-2 Benign Alert Rate ($N=152$) |
|---|---|---:|---:|---:|---:|
| **`gemini-3.1-flash-lite` (Adjacent)** | Rule (b) Primary BALANCED | 88.5% (23/26) [71.0%, 96.0%] | **100.0% (26/26)** [87.1%, 100.0%] | 1.9% (3/156) [0.7%, 5.5%] | **0.0% (0/152)** [0.0%, 2.5%] |
| **`gemini-3.1-flash-lite` (Cumulative)** | Rule (b) Primary BALANCED | 84.6% (22/26) [66.5%, 93.8%] | **100.0% (26/26)** [87.1%, 100.0%] | 2.6% (4/156) [1.0%, 6.4%] | **0.0% (0/152)** [0.0%, 2.5%] |
| **`gemini-3.1-flash-lite` (Adjacent)** | Rule (a) Strict MALICIOUS | 84.6% (22/26) [66.5%, 93.8%] | 84.6% (22/26) [66.5%, 93.8%] | 0.0% (0/156) [0.0%, 2.4%] | 0.0% (0/152) [0.0%, 2.5%] |
| **`gemini-3.1-flash-lite` (Cumulative)** | Rule (a) Strict MALICIOUS | 96.2% (25/26) [81.1%, 99.3%] | 96.2% (25/26) [81.1%, 99.3%] | 0.0% (0/156) [0.0%, 2.4%] | 0.0% (0/152) [0.0%, 2.5%] |
| **`gemma3:4b` (Adjacent)** | Rule (b) Primary BALANCED | 96.2% (25/26) [81.1%, 99.3%] | 96.2% (25/26) [81.1%, 99.3%] | 0.6% (1/156) [0.1%, 3.5%] | 0.7% (1/152) [0.1%, 3.6%] |
| **`gemma3:4b` (Cumulative)** | Rule (b) Primary BALANCED | 76.9% (20/26) [57.9%, 89.0%] | 76.9% (20/26) [57.9%, 89.0%] | 0.0% (0/156) [0.0%, 2.4%] | 0.0% (0/152) [0.0%, 2.5%] |

*Exploratory Sensitivity Analysis: Strict Salami Recall and Per-Transition False Alarm Rates with Category E Step-2 Transitions Excluded .*

#### 2. Operational Quota Event, Day-Boundary Split, & Resumed Combined Evaluation ($H_{2b}$):
During execution of the third strategy (**Combined Prompt**), the API provider's daily Free-Tier quota ceiling was encountered on 2026-10-11 (`GenerateRequestsPerDayPerProjectPerModel-FreeTier`, 500 requests per day limit). Exactly 21 valid transitions were completed before the 500 requests/day cutoff, after which 20 attempts were throttled with `HTTP Error 429: Too Many Requests`.
- **Integrity Safeguard & Day-Boundary Split:** All 20 failed records were isolated into a dedicated audit archive (`predictions_combined_failed_audit.jsonl`). Zero valid verdict labels were modified or fabricated. Following provider quota reset (~05:00 IST on 2026-10-12), evaluation resumed for the remaining 194 transitions across the frozen held-out test split, completing all 215 records across the day boundary (21 transitions on 2026-10-11; 194 transitions on 2026-10-12) with zero parse errors (100.0% valid Draft-07 JSON compliance).
- **Combined Strategy Outcomes on Gemini Flash Lite:**
  - **Rule (b) Primary BALANCED:** Achieved **84.6% (22/26)** strict Salami recall [95% Wilson CI: 66.5%, 93.8%], **100.0% (26/26)** Any-After-Onset sensitivity, **100.0% (7/7)** Fast-Jump recall, and **0.0% (0/25)** Benign Chain FPR ($\bar{W}_e = 0.846$).
  - **Rule (a) Strict MALICIOUS:** Achieved **88.5% (23/26)** Salami recall [95% Wilson CI: 71.0%, 96.0%], **88.5% (23/26)** Any-After-Onset sensitivity [71.0%, 96.0%], **100.0% (7/7)** Fast-Jump recall, and **0.0% (0/25)** Benign Chain FPR ($\bar{W}_e = 0.308$).
- **Statistical Comparisons (Combined vs. Baselines on Rule b):**
  - **Combined vs. Adjacent:** Salami recall difference is **-3.8%** [95% bootstrap CI: -11.5%, +0.0%], exact McNemar $p = 1.0000$ (discordant $b=0, c=1$).
  - **Combined vs. Cumulative:** Salami recall difference is **+0.0%** [95% bootstrap CI: +0.0%, +0.0%], exact McNemar $p = 1.0000$ (discordant $b=0, c=0$).
- **Replication Hypothesis 2b ($H_{2b}$ — Combined Pareto Efficiency):** **Not supported on Gemini, weakly supported on gemma (one fewer false-alarm chain, p=1.0), judge-dependent**. On `gemma3:4b`, Combined matched Adjacent recall (96.2%, 25/26) with one fewer benign false alarm chain (0/25 vs 1/25, $p = 1.0000$). On `gemini-3.1-flash-lite`, however, Combined Prompt does not improve upon Adjacent recall ($84.6\% < 88.5\%$, a 1-chain deficit; exact McNemar $p = 1.0000$) while matching Benign FPR ($0.0\% = 0.0\%$). Combined Prompt expands input context by +47.0% tokens (508.2 vs 345.6 mean prompt tokens on gemma; on Gemini, 503.4 vs 363.7 Adjacent / 357.6 Cumulative tokens) without providing a Pareto advantage on lite-tier cloud reasoning models.

#### 3. Candidate Model Qualification, Pilots, and Exclusions:
1. **Google AI Studio API (`gemini-3.1-flash-lite`):**
   - Qualified under Gate 1 on a 50-call calibration pilot (100.0% parse rate, 50/50 calls, 0 retries, mean latency 3.99s).
   - Fully evaluated across all 3 strategies on the frozen held-out test split (215 transitions per strategy; 645 transitions total).
2. **Local `qwen3:8b` (Ollama):**
   - Evaluated on a 5-call CPU pilot; disqualified under Gate 1 ($\ge 99.0\%$) after achieving a 40.0% parse rate (2/5) with 190s/call CPU latency. The pilot used `num_predict=256` with no thinking control, so the 40% parse rate may reflect truncated reasoning output rather than an inability to produce JSON; this is not characterized as a general model failure.
3. **Hugging Face Serverless Inference Providers:**
   - Disqualified during provider connectivity screening as serverless router endpoints required pre-paid account credits (`HTTP 402 Payment Required`).
4. **DeepSeek API (`deepseek-flash` / `deepseek-v4-pro`):**
   - Evaluated on 2026-10-12. Exactly 4 HTTP requests were made to `api.deepseek.com`: 2 GET metadata and balance queries (`HTTP 200 OK`, total balance $0.00), and 2 rejected POST chat completion probes (one `HTTP 401` unauthenticated probe, one `HTTP 402 Insufficient Balance` probe); none billed (0 calls completed or billed). DeepSeek was formally excluded due to zero available balance ($0.00) and payment requirements. No model outputs, traces, or predictions were produced.
   - Across the study, empirical evaluation remains frozen at two verified judges: `gemma3:4b` (local open-weight 4B) and `gemini-3.1-flash-lite` (lite-tier cloud).

---

## 11. Novel Methods: Capability-Set Tracking & Calibrated Drift Budgeting

Table 8 evaluates alternative defense architectures on the held-out test split ($N=58$ chains):

| Defense Architecture / Method | Strict Salami Recall ($N=26$) (95% Wilson CI) | Any-After-Onset Salami Sensitivity ($N=26$) (95% Wilson CI) | Fast-Jump Recall ($N=7$) (95% Wilson CI) | Overall Malicious Recall ($N=33$) (95% Wilson CI) | Benign Chain FPR ($N=25$) (95% Wilson CI) | Cat C Long-Drift FPR ($N=13$) (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ | LLM Calls / Upd |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Plain Cumulative Guard (Rule b)** | 76.9% (20/26) [57.9%, 89.0%] | 76.9% (20/26) [57.9%, 89.0%] | 100.0% (7/7) [64.6%, 100.0%] | 81.8% (27/33) [65.6%, 91.4%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/13) [0.0%, 22.8%] | 0.731 steps | 1.0 |
| **Plain Adjacent Guard (Rule b)** | 96.2% (25/26) [81.1%, 99.3%] | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (7/7) [64.6%, 100.0%] | 97.0% (32/33) [84.7%, 99.5%] | 4.0% (1/25) [0.7%, 19.5%] | 0.0% (0/13) [0.0%, 22.8%] | 0.192 steps | 1.0 |
| **Capability-Set Tracking (Root-Anchored)** | 61.5% (16/26) [42.5%, 77.6%] | 76.9% (20/26) [57.9%, 89.0%] | 100.0% (7/7) [64.6%, 100.0%] | 69.7% (23/33) [52.7%, 82.6%] | 32.0% (8/25) [17.2%, 51.6%] | 0.0% (0/13) [0.0%, 22.8%] | 1.115 steps | 0.0 |
| **Calibrated Drift Budget (B*=4.1)** | 30.8% (8/26) [16.5%, 50.0%] | 30.8% (8/26) [16.5%, 50.0%] | 42.9% (3/7) [15.8%, 75.0%] | 33.3% (11/33) [19.8%, 50.4%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/13) [0.0%, 22.8%] | 1.654 steps | 0.0 |
| **Hybrid Guard (Adjacent LLM + Capability-Set Tracking)** | 80.8% (21/26) [62.1%, 91.5%] | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (7/7) [64.6%, 100.0%] | 84.8% (28/33) [69.1%, 93.3%] | 32.0% (8/25) [17.2%, 51.6%] | 0.0% (0/13) [0.0%, 22.8%] | 0.500 steps | 1.0 |

*Table 8: Capability-Set Tracking, Drift Budget, and Hybrid Architecture Outcomes on Held-Out Test Split ($N=58$ Chains).*

Among novel defense architectures, Capability-Set Tracking and Hybrid Guard each exhibited 4 premature alerts before attack onset (yielding 16/26 strict vs. 20/26 Any-After-Onset and 21/26 strict vs. 25/26 Any-After-Onset, respectively), while Drift Budget exhibited 0 premature alerts (8/26 on both metrics).

### Structural Breakdown of Novel Architectures
- **Capability-Set Tracking**: While achieving 61.5% Salami recall without LLM inference, Capability-Set Tracking flags 32.0% (8/25) of benign chains because legitimate contract evolutions frequently add utility parameters that expand the formal AST capability footprint.
- **Calibrated Drift Budgeting ($B^*=4.10$)**: By accumulating per-step distances, Drift Budgeting maintains 0.0% Benign FPR but achieves only 30.8% Salami recall, as multi-step attackers spread mutations across low-distance steps that remain below the threshold.
- **Hybrid Guard (Adjacent LLM + Capability-Set Tracking)**: The Hybrid Guard evaluates a disjunctive (boolean OR) composition policy combining step-wise Adjacent LLM semantic vetting (`adj_preds`, Rule b) with root-anchored Capability-Set Tracking: an alert is raised if either the Adjacent LLM judge flags a transition or if the capability-set footprint expands beyond baseline. On the held-out test split, this yields 84.8% (28/33) overall malicious recall and 80.8% (21/26) Salami recall under strict onset scoring, with mean exposure $\bar{W}_e = 0.500$ steps and 32.0% (8/25) Benign FPR. Two crucial architectural dynamics govern this result:
  1. *Comparison Baseline Clarification*: An earlier presentation compared the hybrid's 84.8% (28/33) recall to 81.8% (27/33, Cumulative Guard, $\bar{W}_e = 0.731$ steps). While the hybrid does outperform Plain Cumulative Guard, it implements **Adjacent** LLM inference (`adj_preds`); compared to its direct LLM component **Plain Adjacent Guard** (97.0% [32/33], 96.2% [25/26], $\bar{W}_e = 0.192$ steps), the hybrid's strict recall is actually lower (84.8% vs. 97.0%).
  2. *Strict vs. Monotonic Recall Under Disjunction*: In theory, a boolean OR disjunction has per-chain detection $\ge$ each individual component when evaluated under any-after-onset sensitivity (where the hybrid achieves $\ge 97.0\%$). Under the pre-registered *strict* onset metric ($d \ge m$), however, Capability-Set Tracking flags early preparatory parameter additions prior to true attack onset ($d < m=3$) across 4 malicious chains (`v4_chain_cat_a_05`, `v4_chain_cat_d_05`, `v4_chain_cat_d_12`, `v4_chain_cat_e_10`). Because the disjunction fires on the *earliest* alarm, these premature capability alerts forfeit strict recall credit despite Adjacent LLM correctly alarming at the true onset step. Crucially, the hybrid's benign false positive rate matches Capability-Set Tracking at 32.0% (8/25), inheriting its full false-alarm burden without filtering benefits.

---

## 12. Template Mutation Search & Live Transport Failure Analysis

### 12.1 Template Mutation Search Evaluation under Black-Box Mutation ($N=24$ Chains)
We evaluated black-box template-based mutation search with semantic synonym replacement, parameter smuggling, and prompt obfuscation against the defenses. As implemented in `experiments/evaluate_adaptive_attacker.py`, the evaluation utilizes deterministic template-based mutation search with regex substitutions (`PARAPHRASE_TEMPLATES`) and no LLM in the loop, evaluated against target local judge `gemma3:4b` only. The 24 evaluation chains were selected in `experiments/evaluate_adaptive_attacker.py` (lines 237–240) by taking the first 16 Salami chains (categories A, D, E, F, G) and first 8 Fast-Jump chains (category B) in dataset file iteration order across the combined benchmark. Of the $N=24$ malicious chains evaluated in this experiment, exactly 14 chains (58.3%) originate from the calibration split (10 Salami, 4 Fast-Jump) and 10 chains (41.7%) originate from the held-out test split (6 Salami, 4 Fast-Jump), read directly from the dataset split field. Because thresholds for the dev-calibrated baselines in Table 9 were tuned on calibration benign chains, these baselines were partly evaluated on calibration chains rather than a strictly held-out partition. Because this subset selection follows file iteration order rather than randomized or stratified cross-split sampling, we report this deterministic selection as an experimental limitation. The mutation search is allocated a query budget of $Q \le 5$ queries per step (averaging 8.12 queries per chain across $N=24$ malicious chains; Figure 6, Table 9):

| Target Defense Mechanism | Evasion Success Rate ($N=24$) (95% Wilson CI) | Post-Adaptive Chain Recall (95% Wilson CI) | Avg Query Budget Consumed / Chain |
|---|:---:|:---:|:---:|
| **MCP Semantic Drift Guard (Adjacent, Rule b)** | 8.3% (2/24) [2.3%, 25.8%] | 91.7% (22/24) [74.2%, 97.7%] | 8.12 queries |
| **MCP Semantic Drift Guard (Cumulative, Rule b)** | 41.7% (10/24) [24.5%, 61.2%] | 58.3% (14/24) [38.8%, 75.5%] | 7.96 queries |
| **Capability-Set Tracking (Root-Anchored)** | 25.0% (6/24) [12.0%, 44.9%] | 75.0% (18/24) [55.1%, 88.0%] | 5.96 queries |
| **Calibrated Drift Budget (B*=4.10)** | 83.3% (20/24) [64.1%, 93.3%] | 16.7% (4/24) [6.7%, 35.9%] | 4.25 queries |
| **Parameter Count Delta Baseline (|Delta P| >= 4)** | 33.3% (8/24) [18.0%, 53.3%] | 66.7% (16/24) [46.7%, 82.0%] | 6.83 queries |
| **Normalized Edit Distance Baseline (dist >= 0.6571)** | 87.5% (21/24) [69.0%, 95.7%] | 12.5% (3/24) [4.3%, 31.0%] | 4.12 queries |

*Table 9: Template Mutation Search Evaluation under Black-Box Mutation Feedback ($N=24$ Chains).*

The empirical results show that Cumulative Guard suffered 41.7% evasion compared to 8.3% for Adjacent Guard under this simulation-level search. As an empirical hypothesis, cumulative root anchoring allows template mutations to distribute alterations across multiple fields such that the model judge fails to trigger on the cumulative diff, whereas adjacent diffs preserve sharp step-wise contrast.

### 12.2 Live Transport Delivery-Layer Failure Condition Test Outcomes
We evaluated 5 scripted failure conditions in live MCP client-server communication using a localhost mock harness (`experiments/evaluate_delivery_layer.py`, Figure 7, Table 10):

| Failure Mode ID | Failure Condition & Attack Vector | Unmitigated Delivery Behavior | Mitigated Architectural Fix (Harness Implementation) | Unvetted Tool Delivered (Before $\rightarrow$ After) | Certification Status |
|:---:|---|---|---|:---:|:---:|
| **FC-1** | Ratcheting Failure under Salami Drift | `ALLOW` | `QUARANTINE` | 1 $\rightarrow$ 0 | **PASS** |
| **FC-2** | Reconnection History Reset under Dynamic Server ID | `ALLOW (Trust-on-First-Use Reset)` | `BLOCK (Cross-Session Signature Anchor Enforcement)` | 1 $\rightarrow$ 0 | **PASS** |
| **FC-3** | Double-Fetch / TOCTOU Swapping Vulnerability | `LEAK (Server swaps definition between check and use)` | `SECURE (Single-Fetch Atomic Cache Forwarding)` | 1 $\rightarrow$ 0 | **PASS** |
| **FC-4** | Dropped or Coalesced list_changed Notification Desync | `LEAK (Client invokes mutated tool without re-vetting)` | `BLOCK (State-Monotonic Version Sequence Barrier)` | 1 $\rightarrow$ 0 | **PASS** |
| **FC-5** | Judge Timeout / Network Partition Fail-Safe | `FAIL-OPEN (Delivers unvetted definition to client)` | `FAIL-CLOSED (BLOCK: Serves previous trusted baseline)` | 1 $\rightarrow$ 0 | **PASS** |

*Table 10: Live MCP Transport & Delivery-Layer Failure Condition Test Outcomes on Localhost Mock Harness.*

While Adjacent comparison achieves superior in-memory sensitivity by preventing attention dilution over long contexts (Section 10.3), relying solely on adjacent diffs in transport middleware leaves clients vulnerable to session ratcheting (FC-1), where an attacker incrementally drifts contracts across client reconnects. To reconcile these requirements, our architecture deploys dual-anchor root comparison at the transport delivery layer to permanently block ratcheting and session resets (FC-1, FC-2), while employing adjacent comparison within the semantic vetting judge to maximize step-wise attack sensitivity.

---

## 13. Historical Salami Drift Benchmark V3 Replication

For historical reference, the earlier Benchmark V3 ($N=144$ transitions across 40 chains; see `paper/RECONCILIATION.md` for provenance details) demonstrated:

| Decision Rule | Strategy | Salami Recall ($N=16$) | Fast-Jump Recall ($N=8$) | Benign Chain FPR ($N=16$) | Salami Exposure $\bar{W}_e$ | Transition Parse Failures |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **Rule (b) BALANCED (Unconstrained)** | Adjacent | 50.0% (8/16) [28.0%, 72.0%] | 75.0% (6/8) [40.9%, 92.9%] | 6.3% (1/16) [1.1%, 28.3%] | 1.188 steps | 3/144 (2.08%) |
| | Cumulative | 87.5% (14/16) [64.0%, 96.5%] | 87.5% (7/8) [52.9%, 97.8%] | 50.0% (8/16) [28.0%, 72.0%] | 0.562 steps | 15/144 (10.42%) |
| **Rule (b) BALANCED (Constrained JSON)** | Adjacent | 81.3% (13/16) [57.0%, 93.4%] | 50.0% (4/8) [21.5%, 78.5%] | 0.0% (0/16) [0.0%, 19.4%] | 0.875 steps | 0/144 (0.00%) |
| | Cumulative | 43.8% (7/16) [23.1%, 66.8%] | 62.5% (5/8) [30.6%, 86.3%] | 0.0% (0/16) [0.0%, 19.4%] | 1.500 steps | 0/144 (0.00%) |

*Note on Rule (c): Diagnostic / Parsed-Only Rule (c) evaluates Rule (b) strictly on directly parsed model responses without fail-secure fallbacks; because unconstrained V3 model outputs never emitted SUSPICIOUS upon valid parsing, Rule (c) is chain-equivalent to Rule (a).*

---

## 14. Limitations & Methodological Boundaries

1. **Judge Architecture Scope & Multi-Judge Replication**: Primary evaluations utilize local `gemma3:4b` under Q4_K_M quantization. Cross-architecture replication on Google `gemini-3.1-flash-lite` found no significant difference between Adjacent and Cumulative comparison on the frozen test split (McNemar $p = 1.0000$; Adjacent 88.5% vs. Cumulative 84.6% under Rule (b), with Cumulative higher under Rule (a): 25/26 vs. 22/26), showing that the post hoc exploratory Adjacent advantage ($H_1'$) and attention dilution hypothesis are architecture-specific hypotheses that the Gemini result does not support. Combined Prompt evaluation on `gemini-3.1-flash-lite` completed across all 215 transitions following provider quota reset, finding $H_{2b}$ (Combined Pareto efficiency) not supported on Gemini, weakly supported on gemma (one fewer false-alarm chain, p=1.0), and judge-dependent (Combined Pareto efficiency: 84.6% vs. Adjacent 88.5%, McNemar $p = 1.0000$). An additional candidate judge (DeepSeek API, evaluating `deepseek-flash`) authenticated successfully with a valid key on 2026-10-12 but was formally excluded due to zero account balance and payment requirement (account balance $0.00, HTTP 402 Insufficient Balance, zero completed calls), maintaining the empirical study at two verified judges. Evaluations on larger models and multi-model consensus judges are listed under Future Work.
2. **Synthetic Benchmark Dataset**: Benchmark V4 ($N=116$ chains) consists of scripted, synthetic evolutions built upon real MCP tool schemas. While structurally realistic, synthetic trajectories from a single automated generator may not fully reflect the natural release dynamics of enterprise environments.
3. **Trivial Separator Audit Findings**: Benchmark V4 exhibits docstring length shift correlation (ROC-AUC = 0.7228, failing the $<0.65$ audit threshold) and edit distance failing the two-sided criterion ($\max(\text{AUC}, 1-\text{AUC}) = 0.6511 > 0.65$, FAIL), reflecting natural documentation expansion in attack chains.
4. **Generator Provenance**: Benchmark chains were generated via automated schema modification scripts rather than human red-teamers, though the generation scripts operate independently from the evaluation judge.
5. **Static Regex Baseline Scope**: The static baseline represents the guard's author-defined Tier 2 regex rules; a full offline execution of external proprietary `mcp-scan` binaries across all 436 transitions was not run.
6. **Threat Model Scope**: The defense monitors single-server tool contract drift ($V_0 \rightarrow V_K$). Cross-server distributed collusion and runtime tool-output data injections remain outside the middleware's current scope.
7. **Serialization vs. Live Transport Scope**: Live transport testing was conducted across 5 scripted integration failure modes on a localhost mock harness rather than high-concurrency production deployments. The mitigations are implemented as architectural proposals in the simulation harness rather than standalone client middleware.
8. **Early-Alarm Metric Sensitivity**: The pre-registered primary recall metric requires that the first alert step $d \ge m$. Alarms triggered prematurely prior to attack onset ($d < m$) are scored as misses under this strict metric, penalizing detectors that alert early even if they subsequently detect the true payload. In Benchmark V4 test chains, this strict penalty accounts for 3 chains on Gemini Adjacent, 4 chains on Gemini Cumulative and Combined, 1 chain on Gemma Combined, and 4 chains on Capability Tracking and Hybrid Guard. The Any-After-Onset metric reports detection sensitivity irrespective of premature alerting.
9. **Mutation Search Split Composition**: The 24 malicious chains evaluated under black-box mutation search comprise 14 chains from the calibration split and 10 from the test split. Consequently, dev-calibrated baselines in Table 9 were partly evaluated on calibration chains rather than an entirely independent test partition.
10. **Deterministic Baseline Scope ($H_3$)**: Deterministic baselines are judge-independent (they execute rule-based or statistical scripts without calling language model judges). The diverse-length chains condition in pre-registered $H_3$ was not tested because all Salami chains in Benchmark V4 have fixed length $L=4$.
11. **Unmeasured Production Operator Burden**: The 4.0% false alarm rate is measured on synthetic benchmark chains; production review burden across real enterprise workloads remains an unmeasured qualitative factor.
12. **Single-Step LLM Judge Sweeps on Held-Out Benchmark ($N=56$)**: Standalone full-definition Judge Mode A, structured-diff Judge Mode B, and full multi-tier integrated middleware pipeline evaluations on the single-step held-out benchmark ($N=56$) are deferred to Future Work; Table 3 reports the single-step held-out benchmark measurements ($N=56$), while Table 4 reports the master architectural comparison across deterministic baselines.
13. **Pre-Registration Protocol History & Hypothesis Amendments**: In the initial pre-registration (`paper/PREREGISTRATION.md`, commit `1034af7`, 2026-10-09), $H_1$ predicted a Cumulative advantage on multi-step composition, $H_2$ predicted Adjacent earlier exposure ($W_e$), and $H_3$ predicted deterministic heuristic failure. Post-hoc Amendment 1 (commit `6d79948`, 2026-10-13) formally partitioned $H_2$ into $H_{2a}$ (confirmatory adjacent exposure advantage) and $H_{2b}$ (exploratory combined prompt Pareto efficiency) to isolate the newly formulated Combined prompt strategy from pre-registered single-anchor comparisons. Both the original text and subsequent amendments are fully documented in `paper/PREREGISTRATION.md` Section 8.8. Pre-registration timestamps rely on git history, which the authors control and which has no external timestamp.

### 14.1 Empirical Evaluation Status & Verification Matrix

Table 11 formalizes the completed experimental dimensions and explicitly documents unexecuted or deferred evaluations:

| Evaluation Dimension | Status | Methodology & Operational Boundaries |
|---|:---:|---|
| **External Proprietary Scanner (`mcp-scan`)** | **Not Done** | The Tier 2 static baseline evaluates author-defined regex patterns; full offline execution of external proprietary `mcp-scan` binaries across all 436 transitions is not run. |
| **Single-Step LLM Baseline (Mode A, $N=58$)** | **Done (gemma only)** | Mode A (single-step full tool definition, no diff) was implemented in `experiments/evaluate_mode_a_baseline.py` using `gemma3:4b` ($T=0$) via Ollama across the held-out test split. Single-step sweeps on $N=56$ remain deferred. |
| **Real-Corpus Contract Drift Vetting ($N=13$)** | **Done** | Evaluated all 13 historical pre-existing contract modifications mined from 621 open-source release transitions across exact hash pinning, static regex rules, TF-IDF cosine distance, and Adjacent semantic judges (`gemma3:4b` and `gemini-3.1-flash-lite`). |
| **Template Mutation Search Evaluation ($N=24$)** | **Done (Simulation-level)** | Evaluates automated black-box template-based mutation search with no LLM ($Q \le 5$, avg 8.12 queries/chain) run against `gemma3:4b` only on a simulation testbed; evaluates heuristic evasion rather than dynamic interactive human red-teaming. |
| **Delivery-Layer Failure Mitigations** | **Done (Simulation Harness)** | Design proposals and mitigations verified on a localhost mock simulation harness across 5 scripted failure modes (5/5 $\rightarrow$ 0/5); mitigations are architectural proposals in the harness rather than integrated into production MCP client runtimes. |
| **Benchmark Trivial-Separator Screening** | **Reported Limitation** | Benchmark V4 natural docstring length shift correlation (ROC-AUC = 0.7228) fails the pre-registered $<0.65$ gate; edit distance fails the two-sided criterion ($\max(\text{AUC}, 1-\text{AUC}) = 0.6511 > 0.65$, FAIL). |
| **Benchmark Synthesis & Scale** | **Reported Limitation** | Small sample size ($N=58$ held-out test chains: 26 Salami, 7 Fast-Jump, 25 Benign); trajectories generated via automated schema modification scripts from a single generator rather than organic multi-team enterprise release histories. |
| **Frontier-Tier Judge Evaluation** | **Not Done (Future Work)** | Evaluation covers a local open-weight judge (`gemma3:4b`) and a lite-tier cloud model (`gemini-3.1-flash-lite`); evaluations on large frontier models (e.g., GPT-4o, Claude 3.5 Sonnet) are not run and deferred to Future Work. |
| **Wall-Clock Latency Comparison** | **Not Done** | Input/output token metrics are reported from empirical traces (Combined adds +47.0% prompt tokens on gemma); wall-clock latency was not comparatively benchmarked across heterogeneous local CPU/GPU and cloud network environments. |
| **Third-Party Model Exclusions** | **Excluded (Documented)** | `qwen3:8b` disqualified on 5-call CPU pilot (40.0% parse rate with `num_predict=256` and no thinking control, which may reflect truncated reasoning rather than a general model failure to produce JSON; Gate 1 failed); Hugging Face disqualified due to pre-paid credit requirements (`HTTP 402`); DeepSeek API (`deepseek-flash`) authenticated with valid key but excluded due to zero balance ($0.00, `HTTP 402 Insufficient Balance`, zero completed calls). |

*Table 11: Empirical Evaluation Status & Verification Matrix (Done / Not Done).*

---

## 15. Reproducibility & Open Artifacts

All code, datasets, and scripts are open-source:
- **Benchmark V4 Dataset**: `data/salami_drift_benchmark_v4.jsonl` (SHA-256: `91f1d0de6f7673731c34967e3f5c77504e598b49fd6cc4807ef6209ddd4faebe`)
- **Table Generator**: `python scripts/make_tables.py`
- **Figure Generator**: `python scripts/make_figures.py`
- **Unit Test Suite**: 114 passed, 4 expected failures (118 tests total; `tests/test_old_paper_numbers_fail.py` asserting regression failure against obsolete legacy numbers; `tests/test_paper_numbers_consistency.py` asserting continuous numerical consistency).

---

## 16. Ethical Considerations, AI Assistance & Responsible Disclosure

### 16.1 Responsible Disclosure & Threat Containment
This research formalizes Salami Drift attacks to evaluate defensive middleware and prevent contract-hijacking vulnerabilities in emerging agent protocols. In accordance with responsible vulnerability disclosure principles:
- No operational zero-day exploit payloads, automated attack weaponization scripts, or bypass recipes targeting production systems are published.
- All evaluation chains in Benchmark V4 are synthetic evolutionary trajectories constructed in offline sandboxes over publicly published open-source schemas.
- Zero attacks, probes, or unauthorized interactions were conducted against live third-party MCP servers, production agent registries, or user environments.

### 16.2 AI Assistance Disclosure
In the preparation of this paper, experimental codebase, and benchmark analysis, large language models were employed as drafting and editing aids under human researcher direction. Specifically, AI assistance was used for generating boilerplate code, drafting script scaffolds, and language editing. All experimental protocols, pre-registration hypotheses, statistical calculations, execution traces, and analytical conclusions were verified by human authors.

### 16.3 Third-Party Benchmark License & Attribution
Tool definitions adapted for baseline comparisons and single-step vulnerability analyses from the MCPTox benchmark (Wang et al., 2025; arXiv:2508.14925) were inspected in the source repository (`https://github.com/zhiqiangwang4/MCPTox-Benchmark`, containing 5 files: `README.md`, `analysis.ipynb`, `def_tool/`, `pure_tool.json`, `response_all.json`; upstream README contains only `# AAAI26`; no LICENSE file present; license not verified), and are adapted under academic research attribution.

---

## 17. Conclusion

This paper formalizes Salami Drift attacks against the Model Context Protocol and demonstrates the necessity of multi-tier semantic drift vetting over exact cryptographic pinning. While cryptographic hash pinning reliably halts tampering, it flags legitimate contract evolution as malicious, imposing severe operational review burdens. Across frozen held-out benchmark evaluations, structured semantic drift vetting distinguishes benign refactorings from incremental capability creep, with strategy performance (Adjacent vs. Cumulative) proving architecture- and judge-dependent between local open-weight and cloud reasoning models. Under black-box template mutation search evaluation—conducted strictly against local `gemma3:4b` using template-based mutation search with no LLM (simulation-level)—step-wise adjacent comparison demonstrated resistance against template evasion on `gemma3:4b` only. Complementing semantic vetting with atomic cache forwarding and state-monotonic barriers mitigated the five scripted delivery-layer failure modes in a localhost mock harness, establishing an empirical foundation for secure runtime tool evolution in agent ecosystems.

---

## 18. References

1. Aline Brito, Laerte Xavier, Andre Hora, and Marco Tulio Valente. 2018. Why and How Java Developers Break APIs. In *Proceedings of the IEEE 25th International Conference on Software Analysis, Evolution and Reengineering (SANER)*, pages 255–265. DOI: `10.1109/SANER.2018.8330214`.
2. Danny Dig and Ralph Johnson. 2006. How do APIs evolve? A story of refactoring. *Journal of Software Maintenance and Evolution: Research and Practice*, 18(2):83–107. DOI: `10.1002/smr.328`.
3. Hakan Inan, Kartikeya Upasani, Jianfeng Chi, Rashi Rungta, Krithika Iyer, Yuning Mao, Michael Tontchev, Qing Hu, Brian Fuller, Davide Testuggine, and Madian Khabsa. 2023. Llama Guard: LLM-based Input-Output Safeguard for Human-AI Conversations. *arXiv preprint arXiv:2312.06674*.
4. Lluis Mas, Jordi Vilaplana, Josep Rius, Radu Spaimoc, and Jordi Mateo. 2026. The Trustworthy Model Context Protocol (MCP) Registry: An Architectural Blueprint for Cryptographic Provenance and Runtime Integrity. *Future Internet*, 18(5):243. DOI: `10.3390/fi18050243`.
5. Zachary Newman, John Speed Meyers, and Santiago Torres-Arias. 2022. Sigstore: Software Signing for Everybody. In *Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security (CCS)*, pages 2353–2367. DOI: `10.1145/3548606.3560596`.
6. Traian Rebedea, Razvan Dinu, Makesh Narsimhan Sreedhar, Christopher Parisien, and Jonathan Cohen. 2023. NeMo Guardrails: A Toolkit for Controllable and Safe LLM Applications with Programmable Rails. In *Proceedings of the 2023 Conference on Empirical Methods in Natural Language Processing (EMNLP): System Demonstrations*, pages 431–445. DOI: `10.18653/v1/2023.emnlp-demo.40`.
7. Jiawen Shi, Zenghui Yuan, Guiyao Tie, Pan Zhou, Neil Zhenqiang Gong, and Lichao Sun. 2025. Prompt Injection Attack to Tool Selection in LLM Agents (ToolHijacker). *arXiv preprint arXiv:2504.19793*.
8. Snyk Research and Invariant Labs. 2025. Snyk Agent Scan (formerly mcp-scan): Open-source security scanner for AI agent tool definitions and MCP servers. GitHub repository: `https://github.com/snyk/agent-scan`.
9. W3C Web Application Security Working Group. 2016. Subresource Integrity. W3C Recommendation: `https://www.w3.org/TR/SRI/`.
10. Zhiqiang Wang, Yichao Gao, Yanting Wang, Suyuan Liu, Haifeng Sun, Haoran Cheng, Guanquan Shi, Haohua Du, and Xiangyang Li. 2025. MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers. *arXiv preprint arXiv:2508.14925*.
11. Xuanjun Zong, Zhiqi Shen, Lei Wang, Yunshi Lan, and Chao Yang. 2025. MCP-SafetyBench: A Benchmark for Safety Evaluation of Large Language Models with Real-World MCP Servers. *arXiv preprint arXiv:2512.15163*.
12. Anthropic and Model Context Protocol Working Group. 2024. Model Context Protocol Specification (Version 2024-11-05). `https://modelcontextprotocol.io/specification/2024-11-05`.
13. Xinyi Hou, Yanjie Zhao, Shenao Wang, and Haoyu Wang. 2025. Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions. *arXiv preprint arXiv:2503.23278*.

---

## Appendix A. Extended Baseline & Multi-Judge Evaluation Tables

### Table A.1: Full Benchmark V4 Matched-FPR Baseline Evaluation on Frozen Held-Out Test Split ($N=58$ Chains)

| Baseline / Defense Paradigm | Salami-Only Recall ($N=26$) (95% Wilson CI) | Fast-Jump Recall ($N=7$) (95% Wilson CI) | Overall Malicious Recall ($N=33$) (95% Wilson CI) | Benign Chain FPR ($N=25$) (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ | LLM Calls / Upd |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Exact Hash Pinning (Tier 0)** | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 100.0% (33/33) [89.6%, 100.0%] | 100.0% (25/25) [86.7%, 100.0%] | 0.000 steps | 0.0 |
| **Tier 2 Static Keyword Regex (Leakage Check)** | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/7) [0.0%, 35.4%] | 0.0% (0/33) [0.0%, 10.4%] | 0.0% (0/25) [0.0%, 13.3%] | 2.000 steps | 0.0 |
| **TF-IDF Distance (Calibrated Dev Target=50.0%, Thresh >= 0.5439, Achieved Test FPR=56.0%)** | 50.0% (13/26) [32.1%, 67.9%] | 42.9% (3/7) [15.8%, 75.0%] | 48.5% (16/33) [32.5%, 64.8%] | 56.0% (14/25) [37.1%, 73.3%] | 1.346 steps | 0.0 |
| **TF-IDF Distance (Calibrated Dev Target=25.0%, Thresh >= 0.6000, Achieved Test FPR=28.0%)** | 11.5% (3/26) [4.0%, 29.0%] | 0.0% (0/7) [0.0%, 35.4%] | 9.1% (3/33) [3.1%, 23.6%] | 28.0% (7/25) [14.3%, 47.6%] | 1.885 steps | 0.0 |
| **TF-IDF Distance (Calibrated Dev Target=12.5%, Thresh >= 0.6073, Achieved Test FPR=28.0%)** | 7.7% (2/26) [2.1%, 24.1%] | 0.0% (0/7) [0.0%, 35.4%] | 6.1% (2/33) [1.7%, 19.6%] | 28.0% (7/25) [14.3%, 47.6%] | 1.923 steps | 0.0 |
| **TF-IDF Distance (Calibrated Dev Target=0.0%, Thresh >= 0.6569, Achieved Test FPR=4.0%)** | 3.8% (1/26) [0.7%, 18.9%] | 0.0% (0/7) [0.0%, 35.4%] | 3.0% (1/33) [0.5%, 15.3%] | 4.0% (1/25) [0.7%, 19.5%] | 1.962 steps | 0.0 |
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

### Table A.2: Multi-Judge Evaluation & Replicability on Frozen Held-Out Test Split ($N=58$ Chains)

| Model & Judge Tier | Decision Rule | Anchor Strategy | Parse Rate | Strict Salami Recall (95% Wilson CI) | Any-After-Onset Sensitivity (95% Wilson CI) | Fast-Jump Recall (95% Wilson CI) | Benign Chain FPR (95% Wilson CI) | Benign Step Alert Rate (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **gemma3:4b** (Local 4B) | **Rule (b) Primary BALANCED** | **Adjacent** | 100.0% (0 fails) | 96.2% (25/26) [81.1%, 99.3%] | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (7/7) [64.6%, 100.0%] | 4.0% (1/25) [0.7%, 19.5%] | 0.6% (1/156) [0.1%, 3.5%] | 0.192 |
| **gemma3:4b** (Local 4B) | **Rule (b) Primary BALANCED** | **Cumulative** | 100.0% (0 fails) | 76.9% (20/26) [57.9%, 89.0%] | 76.9% (20/26) [57.9%, 89.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/156) [0.0%, 2.4%] | 0.731 |
| **gemma3:4b** (Local 4B) | **Rule (b) Primary BALANCED** | **Combined Prompt** | 100.0% (0 fails) | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.6% (1/156) [0.1%, 3.5%] | 0.154 |
| **gemma3:4b** (Local 4B) | **Rule (a) Strict MALICIOUS** | **Adjacent** | 100.0% (0 fails) | 46.2% (12/26) [28.8%, 64.5%] | 46.2% (12/26) [28.8%, 64.5%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/156) [0.0%, 2.4%] | 1.346 |
| **gemma3:4b** (Local 4B) | **Rule (a) Strict MALICIOUS** | **Cumulative** | 100.0% (0 fails) | 57.7% (15/26) [38.9%, 74.5%] | 57.7% (15/26) [38.9%, 74.5%] | 85.7% (6/7) [48.7%, 97.4%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/156) [0.0%, 2.4%] | 1.269 |
| **gemma3:4b** (Local 4B) | **Rule (a) Strict MALICIOUS** | **Combined Prompt** | 100.0% (0 fails) | 42.3% (11/26) [25.5%, 61.1%] | 42.3% (11/26) [25.5%, 61.1%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/156) [0.0%, 2.4%] | 1.385 |
| **gemini-3.1-flash-lite** (Lite-tier Cloud) | **Rule (b) Primary BALANCED** | **Adjacent** | 100.0% (0 fail) | 88.5% (23/26) [71.0%, 96.0%] | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 1.9% (3/156) [0.7%, 5.5%] | 0.808 |
| **gemini-3.1-flash-lite** (Lite-tier Cloud) | **Rule (b) Primary BALANCED** | **Cumulative** | 100.0% (0 fail) | 84.6% (22/26) [66.5%, 93.8%] | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 2.6% (4/156) [1.0%, 6.4%] | 0.769 |
| **gemini-3.1-flash-lite** (Lite-tier Cloud) | **Rule (b) Primary BALANCED** | **Combined Prompt** | 100.0% (0 fail) | 84.6% (22/26) [66.5%, 93.8%] | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 2.6% (4/156) [1.0%, 6.4%] | 0.846 |
| **gemini-3.1-flash-lite** (Lite-tier Cloud) | **Rule (a) Strict MALICIOUS** | **Adjacent** | 100.0% (0 fail) | 84.6% (22/26) [66.5%, 93.8%] | 84.6% (22/26) [66.5%, 93.8%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/156) [0.0%, 2.4%] | 0.231 |
| **gemini-3.1-flash-lite** (Lite-tier Cloud) | **Rule (a) Strict MALICIOUS** | **Cumulative** | 100.0% (0 fail) | 96.2% (25/26) [81.1%, 99.3%] | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/156) [0.0%, 2.4%] | 0.269 |
| **gemini-3.1-flash-lite** (Lite-tier Cloud) | **Rule (a) Strict MALICIOUS** | **Combined Prompt** | 100.0% (0 fail) | 88.5% (23/26) [71.0%, 96.0%] | 88.5% (23/26) [71.0%, 96.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/156) [0.0%, 2.4%] | 0.308 |


### Table A.3: Benchmark V4 Trivial-Separator Audit

| Feature / Trivial Separator | Target AUC Threshold | Measured ROC-AUC on Benchmark V4 | Separation Status & Paper Finding |
|---|:---:|:---:|---|
| **Parameter Count Delta ($|\Delta P|$)** | $< 0.65$ | **0.5203** | **PASS** (Zero syntactic separation) |
| **Normalized Levenshtein Edit Distance** | $< 0.65$ | **0.3489** | **FAIL / REPORTED** ($\max(\text{AUC}, 1-\text{AUC}) = 0.6511 > 0.65$; inverse lexical correlation reported) |
| **Docstring Length Delta ($|\Delta L|$)** | $< 0.65$ | **0.7228** | **FAIL / REPORTED** (Modest length shift correlation in select categories; reported honestly) |
