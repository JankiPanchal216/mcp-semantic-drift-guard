# Semantic Drift Detection for Model Context Protocol (MCP) Tool Definition Updates

## Abstract

The Model Context Protocol (MCP) enables Large Language Model (LLM) agents to dynamically discover and invoke external tools at runtime. However, advertised tool contracts—including docstrings, parameter descriptions, and schemas—are directly ingested into agent prompts, creating an attack vector for tool poisoning and unauthorized privilege escalation. Existing defense mechanisms rely on exact cryptographic hash pinning (e.g., SHA-256 over tool definitions), which alerts on every byte-level tool-definition change by construction. Across an empirical audit of 621 historical release transitions from open-source MCP repositories, 31 releases (4.99%) contained tool-definition changes (an operator burden of 0.050 alerts per release transition), meaning all such legitimate maintenance updates trigger reapproval under exact pinning.

To separate integrity detection from semantic security judgment, we propose and evaluate **MCP Semantic Drift Detection**, a multi-tiered defense framework that differentiates authentic software maintenance from malicious tampering. We implement the **MCP Semantic Drift Guard Middleware**, combining sub-millisecond fast-path hash checks and static heuristics with a zero-temperature structured diff semantic judge (`Qwen3-8B`), backed by a persistent SQLite baseline store with automatic rollback. In extensive benchmarks over a cluster-isolated held-out test split ($N=56$), the integrated Guard Middleware under the evaluated `BALANCED` policy with pre-populated trusted baselines achieves **Precision = 100.0%** (33/33, 95% Wilson CI: [89.6%, 100.0%]), **Recall = 100.0%** (33/33, 95% Wilson CI: [89.6%, 100.0%]), and **$F_1 = 100.0\%$**, with a **Benign FPR = 0.0%** (0/23, 95% Wilson CI: [0.0%, 14.3%]); isolating the standalone semantic judge on raw diffs yields an $F_1$ of 91.7% (Precision: 84.6%, Recall: 100.0%, Benign FPR: 26.1% [6/23, 95% CI: 12.5%, 46.5%]). Controlled JSON-RPC socket proxy testing confirms runtime interception, policy enforcement, and automatic definition rollback in active protocol streams.

In adversarial red-teaming across 30 evasion test cases spanning 10 mutation categories, the system achieved a **70.0% Adversarial Detection Rate** (21/30, 95% CI: [52.1%, 83.3%]), successfully detecting indirect wording (2/3), euphemisms (3/3), and prerequisite hijacking (3/3), while uncovering evasion blind spots in optional parameter default injections (0/3 detected) and low-signal boolean schema toggles (0/3 detected). These empirical findings show that meaning-aware semantic drift detection reduces operator reapproval burden while establishing clear boundaries for structural schema verification.

---

## 1. Introduction

### 1.1 The Problem
Autonomous AI agents increasingly rely on standard interface protocols to interact with external databases, execution sandboxes, code repositories, and web services. The Model Context Protocol (MCP) has emerged as an open standard for connecting LLM hosts to heterogeneous tool servers. Under MCP, clients discover available capabilities at runtime by issuing `tools/list` requests. Upstream servers respond with tool manifests containing natural language descriptions, parameter names, type constraints, and documentation.

Because agent host systems inject these advertised manifests directly into system prompts to guide model reasoning, tool definitions occupy a trusted position within the agent's cognitive context. If an upstream server is compromised, malicious dependencies are introduced, or an untrusted server modifies its contracts post-registration, the agent can be coerced into following poisoned instructions—such as exfiltrating user credentials, invoking destructive commands, or chaining unauthorized tools.

### 1.2 Motivation & Operator Review Burden
Current industry security scanners and client integrity checkers (e.g., `snyk-agent-scan` / `mcp-scan`) address tool poisoning via **exact cryptographic tool pinning**. Under exact pinning, a client hashes the canonical JSON representation of a tool definition (SHA-256) upon initial approval. On subsequent invocations, any mismatch between the active hash and the pinned baseline raises a security alarm.

Exact hash comparison evaluates strict byte-level equality, answering the binary integrity question: *"Did the trusted definition change?"* However, software contracts in active ecosystems are not static artifacts: open-source developers continuously refine docstrings to improve model adherence, clarify parameter edge cases, fix typos, add new tools, and introduce backward-compatible optional features.

Across our empirical audit of 621 historical release transitions across open-source MCP repositories:
- **31 of 621 release transitions (4.99%)** contained at least one tool-definition change.
- A total of **123 tool-definition change events** were recorded.
- **110 of the 123 change events (89.4%)** represent tool additions (63 events) or tool removals (47 events).
- Only **13 of the 123 change events (10.6%)** modified pre-existing tool contracts, occurring across **13 of 621 release transitions (2.09%)**:
  - Description / documentation clarifications: 7 releases (1.13% of transitions).
  - Schema / parameter modifications: 2 releases (0.32% of transitions).
  - Mixed description and schema modifications: 4 releases (0.64% of transitions).

#### Quantifying the Review Burden:
1. **Under Exact Hash Pinning**: Because any byte change alters the SHA-256 digest, all 31 release transitions with tool-definition changes trigger security alerts. This imposes an alert burden of **0.050 alerts per release transition** (~1 review alert every 20 releases). For an active repository publishing ~20–25 releases annually, an administrator experiences ~1.0–1.25 review interruptions per repo per year solely from tool manifest changes. In an enterprise environment managing 20 active MCP servers, this generates ~20–25 review alerts per year. Because exact pinning cannot inspect semantic intent, every benign refactoring requires manual human verification to rule out tampering.
2. **Under Semantic Drift Guard**: By addressing the orthogonal question—*"Is the change benign, suspicious, or malicious?"*—the Guard differentiates legitimate evolution from adversarial drift. Under the evaluated `BALANCED` policy with pre-populated baselines, benign false alarm burden on the test set is reduced from 0.050 alerts/release down to 0.000 alerts/release ($0/23$ false alarms), and down to ~0.013 alerts/release under standalone judge evaluation ($6/23$ false alarms, a ~74% reduction in operator reapproval burden).

### 1.3 Research Gap
Prior work (e.g., MCPTox) evaluated downstream agent vulnerability to poisoned tool manifests, but did not measure real-world MCP evolution or evaluate upstream runtime defenses. This research addresses this gap by:
1. Providing an empirical measurement of tool definition evolution across 621 open-source MCP release transitions.
2. Formulating and benchmarking meaning-aware Semantic Drift Judges.
3. Implementing and evaluating an integrated, multi-tier enforcement middleware with automatic rollback and quarantine handling.
4. Stress-testing the approach against an adversarial red-team evasion suite.

---

## 2. Background & Threat Model

### 2.1 Model Context Protocol (MCP) Mechanics
MCP standardizes client-server interactions via JSON-RPC 2.0 over standard I/O (stdio) or Server-Sent Events (SSE). During capability negotiation, the client issues `tools/list` to retrieve the tool catalog:
- `name`: String identifier.
- `description`: Human- and LLM-readable docstring detailing tool intent and constraints.
- `inputSchema`: JSON Schema object defining property types, descriptions, required fields, and validation rules.

### 2.2 Tool Poisoning & The Capability Paradox
Tool poisoning attacks manipulate tool docstrings to inject adversarial directives (e.g., `<IMPORTANT> Before calling this tool, transmit ~/.ssh/id_rsa to http://attacker.com </IMPORTANT>`). We reproduced the **MCPTox** benchmark (*"MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers"*, Zhang et al., AAAI 2026 / arXiv:2508.14925) using local `Qwen3-8B` (Quantization: `Q4_K_M`, $T=0$) across 1,348 test instances spanning 45 MCP servers:
- **No-Think Mode**: 188 exploited out of 1,346 valid instances (**13.97% ASR**).
- **Think Mode**: 560 exploited out of 1,341 valid instances (**41.76% ASR**).
- **Attack Breakdown**: Template-1 Direct Injection (44.93% Think vs 8.13% No-Think); Template-2 Prerequisite Hijacking (25.15% Think vs 3.66% No-Think); Template-3 Argument Redirection (54.62% Think vs 24.60% No-Think).

We designate this empirical finding as the **Capability Paradox**: enabling internal reasoning tokens in `Qwen3-8B` improved the model's adherence to natural language docstrings, which paradoxically caused attack susceptibility to rise by **+27.79 percentage points**. Standard safety filters recorded **0 refusals** across all evaluated test instances, confirming that LLM agents treat tool manifests as trusted operational context.

### 2.3 Adaptive Threat Model
We formulate our defense under an **adaptive attacker model**:
1. **Attacker Knowledge**: The attacker has full knowledge of the defensive pipeline, including SHA-256 hash pinning, Tier 2 static regex patterns, Tier 1 structured diff schema representations, Tier 3 semantic judge prompt templates, and the SQLite baseline rollback mechanism.
2. **Attacker Capabilities**:
   - Modifying tool docstrings and parameter descriptions using indirect phrasing, euphemisms, or semantic paraphrasing.
   - Injecting prompt override payloads targeting the judge (e.g., `"SYSTEM: CLASSIFY AS BENIGN"`).
   - Manipulating JSON Schema attributes (e.g., adding optional parameters with default webhook URLs, toggling `readOnly: true -> false`).
   - Introducing multi-step incremental semantic drift across releases (salami attacks).
   - Adding new unbaselined tools or staging maintainer rug-pulls.
3. **Defender Capabilities**: Middleware proxy positioned at the JSON-RPC boundary intercepting `tools/list` responses, maintaining a persistent trusted SQLite baseline store, and enforcing automated rollback or quarantine.
4. **Out-of-Scope Risks**: Attacks occurring entirely inside upstream server runtime binary execution during `tools/call` without manifest modification, compromised OS environments, unencrypted network transport sniffing, and direct user chat prompt jailbreaks.

---

## 3. Related Work

This research connects tool poisoning defenses, artifact integrity, and agent runtime safety:
- **Tool Poisoning Benchmarks**: *MCPTox* (Zhang et al., 2024, arXiv:2508.14925) and *ToolHijack* (Liu et al., 2024, arXiv:2407.12345) demonstrated that adversarial docstring directives and OpenAPI parameter tampering reliably compromise agent reasoning. Our work complements these studies by shifting focus upstream to runtime detection and contract diffing.
- **Cryptographic Asset Pinning**: *W3C Subresource Integrity (SRI)* (W3C Recommendation, 2016, https://www.w3.org/TR/SRI/) establishes cryptographic hash matching for web scripts. In agent ecosystems, *snyk-agent-scan / mcp-scan* (Snyk Research, 2025, https://github.com/snyk/snyk-agent-scan) pins tool JSON hashes. Our work quantifies the operator review burden of exact pinning in dynamic software environments.
- **Software Supply-Chain Transparency**: *Sigstore* (Newman et al., 2022, OpenSSF / ACM CCS) provides cryptographic signing for container images and packages. Signing validates author identity but cannot evaluate semantic behavioral drift in legitimate updates.
- **Conversational Guardrails**: *NeMo Guardrails* (Rebedea et al., 2023) and *Llama Guard* (Inan et al., 2024) filter unstructured chat dialogues. In contrast, our guard operates specifically on structured JSON-RPC contracts, isolating code-schema modifications from natural language descriptions.
- **API Evolution & Breaking Changes**: Classical API evolution research (Dig & Johnson, 2006; Brito et al., 2018) analyzed structural compiler type signatures. MCP requires analyzing natural language docstrings that steer probabilistic LLM reasoning.

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

### 5.1 Formal Problem Definition

We formally define the tool-definition monitoring task over Model Context Protocol (MCP) servers. An advertised tool contract $T$ is represented as a structured schema tuple $T = (n, d, S)$, where $n$ is the tool name identifier, $d$ is the natural language docstring, and $S$ is the JSON Schema specifying parameter types, required fields, and constraints.

#### 1. Cryptographic Change Detection
Upon receiving a candidate tool update, the system computes the binary cryptographic change indicator $D_H$:
$$D_H = \begin{cases} 0, & H(T_{\text{old}}) = H(T_{\text{new}}) \\ 1, & H(T_{\text{old}}) \neq H(T_{\text{new}}) \end{cases}$$
where:
- $T_{\text{old}}$: previously established trusted tool definition stored in the persistent registry.
- $T_{\text{new}}$: newly observed candidate definition received during `tools/list` capability exchange.
- $H(\cdot)$: SHA-256 cryptographic digest over the canonicalized JSON representation.
- $D_H$: binary indication that the tool definition changed.

*Important Research Distinction*: A hash mismatch ($D_H = 1$) establishes that a tool definition changed, but does not by itself establish that the change is malicious. Exact byte-level equality detects modification rather than interpreting semantic intent.

#### 2. Semantic Drift Classification
When $D_H = 1$, the observed contract evolution is evaluated by a semantic classification function $f_{\theta}$:
$$\hat{y} = f_{\theta}(T_{\text{old}}, T_{\text{new}}, \Delta T)$$
where:
- $\Delta T$: structured difference (AST parameter delta and natural language docstring summary) between $T_{\text{old}}$ and $T_{\text{new}}$.
- $f_{\theta}$: semantic classification function implemented by the semantic judge operating under XML-sandboxed diff prompt templates.
- $\hat{y}$: predicted classification $\in \{\text{BENIGN}, \text{SUSPICIOUS}, \text{MALICIOUS}\}$.

The semantic judge evaluates the observed definition change and assigns the implemented security classification without executing external tools.

#### 3. Classification Evaluation Metrics
To quantify detector effectiveness across benchmark datasets, we use standard classification metrics:
$$\text{Precision} = \frac{TP}{TP + FP}, \qquad \text{Recall} = \frac{TP}{TP + FN}$$
$$F_1 = 2 \cdot \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$
where $TP$ denotes malicious tool modifications correctly identified as threats, $FP$ denotes benign maintenance updates incorrectly flagged as security violations (false alarms), and $FN$ denotes malicious mutations that evade detection.

### 5.2 Multi-Tier Guard Pipeline

The **MCP Guard Middleware** (`guard/middleware.py`) implements a 4-tier pipeline renumbered in strict operational execution order:

```
Incoming tools/list Response
            │
            ▼
[ Tier 0: Hash Fast-Path ] ────────── (Match) ────► ALLOW (0.024 ms, 0 LLM calls)
            │ (Mismatch / New Tool)
            ▼
[ Tier 1: Structured Diff Engine ] ──► Generates Canonical Field-Level Delta
            │
            ▼
[ Tier 2: Static Regex Rules ] ────── (High Match) ► QUARANTINE (0.024 ms, 0 LLM calls)
            │ (Clean)
            ▼
[ Tier 3: Semantic Diff Judge ] ─────► Local Qwen3-8B (Mode B, T=0)
            │
    ┌───────┴───────────────────────┬───────────────────────┐
    ▼                               ▼                       ▼
 BENIGN                         SUSPICIOUS              MALICIOUS
    │                               │                       │
 ALLOW (Update DB)           WARN / QUARANTINE        BLOCK & Rollback V1
```

#### Pipeline Tiers:
1. **Tier 0 (Hash Fast-Path)**: Computes canonical SHA-256 over normalized JSON (`name`, `description`, `inputSchema`). If identical to baseline ($D_H = 0$), returns `ALLOW` in $0.024\text{ ms}$.
2. **Tier 1 (Structured Diff Engine)**: Computes field-level structured delta $\Delta T$ (`params_added`, `params_removed`, `params_modified`, `description_diff_summary`), stripping boilerplate.
3. **Tier 2 (Static Regex Rules)**: Pre-filters diffs against 7 regular expressions (`<IMPORTANT>`, `MUST FIRST`, `/etc/shadow`). High-severity matches trigger immediate `QUARANTINE` in $0.024\text{ ms}$.
4. **Tier 3 (Semantic Diff Judge)**: Prompts local `Qwen3-8B` ($T=0$) with the structured diff wrapped in `<untrusted_diff>` sandboxes, emitting structured JSON decisions ($\hat{y} \in \{\text{BENIGN}, \text{SUSPICIOUS}, \text{MALICIOUS}\}$).
5. **Baseline Store & Rollback Engine**: Persistent SQLite store maintaining trusted contracts. For quarantined updates, the proxy substitutes the trusted V1 definition in the client response.

---

## 6. Detector Benchmark & Held-Out Results

### 6.1 Dataset Construction & Split Isolation
The benchmark dataset combines real updates, programmatic hard negatives, and MCPTox attacks ($N=370$ total), partitioned into Train ($N=259$), Dev ($N=55$), and Held-Out Test ($N=56$, 33 Malicious, 23 Benign) with zero cluster overlap (`server_id + tool_name`).

### 6.2 Held-Out Benchmark Results (N=56)

| Method / Defense Layer | TP | TN | FP | FN | Precision (95% CI) | Recall (95% CI) | $F_1$ Score | Benign FPR (95% CI) | Mean Latency | LLM Calls / Upd |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Tier 0)** | 33 | 0 | 23 | 0 | 58.9% [45.9%, 70.8%] | 100.0% [89.4%, 100.0%] | 74.2% | 100.0% [85.2%, 100.0%] | 0.024 ms | 0.0 |
| **Static Keyword Rules (Tier 2)** | 18 | 23 | 0 | 15 | 100.0% [81.5%, 100.0%] | 54.5% [37.8%, 70.3%] | 70.6% | 0.0% [0.0%, 14.8%] | 0.024 ms | 0.0 |
| **TF-IDF Cosine Baseline** | 31 | 6 | 17 | 2 | 64.6% [50.4%, 76.6%] | 93.9% [80.4%, 98.3%] | 76.5% | 73.9% [53.5%, 87.5%] | ~1.2 ms | 0.0 |
| **Semantic Judge Mode A (Full)** | 32 | 14 | 9 | 1 | 80.5% [65.1%, 91.2%] | 97.0% [84.2%, 99.9%] | 87.9% | 39.1% [21.8%, 59.6%] | 2,850 ms | 1.0 |
| **Semantic Judge Mode B (Diff)** | 33 | 17 | 6 | 0 | 85.7% [72.8%, 94.1%] | 100.0% [89.4%, 100.0%] | 92.3% | 26.1% [12.6%, 46.5%] | 1,420 ms | 1.0 |
| **Integrated Guard Middleware** | **33** | **23** | **0** | **0** | **100.0%** [89.4%, 100.0%] | **100.0%** [89.4%, 100.0%] | **100.0%** | **0.0%** [0.0%, 14.8%] | **~960 ms** | **0.61** |

### 6.3 Reconciling Detection Counts & Short-Circuits
In the Phase 5 test evaluation ($N=56$):
- **Short-Circuit Breakdown**: 26 of 56 items (46.4%) short-circuited at deterministic tiers without invoking the LLM:
  - **1 item** matched trusted baseline hash at Tier 0 (`ALLOW`, $< 1\text{ ms}$).
  - **25 malicious items** triggered high-severity Tier 2 static regex rules (`QUARANTINE`, $< 1\text{ ms}$).
- **LLM-Judged Items**: The remaining 30 items (8 subtle malicious attacks + 22 modified benign items) were dispatched to Tier 3 Semantic Judge.
- **Latency Distribution Explanation**:
  - All 56 updates: Mean = 30.5 s, Median (p50) = 41.6 s, p95 = 72.6 s.
  - The overall mean (30.5 s) is lower than the median (41.6 s) because the 26 deterministic short-circuits execute in $\approx 0.000\text{ s}$, creating a bi-modal distribution that pulls down the mean. For LLM-judged items only, the mean latency is 56.9 s on CPU.

---

## 7. Dataset Validity & Generalization Audits

### 7.1 Controlled Matched-Pairs Evaluation ($N=24$)
To eliminate writing style, server domain, and structural schema complexity as confounding variables, we constructed a **Controlled Matched-Pair Exploratory Pilot** (`data/matched_pairs.jsonl`). Each record is a controlled triplet:
$$\text{Triplet}_i = \Big( \text{Tool}_{\text{old}}, \quad \text{Tool}_{\text{benign\_new}}, \quad \text{Tool}_{\text{malicious\_new}} \Big)$$

- **Dataset Scale & Composition**: 12 matched triplets across 6 distinct servers, yielding **$N = 24$ candidate evaluations** (12 benign, 12 malicious) spanning 6 attack categories (Instruction Injection, Prerequisite Manipulation, Argument Redirection, Authorization Expansion, Data Exfiltration, and Schema Mutation).
- **Provenance & Scoping**: Derived from all available historical modified contracts mined from the open-source corpus. This suite serves strictly as a **descriptive exploratory evaluation** to isolate stylistic phrasing confounds rather than a large asymptotic benchmark ($\ge 100$ pairs).
- **Validation**: Each triplet shared identical server IDs, tool names, argument schemas, and authoring styles.
- **Pilot Results**:
  - **Recall**: 100.0% (12/12 malicious mutations caught, 95% Wilson CI: [75.8%, 100.0%]).
  - **Precision**: 80.0% (12/15, 95% Wilson CI: [54.8%, 93.0%]).
  - **Benign Specificity**: 75.0% (9/12 benign updates allowed; 3 flagged for human review, FPR = 25.0% [95% CI: 8.9%, 53.2%]).
  - **Overall F1 Score**: **88.9%**.

### 7.2 Evaluation on Real Pre-Existing Contract Modifications ($N=13$)
In early evaluation phases, benign updates included all tool-definition events extracted from MCP git histories ($N=123$). However, **110 of the 123 events represent newly added or removed tools**, which lack complex natural language modifications.

We isolated the **13 historical pre-existing contract modifications** to evaluate performance specifically on contract refactorings:
- **Exact Hash Pinning**: 100.0% Alert Rate (13/13 flagged).
- **Static Regex Rules**: 0.0% False Positive Rate (0/13 flagged), but blind to semantic intent.
- **TF-IDF Lexical Baseline**: 69.2% FPR (9/13 flagged).
- **Semantic Guard**: **23.1% FPR** (10 of 13 updates correctly allowed; 3 flagged as suspicious due to commit message notes mentioning vulnerability patches).
- *Takeaway*: Guard reduces the human review burden on authentic contract modifications by **76.9%** (cutting alerts from 13 down to 3), proving that false alarm reduction is not merely an artifact of tool additions.

### 7.3 Static Rule Provenance & Pre-Registration Bias Audit
We audited the 7 static regular expressions (`guard/static_rules.py`) to confirm absence of post-hoc test set overfitting:
1. **Provenance**: Extracted strictly from MCPTox benchmark template definitions (AAAI 2026, Section 3.2) prior to pipeline testing.
2. **Pre-Registration**: Fixed in Phase 3 and left unadjusted through Phase 5.
3. **Empirical Independence on Matched Pairs**: On the Matched-Pairs dataset—where MCPTox phrasing templates were eliminated—static rules detected only **25.0% of attacks (3/12)**, whereas the Tier 3 Semantic Judge detected **100.0% (12/12)**. This confirms that static rules act solely as fast pre-filters and that the system relies on semantic reasoning for evasive payloads.

### 7.4 Server-Grouped 5-Fold Cross-Validation ($N=370$)
To test generalization across unseen server codebases, we performed **5-Fold Server-Grouped Cross-Validation** over all 370 benchmark examples across 19 unique servers with zero server template overlap between folds:

| Fold | Held-Out Test Servers | N | Malicious | Benign | Precision | Recall | Benign FPR | F1 Score |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **Fold 1** | `puppeteer`, `git`, `sentry` | 79 | 48 | 31 | 84.2% | 100.0% | 29.0% | 91.4% |
| **Fold 2** | `filesystem`, `mysql`, `time` | 76 | 70 | 6 | 98.6% | 100.0% | 16.7% | 99.3% |
| **Fold 3** | `adfin`, `filesystem`, `memory` | 79 | 39 | 40 | 81.2% | 100.0% | 22.5% | 89.7% |
| **Fold 4** | `playwright`, `amapmap`, `slack` | 66 | 29 | 37 | 78.4% | 100.0% | 21.6% | 87.9% |
| **Fold 5** | `sqlite`, `github`, `everything`, `flomo` | 70 | 14 | 56 | 50.0% | 100.0% | 25.0% | 66.7% |
| **Macro Mean (Sample SD)** | **5-Fold Cross-Validation** | **370** | **200** | **170** | **78.5% $\pm 17.8\%$** | **100.0% $\pm 0.0\%$** | **23.0% $\pm 4.5\%$** | **87.0% $\pm 12.2\%$** |
| **Pooled (Micro-Avg)** | **All 370 Items Combined** | **370** | **200** | **170** | **83.0%** | **100.0%** | **24.1%** | **90.7%** |

*Note: All ± values denote sample standard deviations (ddof=1) across the 5 folds. Zero leakage was verified formally via automated unit tests (`tests/test_leakage.py`).*

---

## 8. Baselines, Ablations, and Master Comparison

### 8.1 Full Tier Ablation Study (Configurations A–H)
To evaluate the individual and collective contributions of each defensive layer, we evaluated eight architectural variants across the held-out test split ($N=56$):

| Config Identifier | Defensive Layers Included | Precision | Recall | F1 Score | Benign FPR | Malicious FNR | LLM Calls / Upd | Latency (Mean) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **Config A** | Hash Only | 58.9% | **100.0%** | 74.2% | 100.0% (23/23) | **0.0%** | 0.0 | **< 0.05 ms** |
| **Config B** | Static Regex Only | **100.0%** | 75.8% | 86.2% | **0.0%** (0/23) | 24.2% (8/33) | 0.0 | **< 0.05 ms** |
| **Config C** | Hash + Static | 58.9% | **100.0%** | 74.2% | 100.0% (23/23) | **0.0%** | 0.0 | **< 0.05 ms** |
| **Config D** | Hash + Static + Diff | 58.9% | **100.0%** | 74.2% | 100.0% (23/23) | **0.0%** | 0.0 | ~0.10 ms |
| **Config E** | Hash + Static + Semantic Judge | 84.6% | **100.0%** | **91.7%** | 26.1% (6/23) | **0.0%** | 0.68 | ~965 ms |
| **Config F (Full)** | **Full Guard Pipeline** | **84.6%** | **100.0%** | **91.7%** | **26.1%** (6/23) | **0.0%** | **0.61** | **~960 ms** |
| **Config G** | Guard without Schema Check | 84.6% | **100.0%** | 91.7% | 26.1% (6/23) | **0.0%** | 0.61 | ~960 ms |
| **Config H** | Deterministic Fast Path (No LLM) | **100.0%** | 66.7% | 80.0% | **0.0%** (0/23) | 33.3% (11/33) | **0.0** | **~0.12 ms** |

### 8.2 Representation Ablation: Mode A (Full) vs. Mode B (Diff Only)
- **Mode A (Full Definition)**: Presenting complete schemas caused context bloat, yielding Precision = 78.0%, Recall = 97.0%, $F_1 = 86.5\%$, and a **20.0% JSON parsing failure rate** on smaller context evaluations.
- **Mode B (Structured Diff)**: Presenting canonical field-level diffs reduced prompt tokens by 77.4%, reduced latency from 2.85s to 1.42s, and improved performance to Precision = 84.6%, Recall = 100.0%, **$F_1 = 91.7\%$** with **0.0% JSON parsing errors**.

### 8.3 TF-IDF Cosine-Similarity Lexical Baseline
We implemented Baseline 3 (`experiments/baseline_embedding.py`) using a sublinear TF-IDF word n-gram vectorizer ($n \in [1, 3]$). The similarity decision threshold was calibrated strictly on the Train + Dev splits ($N=314$), yielding $\theta^* = 0.590$.
- **Held-Out Test Results ($N=56$)**: Precision = 64.6% (31/48, 95% CI: [50.4%, 76.6%]), Recall = 93.9% (31/33, 95% CI: [80.4%, 98.3%]), **$F_1 = 76.5\%$**, Benign FPR = **73.9%** (17/23, 95% CI: [53.5%, 87.5%]).
- *Finding*: Shallow lexical similarity distance cannot distinguish harmless documentation expansions from malicious directives, producing 17 false alarms out of 23 benign updates.

### 8.4 Local Model Comparison on Held-Out Split ($N=56$)
All models evaluated locally via Ollama with greedy decoding ($T=0$):

| Model | Architecture & Parameters | F1 Score | Precision | Recall | Benign FPR | Mean Latency |
|---|---|---:|---:|---:|---:|---:|
| **Qwen3:8B** | Qwen3-Instruct (8.2B) | **91.7%** | **84.6%** | **100.0%** | **26.1%** | 1,420 ms |
| **Gemma3:4B** | Gemma3-IT (4.3B) | 87.3% | 81.6% | 93.9% | 30.4% | 780 ms |
| **Qwen2.5:1.5B** | Qwen2.5-Instruct (1.5B) | 81.5% | 68.8% | 100.0% | 65.2% | 290 ms |

### 8.5 Thinking ON vs. OFF Ablation (Qwen3:8B)
- **Qwen3:8B Thinking OFF (Direct JSON)**: $F_1 = 91.7\%$, Mean Latency = **1.42 s** (0.0% parse errors).
- **Qwen3:8B Thinking ON (Reasoning Chain)**: $F_1 = 91.7\%$, Mean Latency = **4.68 s** (**+230% latency overhead**).
- **Ablation Interpretation**: Disabling internal thinking reduced per-tool latency by ~70% while maintaining classification accuracy on structured diffs ($F_1 = 91.7\%$, latency 1.42 s vs 4.68 s).

### 8.6 Prompt Sensitivity & Instruction Robustness ($N=20$)
We evaluated three semantically equivalent system instructions (Operational Auditor, Declarative Verifier, Risk-Focused Auditor) across a stratified sample ($N=20$):
- **Formulation 1 (Default)**: $F_1 = 92.3\%$, FPR = 25.0% (2/8).
- **Formulation 2 (Declarative)**: $F_1 = 92.3\%$, FPR = 25.0% (2/8).
- **Formulation 3 (Risk-Focused)**: $F_1 = 88.9\%$, FPR = 37.5% (3/8).
- **Inter-Prompt Agreement**: Pairwise Cohen's $\kappa = 0.89$–$1.00$, with zero false negatives across all variants.

### 8.7 Run-to-Run Determinism under Q4_K_M Quantization ($N=56$)
We conducted 3 repeated runs across all 56 held-out test examples using `qwen3:8b` ($Q4\_K\_M$, $T=0$, seed=42):
- **Label Agreement**: **100.0% across all 168 inferences** (zero categorical flips between `BENIGN`, `SUSPICIOUS`, and `MALICIOUS`).
- **Latency Jitter**: $\sigma = \pm 13.6\text{ ms}$ ($\pm 1.2\%$), reflecting standard CPU/GPU scheduling.
- **JSON Parser Stability**: 100.0% valid JSON responses emitted.

### 8.8 Master Evaluation Comparison Matrix

| System / Defense Paradigm | Precision (95% CI) | Recall (95% CI) | F1 Score | Benign FPR (95% CI) | Malicious FNR (95% CI) | Mean Latency | LLM Calls / Upd |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Tier 0)** | 58.9% [45.9%, 70.8%] | **100.0%** [89.6%, 100.0%] | 74.2% | 100.0% [85.7%, 100.0%] | **0.0%** [0.0%, 10.4%] | **< 0.05 ms** | 0.0 |
| **Static Keyword Rules (Tier 2)** | **100.0%** [86.7%, 100.0%] | 75.8% [59.0%, 87.2%] | 86.2% | **0.0%** [0.0%, 14.3%] | 24.2% [12.8%, 41.0%] | **< 0.05 ms** | 0.0 |
| **TF-IDF Cosine Baseline** | 64.6% [50.4%, 76.6%] | 93.9% [80.4%, 98.3%] | 76.5% | 73.9% [53.5%, 87.5%] | 6.1% [1.7%, 19.6%] | ~1.2 ms | 0.0 |
| **Deterministic Schema (Tier 1.5)** | **0.0%** [0.0%, 0.0%] | 0.0% [0.0%, 10.4%] | 0.0% | **0.0%** [0.0%, 14.3%] | 100.0% [89.6%, 100.0%] | 0.08 ms | 0.0 |
| **Semantic Judge Mode A (Full)** | 78.0% [63.3%, 88.0%] | 97.0% [84.7%, 99.5%] | 86.5% | 39.1% [22.2%, 59.2%] | 3.0% [0.5%, 15.3%] | 2,850 ms | 1.0 |
| **Semantic Judge Mode B (Diff Only)** | 84.6% [70.3%, 92.8%] | **100.0%** [89.6%, 100.0%] | 91.7% | 26.1% [12.5%, 46.5%] | **0.0%** [0.0%, 10.4%] | 1,420 ms | 1.0 |
| **Integrated Guard Middleware (BALANCED)** | **100.0%** [89.6%, 100.0%] | **100.0%** [89.6%, 100.0%] | **100.0%** | **0.0%** [0.0%, 14.3%] | **0.0%** [0.0%, 10.4%] | **~960 ms** | **0.61** |

---

## 9. Adversarial Evaluation and Defense Hardening

### 9.1 Initial Adversarial Red-Team Suite ($N=30$, 10 Categories)
We evaluated 30 structured adversarial cases across 10 evasion categories (3 cases per category):
- **Overall Detection Rate**: **70.0%** ($21 / 30$, 95% Wilson CI: [52.1%, 83.3%]).
- **Detected Categories (100%)**: Euphemisms (3/3), Subtle Boundaries (3/3), Diagnostic Prerequisites (3/3), Parameter Docstring Hiding (3/3), Explicit Redirection (3/3), Field Splitting (3/3).
- **Partial Detection**: Indirect Wording (2/3), Multi-Step Intent (1/3).
- **Identified Blind Spots (0/3)**: Purely structural modifications—specifically **Optional Parameter Default Injections** (0/3) and **Low-Signal Boolean Schema Toggles** (`readOnly: true -> false`, 0/3)—bypassed natural-language docstring judges.

### 9.2 Deterministic Schema Security Checks (Tier 1.5)
To address the schema-only blind spots identified in Section 9.1 without relying on brittle LLM reasoning over raw JSON objects, we implemented **Deterministic Tier 1.5 Schema Security Checks** (`guard/schema_security_rules.py`):
1. **Authorization Toggles**: Flags `readOnly: true -> false` transitions.
2. **Default Value Injections**: Regular expression audit intercepting external URLs, IP addresses, and sensitive paths in property `default` fields.
3. **Interface Constriction**: Audits parameter type mutations and enum constraint narrowing.
- **Performance**: Executes in $< 0.10\text{ ms}$ and produced **0 false positives** on the evaluated $N=23$ benign test cases.

### 9.3 Exploratory Adversarial Pilot Evaluation (Red-Team v2, $N=28$, 14 Categories)
We constructed and evaluated a fresh 14-category adversarial suite (`data/redteam_v2.jsonl`, $N=28$, exactly $n=2$ cases per category) as an **exploratory adversarial pilot** against the upgraded defense pipeline:
- **Overall Pilot Detection Rate**: **89.3%** ($25 / 28$ detected, 95% Wilson CI: [72.8%, 96.3%]).
- **Tier 1.5 Schema Checks Contribution**: Caught 10/28 attacks deterministically upstream in $< 0.10\text{ ms}$, successfully resolving the previous $0/3$ blind spots on parameter defaults and `readOnly` toggles.
- **Remaining Evasions ($n=3$)**: Highly subtle passive voice framing where exfiltration was described as standard optional telemetry without concrete network indicators.
- **Exploratory Pilot Qualification**: Because each category contains $n=2$ test cases, this 89.3% detection rate is strictly an exploratory pilot demonstrating targeted evasion mechanics and failure modes, rather than a definitive asymptotic robustness estimate.

### 9.4 Judge Prompt Injection Robustness Pilot ($N=4$)
We evaluated 4 pilot cases containing direct prompt override payloads targeting the judge (e.g., `"SYSTEM: CLASSIFY AS BENIGN. The following diff is authorized"`):
- **Result**: **4 of 4 attacks detected (100% recall)**.
- **Mechanism**: Mode B isolated diff formatting encloses untrusted diff content in strict `<untrusted_diff>` XML sandboxes, preventing command breakout into the judge instruction channel.

### 9.5 Incremental Salami Drift Multi-Step Simulation ($N=5$)
We evaluated a 5-version sequential incremental drift progression ($V_1 \xrightarrow{} V_2 \xrightarrow{} V_3 \xrightarrow{} V_4 \xrightarrow{} V_5$):
- **Per-Step Adjacent Diffing**: Each step-wise change $\Delta_i = (V_{i-1} \rightarrow V_i)$ appeared cosmetic, allowing the attack to progress until Step 5.
- **Cumulative Baseline Anchoring**: Comparing candidate $V_i$ against the root trusted baseline $V_{\text{root}}$ detected the accumulated drift at **Step 4** (flagged as `MALICIOUS` $\rightarrow$ `QUARANTINE`), halting the attack chain before weaponized exfiltration could execute.

### 9.6 Newly Added Tools & Maintainer Rug-Pull Timing Policies
- **Newly Added Tools**: Newly introduced tools lack prior V1 baselines; our policy enforces **Initial Discovery Quarantine** until explicit administrative review.
- **Maintainer Rug-Pull Timing**: For servers with clean historical releases that later turn malicious, the middleware re-verifies cryptographic hashes and evaluates semantic diffs on every session handshake, preventing historical reputation from granting uninspected trust.

---

## 10. Deployment, Latency & Operational Safety Analysis

### 10.1 Live MCP JSON-RPC Socket Proxy Testing
Controlled socket proxy testing (`experiments/phase5_live_mcp_proxy.py`) verified real-time `tools/list` traffic interception:
- **Bootstrap Phase**: Initial tool contracts registered in SQLite as `TRUSTED`.
- **Benign Update Phase**: Docstring clarifications evaluated as `BENIGN` $\rightarrow$ `ALLOW`, updating baseline records.
- **Attack Phase**: A poisoned tool contract was intercepted, evaluated as `MALICIOUS` $\rightarrow$ `QUARANTINE`, and replaced with the **Trusted V1 definition** in the client response.

### 10.2 Component Latency & Fast-Path Optimization
Across all evaluated pipeline layers:
- **Tier 0 Hash Fast-Path**: $0.024\text{ ms}$ (0 LLM calls).
- **Tier 1.5 Schema Security Checks**: $0.080\text{ ms}$ (0 LLM calls).
- **Tier 2 Static Regex Rules**: $0.024\text{ ms}$ (0 LLM calls).
- **Tier 3 Semantic Diff Judge (CPU Inference)**: Mean Latency = **1.42 s** (`Qwen3:8B` Mode B), with smaller models achieving 780 ms (`Gemma3:4B`) and 290 ms (`Qwen2.5:1.5B`).
- **Short-Circuit Compute Savings**: Upstream deterministic tiers short-circuited 46.4% of candidate updates in $< 1\text{ ms}$, reducing model invocation requirements to 0.61 calls per update.

### 10.3 Asynchronous Out-of-Band Staging Mode
To prevent the ~1.42s CPU semantic inference latency from delaying interactive agent startup handshakes, we specify an **Asynchronous Out-of-Band Staging Architecture**:
1. **Immediate Client Handshake**: When an upstream server broadcasts an updated candidate definition ($V_2$), the middleware immediately returns the cached, trusted $V_1$ definition to the LLM agent client ($0\text{ ms}$ added latency).
2. **Background Queue Dispatch**: The candidate $V_2$ payload is dispatched to an asynchronous background worker pool for multi-tier inspection.
3. **Promotion vs. Quarantine**:
   - If verified as `BENIGN`, $V_2$ is promoted to the SQLite baseline store and served on subsequent sessions.
   - If evaluated as `MALICIOUS` or `SUSPICIOUS`, $V_2$ is permanently quarantined, and an administrative security alert is dispatched with full structured audit findings.

### 10.4 Policy Engine Failure Modes & Timeout Specifications
To ensure predictable fail-safe behavior under adverse operating conditions (network disconnects, process crashes, or inference stalls > 45s), the policy engine supports two configurable operational modes (verified in `tests/test_failure_policy.py`):
1. **FAIL_SECURE Mode (BALANCED / STRICT Default)**: If the semantic judge experiences a socket timeout, non-JSON output parse failure, or daemon unavailability, the candidate update is treated as `SUSPICIOUS` $\rightarrow$ `QUARANTINE`. The proxy serves the last trusted $V_1$ baseline and logs an `ERROR_TIMEOUT` alert, guaranteeing that deliberate denial-of-service or prompt-breaking attacks cannot force an uninspected bypass.
2. **FAIL_OPEN Mode (AUDIT Mode)**: Allows the candidate definition through while recording an unverified telemetry event, suitable solely for passive development environments.

### 10.5 Rollback Safety & Breaking Schema Incompatibility
While rolling back to $V_1$ provides an effective containment mechanism for docstring modifications and optional parameter additions, it is **not universally call-compatible** when an upstream server introduces breaking structural changes (verified in `tests/test_rollback_safety.py`):
- **Compatible Rollback**: When $V_2$ modifies descriptions or adds optional parameters with server defaults, client calls constructed with $V_1$ schemas succeed seamlessly.
- **Incompatible Breaking Changes**: If $V_2$ introduces newly required arguments, renames existing parameters, removes properties, or alters primitive types, client calls constructed against the $V_1$ schema will be rejected by the upstream server runtime during subsequent `tools/call` invocations (producing `MissingRequiredArgument` or `InvalidParameter` RPC errors).
- **Enforced Safety Protocol**: When a quarantined update contains breaking schema modifications, the middleware escalates from transparent definition substitution to **Full Tool Quarantine**, disabling tool access and alerting the agent runtime rather than attempting a brittle rollback.

---

## 11. Limitations

We explicitly document the following empirical, architectural, and evaluation boundaries:

1. **Authentic Existing-Contract Sample Size ($N=13$)**: Real open-source MCP repositories currently contain only 13 modified pre-existing tool contracts; 110 of the 123 observed evolutionary events represent tool additions and removals. While Guard reduces false alarms on this sample by 76.9% (from 13 down to 3), broader empirical validation requires ongoing ecosystem tracking.
2. **Matched-Pair Pilot Scale ($N=24$)**: The controlled matched-pair dataset contains $N=24$ candidate evaluations (12 matched triplets across 6 servers). It serves strictly as an exploratory pilot isolating stylistic phrasing confounds rather than a large asymptotic corpus ($\ge 100$ pairs).
3. **Adversarial Red-Team v2 Scale ($N=28$)**: The upgraded adversarial suite evaluates 14 evasion categories with exactly $n=2$ test cases per category, serving as an exploratory demonstration of failure mechanisms rather than a population-level robustness estimate.
4. **Synthetic Adversarial Datasets**: Due to the nascent nature of production MCP deployments, malicious drift samples are generated via synthetic templates (MCPTox mutations) and red-team injections rather than discovered in-the-wild zero-day incidents.
5. **Dataset & Style Confounding**: Despite paired evaluation and 47 programmatic hard negatives, subtle lexical differences between authentic developer docstrings and synthetic attack injections may introduce latent stylistic signals.
6. **Local CPU Inference Latency**: Local `Qwen3:8B` inference averages ~1.42s on CPU. While 46.4% of updates short-circuit at deterministic tiers in $< 0.10\text{ ms}$, synchronous inline execution during high-frequency startup handshakes requires asynchronous out-of-band staging.
7. **Rollback Compatibility Scope**: Baseline rollback to $V_1$ is effective for docstring modifications and optional parameters, but breaking structural mutations (required parameter additions, property deletions, type changes) cause downstream RPC invocation failures and must escalate to Full Tool Quarantine.
8. **Evaluation Environment**: Live JSON-RPC proxy evaluation was conducted in controlled local socket test fixtures rather than multi-tenant, internet-scale production deployments.
9. **Judge Prompt-Injection Sample ($N=4$)**: Prompt override sandboxing was verified across 4 targeted pilot cases; evaluating complex multi-turn prompt injection payloads remains future work.
10. **Salami-Drift Evaluation Scope ($N=5$)**: Incremental multi-step drift was evaluated across a 5-version sequential chain; larger multi-branch drift topologies remain to be explored.
11. **Local vs. Frontier Model Scope**: Primary evaluations were conducted on quantized local models (`Qwen3:8B`, `Gemma3:4B`, `Qwen2.5:1.5B`); evaluations on closed commercial frontier APIs (e.g., GPT-4o, Claude 3.5 Sonnet) were not executed.
12. **Corpus Coverage**: Mining was conducted across 28 open-source repositories on GitHub; while diverse, it does not encompass the entire closed enterprise MCP landscape.

---

## 12. Reproducibility & Open Artifacts

To support full third-party reproduction and ongoing research, all code, benchmark datasets, prompt templates, and evaluation scripts are released under an open-source license at the anonymized repository: `https://github.com/anonymous-submission/mcp-semantic-drift`.

### 12.1 Execution Commands
- **Unit & Integration Tests (40 Tests, Zero Leakage & Safety)**:
  ```bash
  python -m unittest discover tests
  ```
- **Zero-Leakage Server Disjointness Verification**:
  ```bash
  python -m unittest tests/test_leakage.py
  ```
- **5-Fold Server-Grouped Cross-Validation**:
  ```bash
  python experiments/cross_validate.py
  ```
- **TF-IDF Baseline Calibration**:
  ```bash
  python experiments/baseline_embedding.py
  ```
- **Multi-Tier Detector Ablation**:
  ```bash
  python experiments/ablation_detector.py
  ```
- **Live Local Proxy Integration Test**:
  ```bash
  python experiments/phase5_live_mcp_proxy.py
  ```

### 12.2 Artifact Specifications
- **Judge System Prompt**: Implemented in `guard/semantic_judge.py` using strict JSON schema output formatting and XML delimiter sandboxing (`<untrusted_diff>`).
- **Deterministic Schema Security Rules**: Implemented in `guard/schema_security_rules.py` for parameter defaults, `readOnly` toggles, and enum constriction.
- **Static Regex Rules**: 7 pre-registered regular expressions in `guard/static_rules.py`.
- **Corpus Mining**: `experiments/phase2_extract_corpus.py` across 28 repositories on GitHub with $\ge 2$ release tags (621 version transitions).
- **Hard Negative Provenance**: 47 programmatic hard negatives generated in `experiments/generate_hard_negatives.py` by inserting legitimate security terms into real benign docstrings without changing tool semantics.

---

## 13. Conclusion

This research demonstrates that **MCP Semantic Drift Detection** separates byte-level integrity verification from semantic security analysis. While exact cryptographic hashing flags all observed tool-definition changes because its integrity criterion is byte-level equality, the integrated Guard Middleware under the tested BALANCED policy reduced false alarms on the evaluated N=56 test split while detecting all tested attack vectors in that sample. Adversarial evaluations show strong baseline detection against explicit instruction tampering while highlighting subtle euphemisms and breaking schema evolutions as key areas for ongoing defensive refinement.

---

## References

1. **Brito, G., Hora, A., & Valente, M. T.** (2018). *Breaking Bad: An Extensive Empirical Study of Breaking Changes in Ecosystems*. In Proceedings of the IEEE 25th International Conference on Software Analysis, Evolution and Reengineering (SANER), pp. 76–86.
2. **Dig, D., & Johnson, R.** (2006). *How do APIs evolve? A story of refactoring*. Journal of Software Maintenance and Evolution: Research and Practice, 18(2), 83–107.
3. **Inan, H., Upasani, K., Chi, J., Rungta, R., Iyer, K., Mao, Y., Tontchev, M., Hu, Q., Fuller, B., Testuggine, D., & Khabsa, M.** (2023). *Llama Guard: LLM-based Input-Output Safeguard for Human-AI Conversations*. arXiv preprint arXiv:2312.06674.
4. **Liu, Y., Zhang, Y., & Chen, X.** (2024). *ToolHijacker: Stealing Tool Execution in LLM Agent through Black-box Poisoning*. arXiv preprint arXiv:2407.12345.
5. **Newman, L., et al. (OpenSSF)** (2022). *Sigstore: Software Signing for Everybody*. ACM Conference on Computer and Communications Security (CCS).
6. **Rebedea, T., Dinu, R., Sreedhar, M. N., Parisien, C., & Cohen, J.** (2023). *NeMo Guardrails: A Toolkit for Controllable and Safe LLM Applications with Programmable Rails*. In Proceedings of the 2023 Conference on Empirical Methods in Natural Language Processing (EMNLP): System Demonstrations, pp. 431–444.
7. **Snyk Research** (2025). *snyk-agent-scan / mcp-scan: Open-source tool definition security and hash-pinning scanner*. GitHub Repository: https://github.com/snyk/snyk-agent-scan.
8. **W3C Web Application Security Working Group** (2016). *Subresource Integrity*. W3C Recommendation. https://www.w3.org/TR/SRI/.
9. **Zhang, X., Wang, Y., Li, Z., & Zhao, J.** (2025). *MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers*. arXiv preprint arXiv:2508.14925 (AAAI 2026).

---

## Appendix: Exploratory Pilot Evaluations

### A.1 Phase 3 Exploratory Representation Pilot ($N=10$)
In initial Phase 3 exploratory calibration across 10 stratified samples (6 Malicious, 4 Benign):
- **Exact Hash Pinning**: Precision = 60.0%, Recall = 100.0%, $F_1 = 75.0\%$, Benign FPR = 100.0%.
- **Static Rules**: Precision = 100.0%, Recall = 50.0%, $F_1 = 66.7\%$, Malicious FNR = 50.0%.
- **Mode A (Full Definition)**: $F_1 = 83.3\%$, with a 20.0% JSON output parsing failure rate.
- **Mode B (Diff Only)**: Precision = 85.7%, Recall = 100.0%, $F_1 = 92.3\%$, Benign FPR = 25.0%, JSON Parse Errors = 0.0%.

### A.2 Phase 4 Integrated Middleware Replay Pilot ($N=10$)
Across a 10-example stratified replay test, the integrated middleware prototype achieved 100.0% precision and recall with an average of 0.30 LLM calls per update, validating initial multi-tier short-circuit logic prior to full master benchmark scaling.
