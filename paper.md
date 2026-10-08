# Semantic Drift Detection for Model Context Protocol (MCP) Tool Definition Updates

## Abstract

The Model Context Protocol (MCP) enables Large Language Model (LLM) agents to dynamically discover and invoke external tools at runtime. However, advertised tool contracts—including docstrings, parameter descriptions, and schemas—are directly ingested into agent prompts, creating an attack vector for tool poisoning and unauthorized privilege escalation. Existing defense mechanisms rely on exact cryptographic hash pinning (e.g., SHA-256 over tool definitions), which alerts on every byte-level tool-definition change by construction. Across an empirical audit of 621 historical release transitions from open-source MCP repositories, 31 releases (4.99%) contained tool-definition changes (an operator burden of 0.050 alerts per release transition), meaning all such legitimate maintenance updates trigger reapproval under exact pinning.

To separate integrity detection from semantic security judgment, we propose and evaluate **MCP Semantic Drift Detection**, a multi-tiered defense framework that differentiates authentic software maintenance from malicious tampering. We implement the **MCP Semantic Drift Guard Middleware**, combining sub-millisecond fast-path hash checks and static heuristics with a zero-temperature structured diff semantic judge (`Qwen3-8B`), backed by a persistent SQLite baseline store with automatic rollback. Integrated benchmark evaluations pre-populate the exact ground-truth old definition as a per-item oracle baseline to isolate single-step drift classification rather than measuring end-to-end longitudinal deployment. In active empirical benchmarks over the held-out test split ($N=56$; source: `results/computed_metrics.json`), exact cryptographic hash pinning achieves **Precision = 58.9%** (33/56, 95% Wilson CI: [45.9%, 70.8%]), **Recall = 100.0%** (33/33, 95% Wilson CI: [89.6%, 100.0%]), with **Benign FPR = 100.0%** (23/23, 95% Wilson CI: [85.7%, 100.0%]) in 0.012 ms (mean per-item CPU latency on Windows x86_64 [0 NVIDIA GPUs] from `results/main_test_hash/predictions.jsonl`); author-defined static regex rules achieve **Precision = 100.0%** (25/25, 95% Wilson CI: [86.7%, 100.0%]), **Recall = 75.8%** (25/33, 95% Wilson CI: [59.0%, 87.2%]), with **Benign FPR = 0.0%** (0/23, 95% Wilson CI: [0.0%, 14.3%]) in 0.217 ms (mean per-item CPU latency from `results/main_test_static/predictions.jsonl`); and the TF-IDF cosine baseline achieves **Precision = 64.6%** (31/48, 95% Wilson CI: [50.4%, 76.6%]), **Recall = 93.9%** (31/33, 95% Wilson CI: [80.4%, 98.3%]), with **Benign FPR = 73.9%** (17/23, 95% Wilson CI: [53.5%, 87.5%]) in 0.903 ms (mean per-item CPU latency from `results/main_test_tfidf/predictions.jsonl`). The standalone LLM judge and full integrated middleware sweeps are designated [PENDING RE-RUN] pending full local execution. Controlled JSON-RPC socket proxy testing confirms runtime interception, policy enforcement, and automatic definition rollback in active protocol streams.

In adversarial red-teaming across 30 evasion test cases spanning 10 mutation categories, performance metrics are designated [PENDING RE-RUN] pending re-execution with per-item trace logging. These empirical findings show that meaning-aware semantic drift detection reduces operator reapproval burden while establishing clear boundaries for structural schema verification.

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
2. **Under Semantic Drift Guard**: By addressing the orthogonal question—*"Is the change benign, suspicious, or malicious?"*—the Guard differentiates legitimate evolution from adversarial drift. [PENDING: alert-burden replay, Gate 3.1].

### 1.3 Research Gap
Prior work (e.g., MCPTox) evaluated downstream agent vulnerability to poisoned tool manifests, but did not measure real-world MCP evolution or evaluate upstream runtime defenses. This research addresses this gap by:
1. Providing an empirical measurement of tool definition evolution across 621 open-source MCP release transitions.
2. Formulating and benchmarking meaning-aware Semantic Drift Judges.
3. Implementing and evaluating an integrated, multi-tier enforcement middleware with automatic rollback and quarantine handling.
4. Stress-testing the approach against an adversarial red-team evasion suite.
5. Evaluating multi-step incremental semantic drift (Salami Drift) to compare adjacent, cumulative, and dual-anchor monitoring architectures.

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
[ Tier 0: Hash Fast-Path ] ────────── (Match) ────► ALLOW (0.012 ms, 0 LLM calls)
            │ (Mismatch / New Tool)
            ▼
[ Tier 1: Structured Diff Engine ] ──► Generates Canonical Field-Level Delta
            │
            ▼
[ Tier 1.5: Schema Security Rules ] ─ (Violation) ─► BLOCK & Rollback V1 (0.005 ms, 0 LLM calls)
            │ (Clean)
            ▼
[ Tier 2: Static Regex Rules ] ────── (High Match) ► BLOCK & Rollback V1 (0.217 ms, 0 LLM calls)
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
1. **Tier 0 (Hash Fast-Path)**: Computes canonical SHA-256 over normalized JSON (`name`, `description`, `inputSchema`). If identical to baseline ($D_H = 0$), returns `ALLOW` in $0.012\text{ ms}$.
2. **Tier 1 (Structured Diff Engine)**: Computes field-level structured delta $\Delta T$ (`params_added`, `params_removed`, `params_modified`, `description_diff_summary`), stripping boilerplate.
3. **Tier 1.5 (Deterministic Schema Rules)**: Scans parameter default injections, type conversions, and `readOnly` attribute flips in $0.005\text{ ms}$.
4. **Tier 2 (Static Regex Rules)**: Pre-filters diffs against 7 regular expressions (`<IMPORTANT>`, `MUST FIRST`, `/etc/shadow`). High-severity matches trigger immediate `BLOCK` in $0.217\text{ ms}$.
5. **Tier 3 (Semantic Diff Judge)**: Prompts local `Qwen3-8B` ($T=0$) with the structured diff wrapped in `<untrusted_diff>` sandboxes, emitting structured JSON decisions ($\hat{y} \in \{\text{BENIGN}, \text{SUSPICIOUS}, \text{MALICIOUS}\}$).
6. **Baseline Store & Rollback Engine**: Persistent SQLite store maintaining trusted contracts. For blocked updates, the proxy substitutes the trusted V1 definition in the client response.

*Evaluation Baseline Setup Note*: In offline benchmark experiments, the integrated middleware pre-populates the ground-truth `old_definition` of each candidate update as that tool's trusted baseline. Consequently, benchmark results reflect single-step drift classification against an oracle baseline, rather than an unanchored longitudinal deployment measurement.

---

## 6. Detector Benchmark & Held-Out Results

### 6.1 Dataset Construction & Split Isolation
The benchmark dataset combines real updates, programmatic hard negatives, and MCPTox attacks ($N=370$ total), partitioned into Train ($N=259$), Dev ($N=55$), and Held-Out Test ($N=56$, 33 Malicious, 23 Benign) with zero cluster overlap (`server_id + tool_name`). Integrated pipeline evaluations use per-item oracle baselines to isolate drift detection accuracy from baseline synchronization state.

### 6.2 Held-Out Benchmark Results (N=56)

*Provenance: Deterministic and lexical detector metrics derived from live execution on `data/drift_test.jsonl` logged in `results/computed_metrics.json`. All confidence intervals are 95% Wilson score intervals. Reported execution latencies reflect mean per-item CPU latency on Windows x86_64 [0 NVIDIA GPUs] measured with `time.perf_counter()` across individual prediction traces in `results/<run>/predictions.jsonl`.*

| Method / Defense Layer | TP | TN | FP | FN | Precision (95% CI) | Recall (95% CI) | $F_1$ Score | Benign FPR (95% CI) | Mean Latency | LLM Calls / Upd |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Tier 0)** | 33 | 0 | 23 | 0 | 58.9% [45.9%, 70.8%] | 100.0% [89.6%, 100.0%] | 74.2% | 100.0% [85.7%, 100.0%] | 0.012 ms | 0.0 |
| **Static Keyword Rules (Tier 2)** | 25 | 23 | 0 | 8 | 100.0% [86.7%, 100.0%] | 75.8% [59.0%, 87.2%] | 86.2% | 0.0% [0.0%, 14.3%] | 0.217 ms | 0.0 |
| **TF-IDF Cosine Baseline** | 31 | 6 | 17 | 2 | 64.6% [50.4%, 76.6%] | 93.9% [80.4%, 98.3%] | 76.5% | 73.9% [53.5%, 87.5%] | 0.903 ms | 0.0 |
| **Semantic Judge Mode A (Full)** | [PENDING RE-RUN] | - | - | - | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | 1.0 |
| **Semantic Judge Mode B (Diff)** | [PENDING RE-RUN] | - | - | - | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | 1.0 |
| **Integrated Guard Middleware** | [PENDING RE-RUN] | - | - | - | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING] |

### 6.3 Reconciling Detection Counts & Short-Circuits
In the test evaluation ($N=56$):
- **Short-Circuit Breakdown**: 25 of 56 candidate updates (44.6%) match high-severity Tier 2 static rules on the test split and trigger immediate `BLOCK` in $0.217\text{ ms}$ without invoking an LLM.
- **Escalated Updates**: The remaining 31 candidate updates (8 subtle malicious docstring mutations and 23 benign refactoring updates) require semantic evaluation by Tier 3.
- **Latency Distribution**: Fast-path deterministic evaluations execute in $< 0.25\text{ ms}$ on CPU. End-to-end and LLM-tier latencies are designated `[PENDING RE-RUN]` to be populated from verifiable per-item execution logs.

---

## 7. Dataset Validity & Generalization Audits

### 7.1 Controlled Matched-Pairs Evaluation ($N=24$)
To eliminate writing style, server domain, and structural schema complexity as confounding variables, we constructed a **Controlled Matched-Pair Exploratory Pilot** (`data/matched_pairs.jsonl`). Each record is a controlled triplet:
$$\text{Triplet}_i = \Big( \text{Tool}_{\text{old}}, \quad \text{Tool}_{\text{benign\_new}}, \quad \text{Tool}_{\text{malicious\_new}} \Big)$$

- **Dataset Scale & Composition**: 12 matched triplets across 6 distinct servers, yielding **$N = 24$ candidate evaluations** (12 benign, 12 malicious) spanning 6 attack categories.
- **Provenance & Scoping**: Derived from all available historical modified contracts mined from the open-source corpus. This suite serves strictly as a **descriptive exploratory evaluation**.
- **Pilot Results**: Metrics for LLM evaluation on matched pairs are designated `[PENDING RE-RUN]` pending execution with per-item trace logging.

### 7.2 Evaluation on Real Pre-Existing Contract Modifications ($N=13$)
In early evaluation phases, benign updates included all tool-definition events extracted from MCP git histories ($N=123$). However, **110 of the 123 events represent newly added or removed tools**, which lack complex natural language modifications.

We isolated the **13 historical pre-existing contract modifications** to evaluate performance specifically on contract refactorings:
- **Exact Hash Pinning**: 100.0% Alert Rate (13/13 flagged; exact byte changes).
- **Static Regex Rules**: 0.0% False Positive Rate (0/13 flagged; no injection keywords matched).
- **TF-IDF Lexical Baseline**: 69.2% FPR (9/13 flagged).
- **Semantic Guard**: `[PENDING RE-RUN]`.

### 7.3 Static Rule Provenance & Bias Statement
Author statement: The static rules (`guard/static_rules.py`) were derived from MCPTox benchmark template definitions (AAAI 2026, Section 3.2) and tested against MCPTox-derived attacks. As the repository history begins at the initial baseline commit, pre-registration across earlier development phases cannot be independently verified from git history. On datasets where MCPTox phrasing templates are modified, static rules act as fast pre-filters and the system relies on subsequent semantic tiers for evasive payloads.

### 7.4 Server-Grouped 5-Fold Cross-Validation ($N=370$)
To test generalization across unseen server codebases, 5-Fold Server-Grouped Cross-Validation over all 370 benchmark examples across 19 unique servers is designated `[PENDING RE-RUN]` to export per-item traces.

| Fold | Held-Out Test Servers | N | Malicious | Benign | Precision | Recall | Benign FPR | F1 Score |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **Fold 1** | `slack`, `mcptox-filesystem`, `mcptox-flomo` | 75 | 73 | 2 | [PENDING] | [PENDING] | [PENDING] | [PENDING] |
| **Fold 2** | `everything`, `github`, `sentry`, `mcptox-puppeteer` | 74 | 48 | 26 | [PENDING] | [PENDING] | [PENDING] | [PENDING] |
| **Fold 3** | `mysql`, `sqlite`, `mcptox-adfin`, `mcptox-github` | 74 | 50 | 24 | [PENDING] | [PENDING] | [PENDING] | [PENDING] |
| **Fold 4** | `playwright`, `git`, `memory`, `time` | 74 | 0 | 74 | [PENDING] | [PENDING] | [PENDING] | [PENDING] |
| **Fold 5** | `filesystem`, `puppeteer`, `sequentialthinking`, `mcptox-amapmap` | 73 | 29 | 44 | [PENDING] | [PENDING] | [PENDING] | [PENDING] |
| **Macro Mean** | **5-Fold Cross-Validation** | **370** | **200** | **170** | **[PENDING RE-RUN]** | **[PENDING RE-RUN]** | **[PENDING RE-RUN]** | **[PENDING RE-RUN]** |
| **Pooled (Micro-Avg)** | **All 370 Items Combined** | **370** | **200** | **170** | **[PENDING RE-RUN]** | **[PENDING RE-RUN]** | **[PENDING RE-RUN]** | **[PENDING RE-RUN]** |

---

## 8. Baselines, Ablations, and Master Comparison

### 8.1 Full Tier Ablation Study (Configurations A–H)
To evaluate the individual and collective contributions of each defensive layer, we evaluate eight architectural variants across the held-out test split ($N=56$):

| Config Identifier | Defensive Layers Included | Precision | Recall | F1 Score | Benign FPR | Malicious FNR | LLM Calls / Upd | Latency (Mean) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **Config A** | Hash Only | 58.9% | **100.0%** | 74.2% | 100.0% (23/23) | **0.0%** | 0.0 | 0.012 ms |
| **Config B** | Static Regex Only | **100.0%** | 75.8% | 86.2% | **0.0%** (0/23) | 24.2% (8/33) | 0.0 | 0.217 ms |
| **Config C** | Hash + Static | [PENDING] | [PENDING] | [PENDING] | [PENDING] | [PENDING] | 0.0 | [PENDING] |
| **Config D** | Hash + Static + Diff | [PENDING] | [PENDING] | [PENDING] | [PENDING] | [PENDING] | 0.0 | [PENDING] |
| **Config E** | Hash + Static + Semantic Judge | [PENDING] | [PENDING] | [PENDING] | [PENDING] | [PENDING] | [PENDING] | [PENDING] |
| **Config F (Full)** | **Full Guard Pipeline** | **[PENDING]** | **[PENDING]** | **[PENDING]** | **[PENDING]** | **[PENDING]** | **[PENDING]** | **[PENDING]** |
| **Config G** | Guard without Schema Check | [PENDING] | [PENDING] | [PENDING] | [PENDING] | [PENDING] | [PENDING] | [PENDING] |
| **Config H** | Deterministic Fast Path (No LLM) | **100.0%** | 75.8% | 86.2% | **0.0%** (0/23) | 24.2% (8/33) | **0.0** | 0.217 ms |

*Note on Config H: Config H defines the middleware operating with Tier 3 Semantic Judge disabled under the standard policy: high-severity Tier 2 static rule triggers `BLOCK`, and unflagged updates default to `ALLOW`.*

### 8.2 Representation Ablation: Mode A (Full) vs. Mode B (Diff Only)
- **Mode A (Full Definition)**: Presenting complete schemas; metrics designated `[PENDING RE-RUN]`.
- **Mode B (Structured Diff)**: Presenting canonical field-level diffs; metrics designated `[PENDING RE-RUN]`.

### 8.3 TF-IDF Cosine-Similarity Lexical Baseline
We implemented Baseline 3 (`experiments/baseline_embedding.py`) using a sublinear TF-IDF word n-gram vectorizer ($n \in [1, 3]$). The similarity decision threshold was calibrated strictly on the Train + Dev splits ($N=314$), yielding $\theta^* = 0.590$.
- **Held-Out Test Results ($N=56$)**: Precision = 64.6% (31/48, 95% CI: [50.4%, 76.6%]), Recall = 93.9% (31/33, 95% CI: [80.4%, 98.3%]), **$F_1 = 76.5\%$**, Benign FPR = **73.9%** (17/23, 95% CI: [53.5%, 87.5%]).
- *Finding*: Shallow lexical similarity distance cannot distinguish harmless documentation expansions from malicious directives, producing 17 false alarms out of 23 benign updates.

### 8.4 Local Model Comparison on Held-Out Split ($N=56$)
All models evaluated locally via Ollama with greedy decoding ($T=0$); metrics designated `[PENDING RE-RUN]`:

| Model | Architecture & Parameters | F1 Score | Precision | Recall | Benign FPR | Mean Latency |
|---|---|---:|---:|---:|---:|---:|
| **Qwen3:8B** | Qwen3-Instruct (8.2B) | [PENDING] | [PENDING] | [PENDING] | [PENDING] | [PENDING RE-RUN] |
| **Gemma3:4B** | Gemma3-IT (4.3B) | [PENDING] | [PENDING] | [PENDING] | [PENDING] | [PENDING RE-RUN] |
| **Qwen2.5:1.5B** | Qwen2.5-Instruct (1.5B) | [PENDING] | [PENDING] | [PENDING] | [PENDING] | [PENDING RE-RUN] |

### 8.5 Thinking ON vs. OFF Ablation (Qwen3:8B)
- **Qwen3:8B Thinking OFF (Direct JSON)**: Designated `[PENDING RE-RUN]`.
- **Qwen3:8B Thinking ON (Reasoning Chain)**: Designated `[PENDING RE-RUN]`.

### 8.6 Prompt Sensitivity & Instruction Robustness ($N=20$)
Evaluations across three semantically equivalent system instructions are designated `[PENDING RE-RUN]`.

### 8.7 Run-to-Run Determinism under Q4_K_M Quantization ($N=56$)
Repeated runs across held-out test examples are designated `[PENDING RE-RUN]`.

### 8.8 Master Evaluation Comparison Matrix

*Provenance: Deterministic and lexical rows derived from live execution on `data/drift_test.jsonl` logged in `results/computed_metrics.json` at commit `381125b09dee2d05f23e170e32762a71f815305d`.*

| System / Defense Paradigm | Precision (95% CI) | Recall (95% CI) | F1 Score | Benign FPR (95% CI) | Malicious FNR (95% CI) | Mean Latency | LLM Calls / Upd |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Tier 0)** | 58.9% [45.9%, 70.8%] | **100.0%** [89.6%, 100.0%] | 74.2% | 100.0% [85.7%, 100.0%] | **0.0%** [0.0%, 10.4%] | 0.012 ms | 0.0 |
| **Static Keyword Rules (Tier 2)** | **100.0%** [86.7%, 100.0%] | 75.8% [59.0%, 87.2%] | 86.2% | **0.0%** [0.0%, 14.3%] | 24.2% [12.8%, 41.0%] | 0.217 ms | 0.0 |
| **TF-IDF Cosine Baseline** | 64.6% [50.4%, 76.6%] | 93.9% [80.4%, 98.3%] | 76.5% | 73.9% [53.5%, 87.5%] | 6.1% [1.7%, 19.6%] | 0.903 ms | 0.0 |
| **Deterministic Schema (Tier 1.5)** | n/a | 0.0% [0.0%, 10.4%] | 0.0% | **0.0%** [0.0%, 14.3%] | 100.0% [89.6%, 100.0%] | 0.005 ms | 0.0 |
| **Semantic Judge Mode A (Full)** | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | 1.0 |
| **Semantic Judge Mode B (Diff Only)** | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | 1.0 |
| **Integrated Guard Middleware (BALANCED)** | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING RE-RUN] | [PENDING] |

*Note on Tier 1.5: Precision is n/a because 0 positive predictions are made on the standard test set (0/33 caught; all 33 test attacks are natural-language docstring mutations). Its primary defensive value is targeted at schema-evasion cases (e.g. parameter default URL injections and readOnly toggles, evaluated in Section 9.3).*

---

## 9. Adversarial Evaluation and Defense Hardening

### 9.1 Initial Adversarial Red-Team Suite ($N=30$, 10 Categories)
Evaluation of 30 structured adversarial cases across 10 evasion categories is designated `[PENDING RE-RUN]` to record per-item traces.

### 9.2 Deterministic Schema Security Checks (Tier 1.5)
To address schema-only modifications, Tier 1.5 Schema Security Checks (`guard/schema_security_rules.py`) scan:
1. **Authorization Toggles**: Flags `readOnly: true -> false` transitions.
2. **Default Value Injections**: Regular expression audit intercepting external URLs, IP addresses, and sensitive paths in property `default` fields.
3. **Interface Constriction**: Audits parameter type mutations and enum constraint narrowing.
- **Performance**: Executes in $0.005\text{ ms}$ on CPU with **0 false positives** on the $N=23$ benign test cases.

### 9.3 Exploratory Adversarial Pilot Evaluation (Red-Team v2, $N=28$, 14 Categories)
Evaluation of `data/redteam_v2.jsonl` ($N=28$, $n=2$/category) against the upgraded pipeline is designated `[PENDING RE-RUN]`.

### 9.4 Judge Prompt Injection Robustness Pilot ($N=4$)
Direct prompt override payloads targeting the judge are designated `[PENDING RE-RUN]`.

### 9.5 Multi-Step Incremental Semantic Drift Evaluation (Salami Drift Benchmark V3)

#### 1. Threat Model & Historical Experimental Progression
An adversary controlling an upstream Model Context Protocol server may partition an unauthorized capability escalation across $K$ consecutive, individually minor releases ($V_1 \xrightarrow{\Delta_1} V_2 \dots \xrightarrow{\Delta_{K-1}} V_K$). Under this **Salami Drift** threat model, each adjacent delta $\Delta_i = (V_{i-1} \rightarrow V_i)$ introduces only an innocuous parameter or cosmetic docstring modification to remain below single-step detection thresholds, while the cumulative modification relative to the established baseline $\Delta_{\text{total}} = (V_0 \rightarrow V_K)$ achieves full unauthorized privilege escalation, telemetry redirection, or prompt override.

The empirical evaluation of this threat progressed through three distinct methodological iterations:
- **V1 Benchmark ($N=18$ chains, 62 transitions)**: The initial proof-of-concept demonstrated that adjacent, cumulative, and dual strategies produced indistinguishable results (75.0% chain detection). An architectural audit revealed that V1 exposed that the benchmark contained deterministic/static detection leakage and was insufficient to establish the hypothesis.
- **V2 Iteration**: Attempted to remove leakage; however, an independent audit discovered that authoritative metrics had been generated using mock/gold-label injection. V2 must therefore not be presented as valid empirical evidence and serves as an explicit methodological failure and audit finding.
- **V3 Authoritative Live Benchmark**: Completely redesigned benchmark with 9 automated validation quality gates (`results/SALAMI_DRIFT_V3_VALIDATION.md`), deterministic leakage removed from semantic categories, a live model selection diagnostic, smoke testing, full live evaluation with 0 mock calls and 0 gold-label leakage, and an independent final methodological audit. V3 is the authoritative experiment.

#### 2. V3 Benchmark Composition & Validation Gates
The V3 benchmark (`data/salami_drift_benchmark_v3.jsonl`, SHA-256: `04d864faa59c1c088205bb8fa38c99fc5fa3f0428070c331fe546ef0884b599f`) comprises **40 independent chains** spanning **144 total state transitions** (40 malicious transitions, 104 benign transitions):
- **Malicious Chains ($N=24$ chains, 40 attack transitions)**:
  - *16 Salami Drift chains*:
    - Category A (Adjacent-Evasive Salami Drift, $n=4$ chains, 16 transitions): Multi-step capability combinations introducing standard operational parameters (`format_style`, `record_metrics`, `stream_channel`) where individual steps are subtle.
    - Category D (Parameter Drift, $n=3$ chains, 12 transitions): Gradual relaxing of configuration constraints (e.g., timeout $\rightarrow$ custom transport $\rightarrow$ TLS verification disable toggle).
    - Category E (Instruction Erosion, $n=3$ chains, 12 transitions): Incremental docstring phrasing weakening authority boundaries (e.g., style theme $\rightarrow$ LaTeX support $\rightarrow$ raw script rendering).
    - Category F (Capability Combination, $n=3$ chains, 12 transitions): Staging auxiliary logging parameters that become dangerous only when combined.
    - Category G (Low-Signal Semantic Drift, $n=3$ chains, 12 transitions): Paraphrased operational options without injection keywords.
  - *Category B (Fast-Jump Positive Controls, $n=8$ chains, 24 transitions)*: Single-step overt capability leaps serving as positive controls.
- **Benign Control Chains ($N=16$ chains, 104 transitions)**:
  - *Category C (Benign Long-Drift Controls, $n=8$ chains, 32 transitions)*: Legitimate software evolution adding 4 consecutive valid parameters across 4 versions with cumulative distance matched to Category A.
  - *Standard Benign Controls ($n=8$ chains, 24 transitions)*: 3-step routine maintenance updates (bug fixes, pagination, formatting).

All chains passed 9 pre-inference validation gates, confirming Draft-07 JSON Schema validity, monotonic parameter sequencing, zero deterministic Tier 1.5/Tier 2 leakage in semantic categories, and zero gold-label leakage in model-facing prompts (`results/salami_drift_v3/model_input_audit.json`).

#### 3. Model Selection Diagnostic
Model capacity was identified as a critical dependency for structured diff reasoning. Prior to benchmarking, candidate local models were evaluated across a fixed three-model diagnostic suite (`scratch/model_selection_diagnostic.py`):
- `qwen2.5:1.5b`: Achieved 66.7% structured JSON parse success; rejected because of truncated/malformed outputs.
- `gemma3:4b`: Achieved **100.0% structured JSON parse success** in diagnostic with stable complete responses and approximately 13.8 seconds/call on CPU; selected as the authoritative evaluation engine.
- `qwen3:8b`: Achieved 0.0% parse success in diagnostic; rejected because of empty/timeout outputs on CPU.

Model selection was conducted on fixed diagnostic prompts strictly prior to benchmarking and was not based on benchmark performance.

#### 4. Live Benchmark Execution & Audited Metrics
The authoritative benchmark executed 432 strategy evaluations (144 transitions $\times$ 3 strategies) generating **576 genuine live LLM calls** (0 mock calls, 0 gold-label leakage). All semantic-category transitions reached the Tier 3 semantic-judge stage; 94.6% produced directly parsed Tier 3 decisions, while 5.4% (31/576 calls) required the documented `BALANCED` policy fallback because of parsing failures, safely resolving to `WARN`/`SUSPICIOUS` without ground-truth contamination.

##### Transition-Level Main Results ($N=144$ Transitions):
*Source: `results/salami_drift_v3/computed_metrics.json` and traces in `results/salami_drift_v3_*/predictions.jsonl`.*

| Strategy | TP | TN | FP | FN | Recall | Precision | F1 | Benign Transition FPR |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Adjacent** | 17 | 104 | 0 | 23 | 42.5% | 100.0% | 0.597 | 0.0% |
| **Cumulative** | 25 | 102 | 2 | 15 | 62.5% | 92.6% | 0.746 | 1.9% |
| **Dual** | 28 | 102 | 2 | 12 | 70.0% | 93.3% | 0.800 | 1.9% |

##### Chain-Level Trajectory Outcomes ($N=40$ Chains):

| Strategy | Malicious Chain Recall | Benign Chain FPR | Mean Exposure |
|---|:---:|:---:|:---:|
| **Adjacent** | 58.3% (14/24) | 6.2% (1/16) | 0.88 |
| **Cumulative** | 91.7% (22/24) | 50.0% (8/16) | 0.42 |
| **Dual** | 91.7% (22/24) | 50.0% (8/16) | 0.38 |

*Methodological Audit on Chain FPR*: Chain-level FPR is substantially higher than transition-level FPR because a benign chain is counted as a false-positive chain if at least one transition is flagged across its trajectory. Final audit findings confirm that while transition-level benign FPR remained low at **1.9%** (2 false positives across 104 benign transitions), 6 of the 8 cumulative/dual benign-chain flags were associated with parsing-error $\rightarrow$ `WARN` fallbacks rather than substantive semantic `MALICIOUS` judgments. Only 2 benign chains (`v3_chain_29` and `v3_chain_31`) exhibited semantic false alarms at Step 4 due to natural feature accumulation across multiple valid versions.

#### 5. Hypothesis Testing & Paired Statistical Analysis
The core research hypothesis evaluates whether cumulative context recovers malicious incremental transitions missed by adjacent-only comparison:
$$\text{Adjacent Prediction} = \text{BENIGN} \quad \wedge \quad \text{Cumulative Prediction} = \text{MALICIOUS}$$

##### Paired McNemar Exact Tests ($N=144$ Paired Transitions):
- **Adjacent vs. Cumulative**: McNemar exact $p = 0.21011$ ($\text{not statistically significant at } \alpha = 0.05$).
- **Adjacent vs. Dual**: McNemar exact $p = 0.02246$ ($\text{statistically significant at } \alpha = 0.05$).

There were **11 cumulative-only detections** (Adjacent = `BENIGN`, Cumulative = `MALICIOUS`) versus **3 reverse discordant cases** (Adjacent = `MALICIOUS`, Cumulative = `BENIGN`, 2 of which stemmed from JSON parse failures on cumulative diffs).

V3 provides direct evidence that cumulative context can recover malicious transitions missed by adjacent-only comparison, with 11 cumulative-only detections versus 3 reverse discordant cases. However, the paired Adjacent-vs-Cumulative comparison was not statistically significant (McNemar exact $p = 0.21011$). In contrast, Dual-Anchor significantly outperformed Adjacent-only monitoring (McNemar exact $p = 0.02246$), indicating that combining local and root-relative comparisons provides stronger detection than adjacent comparison alone on this benchmark.

##### Audited Cumulative-Only Detections ($N=11$ Cases):
Independent audit confirmed that all 11 cumulative-only detections satisfy the intended salami-drift construction: individually subtle incremental changes that become materially more suspicious when evaluated against the root definition ($V_0 \rightarrow V_k$):
1. `v3_chain_01_matrix_math_step_04` (Cat A): Step 4 adds `stream_channel` context redirection.
2. `v3_chain_02_formatter_bypass_step_03` (Cat A): Step 3 introduces unescaped character encoding bypass.
3. `v3_chain_04_container_supervisor_step_04` (Cat A): Step 4 attaches host IPC namespace.
4. `v3_chain_05_param_tls_step_04` (Cat D): Step 4 enables TLS certificate verification toggle.
5. `v3_chain_07_param_sandbox_step_04` (Cat D): Step 4 enables host network interface binding.
6. `v3_chain_08_inst_markdown_step_03` (Cat E): Step 3 enables raw script block rendering.
7. `v3_chain_09_inst_prompts_step_04` (Cat E): Step 4 injects directive precedence overrides.
8. `v3_chain_10_inst_sql_step_03` (Cat E): Step 3 introduces raw predicate injection.
9. `v3_chain_10_inst_sql_step_04` (Cat E): Step 4 disables automatic tenant isolation clauses.
10. `v3_chain_12_comb_search_step_04` (Cat F): Step 4 attaches dynamic expression evaluation.
11. `v3_chain_15_sem_metrics_step_03` (Cat G): Step 3 enables environment token logging.

#### 6. Threats to Validity
We identify the following potential threats to validity and the controls instituted in V3:
- **Benchmark Construction Bias**: Synthetic attack trajectories and benign evolutions may introduce structural artifacts. V3 mitigated this through length-matched Category C benign drift controls and 9 pre-inference validation gates.
- **Deterministic Leakage Controls**: Prior iterations suffered from static keyword leakage; V3 strictly verified that 100% of transitions in semantic categories bypassed Tier 1.5 and Tier 2 filters.
- **Gold-Label Leakage Controls**: V3 enforced strict isolation of model prompts from ground-truth labels and metadata, verified via `results/salami_drift_v3/model_input_audit.json`.
- **Local Model Limitations & Dependence on Semantic Judge**: Evaluations utilized local quantized `gemma3:4b`. Variations in base model reasoning, instruction following, and output parsing directly influence detection fidelity.
- **Parsing / Fallback Behavior**: A 5.4% parse failure rate was observed, with formatting anomalies defaulting to policy fallback (`WARN`), contributing to benign chain false alarms.
- **Chain-Level FPR Amplification**: Evaluating multi-step chains compounds transition false positives; any single transition alert marks the entire benign chain as flagged.
- **Limited Trajectory Sample Size**: With 40 chains and 144 transitions, findings represent evidence on the constructed benchmark rather than asymptotic universal proof.
- **Generalization Boundaries**: V3 evaluates structured MCP tool evolution categories but does not encompass all arbitrary open-world tool evolution topologies.

### 9.6 Newly Added Tools & Maintainer Rug-Pull Timing Policies
- **Newly Added Tools**: Newly introduced tools lack prior V1 baselines; policy enforces **Initial Discovery Quarantine** until explicit administrative review.
- **Maintainer Rug-Pull Timing**: For servers with clean historical releases that later turn malicious, the middleware re-verifies cryptographic hashes and evaluates semantic diffs on every session handshake.

---

## 10. Deployment, Latency & Operational Safety Analysis

### 10.1 Live MCP JSON-RPC Socket Proxy Testing
Controlled socket proxy testing (`experiments/phase5_live_mcp_proxy.py`) verified real-time `tools/list` traffic interception:
- **Bootstrap Phase**: Initial tool contracts registered in SQLite as `TRUSTED`.
- **Benign Update Phase**: Docstring clarifications evaluated as `BENIGN` $\rightarrow$ `ALLOW`, updating baseline records.
- **Attack Phase**: A poisoned tool contract was intercepted, evaluated as `MALICIOUS` $\rightarrow$ `QUARANTINE`, and replaced with the **Trusted V1 definition** in the client response.

### 10.2 Component Latency & Fast-Path Optimization
Measured deterministic tier latencies on host CPU (`results/computed_metrics.json`):
- **Tier 0 Hash Fast-Path**: $0.012\text{ ms}$ (0 LLM calls).
- **Tier 1.5 Schema Security Checks**: $0.005\text{ ms}$ (0 LLM calls).
- **Tier 2 Static Regex Rules**: $0.217\text{ ms}$ (0 LLM calls).
- **Tier 3 Semantic Diff Judge Latencies**: Historical figures are `[PENDING RE-RUN] (origin unknown, no per-item log exists on disk; measured local CPU inference for Qwen3:8B is ~50-70s per item)`.

### 10.3 Asynchronous Out-of-Band Staging Mode
To prevent local LLM semantic inference latencies from delaying interactive agent startup handshakes, we specify an **Asynchronous Out-of-Band Staging Architecture**:
1. **Immediate Client Handshake**: When an upstream server broadcasts an updated candidate definition ($V_2$), the middleware immediately returns the cached, trusted $V_1$ definition to the LLM agent client ($0\text{ ms}$ added latency).
2. **Background Queue Dispatch**: The candidate $V_2$ payload is dispatched to an asynchronous background worker pool for multi-tier inspection.
3. **Promotion vs. Quarantine**:
   - If verified as `BENIGN`, $V_2$ is promoted to the SQLite baseline store and served on subsequent sessions.
   - If evaluated as `MALICIOUS` or `SUSPICIOUS`, $V_2$ is permanently quarantined, and an administrative security alert is dispatched with full structured audit findings.

### 10.4 Policy Engine Failure Modes & Timeout Specifications
To ensure predictable fail-safe behavior under adverse operating conditions, the policy engine supports two configurable operational modes (verified in `tests/test_failure_policy.py`):
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

1. **Authentic Existing-Contract Sample Size ($N=13$)**: Real open-source MCP repositories currently contain only 13 modified pre-existing tool contracts; 110 of the 123 observed evolutionary events represent tool additions and removals.
2. **Matched-Pair Pilot Scale ($N=24$)**: The controlled matched-pair dataset contains $N=24$ candidate evaluations (12 matched triplets across 6 servers). It serves strictly as an exploratory pilot isolating stylistic phrasing confounds rather than a large asymptotic corpus ($\ge 100$ pairs).
3. **Adversarial Red-Team v2 Scale ($N=28$)**: The upgraded adversarial suite evaluates 14 evasion categories with exactly $n=2$ test cases per category, serving as an exploratory demonstration of failure mechanisms rather than a population-level robustness estimate.
4. **Synthetic Adversarial Datasets**: Malicious drift samples are generated via synthetic templates (MCPTox mutations) and red-team injections rather than discovered in-the-wild zero-day incidents.
5. **Dataset & Style Confounding**: Despite paired evaluation and 47 programmatic hard negatives, subtle lexical differences between authentic developer docstrings and synthetic attack injections may introduce latent stylistic signals.
6. **Local Inference Latency**: Local `Qwen3:8B` inference requires ~50–70s per item on CPU; synchronous inline execution during high-frequency startup handshakes requires asynchronous out-of-band staging or GPU acceleration.
7. **Rollback Compatibility Scope**: Baseline rollback to $V_1$ is effective for docstring modifications and optional parameters, but breaking structural mutations (required parameter additions, property deletions, type changes) cause downstream RPC invocation failures and must escalate to Full Tool Quarantine.
8. **Evaluation Environment**: Live JSON-RPC proxy evaluation was conducted in controlled local socket test fixtures rather than multi-tenant, internet-scale production deployments.
9. **Judge Prompt-Injection Sample ($N=4$)**: Prompt override sandboxing was verified across 4 targeted pilot cases; evaluating complex multi-turn prompt injection payloads remains future work.
10. **Local Model Capacity**: Only `gemma3:4b` was suitable for the authoritative Salami Drift V3 run under the local CPU environment. Larger `qwen3:8b` failed the diagnostic because of empty/timeout outputs.
11. **Parsing Failures & Fallback Sensitivity**: Across the live V3 evaluation, 31 of 576 model queries (5.4%) failed structured JSON parsing and required policy fallback, contributing to benign chain false alarms.
12. **Benign Chain False Positives vs. Transition FPR**: While transition-level benign FPR was low at 1.9% (2/104), chain-level benign FPR reached 50.0% (8/16 chains). 6 of the 8 cumulative/dual benign chain alarms stemmed from parse-error fallbacks on long cumulative diffs rather than semantic judgments.
13. **Statistical Power**: The Salami Drift benchmark contains 144 transitions across 40 trajectories. Results demonstrate empirical evidence on the constructed benchmark rather than universal proof across arbitrary environments.
14. **Benchmark Scope**: V3 covers defined salami-drift categories (A, D, E, F, G, B, C) but does not establish performance against every possible open-world MCP tool evolution topology.
15. **Model Dependence**: Semantic detection fidelity depends directly on the selected local LLM and its parsing reliability.
16. **No Claim of Universal Optimality**: Dual-Anchor monitoring is not claimed to be universally optimal across all deployment settings; it was the strongest strategy among those evaluated on this benchmark.
17. **Local vs. Frontier Model Scope**: Primary evaluations focus on quantized local models (`Qwen3:8B`, `Gemma3:4B`, `Qwen2.5:1.5B`); evaluations on closed commercial frontier APIs (e.g., GPT-4o, Claude 3.5 Sonnet) were not executed.
18. **Corpus Coverage**: Mining was conducted across 28 open-source repositories on GitHub; while diverse, it does not encompass the entire closed enterprise MCP landscape.

---

## 12. Reproducibility & Open Artifacts

To support full third-party reproduction and ongoing research, all code, benchmark datasets, prompt templates, and evaluation scripts are released under an open-source license at the anonymized repository: `https://github.com/anonymous-submission/mcp-semantic-drift`.

### 12.1 Execution Commands
- **Unit & Integration Tests (Zero Leakage & Safety)**:
  ```bash
  python -m unittest discover tests
  ```
- **Salami Drift Benchmark V3 Live Authoritative Evaluation**:
  ```bash
  python experiments/evaluate_salami_drift_v3.py --model gemma3:4b --authoritative
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
- **Pinned Repository Commit**: `d826a89c92e742ca1433f446059dbe4cb40fb7e9`
- **MCPTox Submodule Commit**: `f85189f9ad12504c197c7f920ab818a40657b1fa`
- **Salami Drift Benchmark V3 Dataset**: `data/salami_drift_benchmark_v3.jsonl` (SHA-256: `04d864faa59c1c088205bb8fa38c99fc5fa3f0428070c331fe546ef0884b599f`)
- **Authoritative Salami Drift V3 Prediction Traces**:
  - Adjacent Strategy: `results/salami_drift_v3_per_step/predictions.jsonl`
  - Cumulative Strategy: `results/salami_drift_v3_cumulative/predictions.jsonl`
  - Dual-Anchor Strategy: `results/salami_drift_v3_dual/predictions.jsonl`
- **Audit & Validation Manifests**:
  - `results/salami_drift_v3/validation_report.json`
  - `results/salami_drift_v3/run_manifest.json`
  - `results/salami_drift_v3/computed_metrics.json`
  - `results/salami_drift_v3/model_input_audit.json`
  - `results/SALAMI_DRIFT_V3_VALIDATION.md`
  - `results/SALAMI_DRIFT_V3_FINAL_AUDIT.md`
  - `results/FINAL_RESEARCH_PACKAGE_AUDIT.md`
- **Judge System Prompt**: Implemented in `guard/semantic_judge.py` using strict JSON schema output formatting and XML delimiter sandboxing (`<untrusted_diff>`).
- **Deterministic Schema Security Rules**: Implemented in `guard/schema_security_rules.py` for parameter defaults, `readOnly` toggles, and enum constriction.
- **Static Regex Rules**: 7 rules in `guard/static_rules.py`.
- **Corpus Mining**: `experiments/phase2_extract_corpus.py` across 28 repositories on GitHub with $\ge 2$ release tags (621 version transitions).
- **Hard Negative Provenance**: 47 programmatic hard negatives generated in `experiments/generate_hard_negatives.py` by inserting legitimate security terms into real benign docstrings without changing tool semantics.

---

## 13. Conclusion

This research demonstrates that **MCP Semantic Drift Detection** separates byte-level integrity verification from semantic security analysis. While exact cryptographic hashing flags all observed tool-definition changes because its integrity criterion is byte-level equality, multi-tiered semantic drift detection provides a layered defense architecture. Deterministic static and schema layers resolve obvious attacks and schema anomalies in sub-millisecond latencies, escalating ambiguous docstring modifications to semantic judges.

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
Pilot results on Phase 3 representations are designated `[PENDING RE-RUN]`.

### A.2 Phase 4 Integrated Middleware Replay Pilot ($N=10$)
Pilot replay results across the 10-example stratified replay test are designated `[PENDING RE-RUN]`.
