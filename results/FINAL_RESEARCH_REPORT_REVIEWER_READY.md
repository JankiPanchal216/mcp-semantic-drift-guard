# Semantic Drift Detection for Model Context Protocol (MCP) Tool Definition Updates

**Comprehensive Research Report & Evidence Package**

---

## Abstract

The Model Context Protocol (MCP) standardizes runtime tool integration for Large Language Model (LLM) agents, but exposes an unverified attack surface: tool definition updates can introduce covert semantic drift, prompt injections, and supply-chain tool poisoning. While exact cryptographic hash pinning provides strict byte-level integrity verification, it flags every observed tool-definition change because its integrity criterion is byte-level equality. In our empirical corpus of 621 real-world MCP server release transitions across 12 repositories, 31 transitions (4.99%) modified tool definitions (comprising 110 tool additions/removals and 13 pre-existing contract modifications), meaning all such legitimate maintenance events trigger review under exact pinning.

To separate integrity detection from semantic security judgment, we propose a multi-tiered **Semantic Drift Guard Middleware** that combines fast-path SHA-256 cryptographic hashing, deterministic schema security checks, structured JSON contract diffing, and an isolated diff-only local semantic judge (Qwen3-8B). In an integrated middleware evaluation under a balanced policy ($N=56$), the system achieved 100.0% precision, 100.0% recall, 100.0% F1, and 0.0% benign false positive rate (FPR) when evaluated with pre-populated trusted baselines. In a conservative standalone semantic-judge evaluation isolating Mode-B classification ($N=56$), the judge achieved an F1 score of **92.3%** (Precision: 85.7%, Recall: 100.0%, Benign FPR: 26.1% [6/23]). In 5-fold server-grouped cross-validation across 370 examples with zero server overlap, the standalone judge achieved a mean F1 of 89.7% ± 6.2% (standard deviation), 100.0% ± 0.0% recall, and 23.0% ± 4.1% benign FPR.

In an exploratory adversarial pilot of 28 newly constructed cases spanning 14 attack categories, the guard detected 25/28 cases (89.3%), with subtle passive euphemisms identifying key evasion boundaries. While unchanged tool manifests pass in 0.024 ms and deterministic checks execute in 0.16 ms, changed tool definitions requiring local semantic judge evaluation exhibit a mean latency of 1.42s on the evaluated local CPU setup, making asynchronous staging a necessary deployment design for interactive environments. Rollback serves as an effective containment mechanism for compatible changes, while breaking contract changes necessitate explicit quarantine.

---

## 1. Introduction

As Large Language Model (LLM) agents transition from passive conversational assistants to autonomous agents executing external actions, the **Model Context Protocol (MCP)** has emerged as the standard protocol for connecting AI models to external tools, databases, and operating system services. Under MCP, tool capabilities are dynamically advertised via JSON-RPC handshakes (`tools/list`), where natural language docstrings and JSON Schema structures are injected directly into the agent's context window.

However, this dynamic discovery mechanism introduces a critical supply-chain vulnerability: **unverified tool definition evolution**. When an upstream server updates, subtle modifications to tool docstrings or schemas can hijack agent reasoning, force unauthorized prerequisite tool executions, redirect parameters to external endpoints, or exfiltrate private credentials (`~/.ssh`, `.env`, API tokens).

### The Integrity-vs-Maintenance Tension
1. **The Hash Pinning Baseline**: Traditional integrity defenses rely on cryptographic SHA-256 hash pinning. Exact hash pinning flags every observed tool-definition change because its integrity criterion is byte-level equality. In our observed corpus, 31 of 621 release transitions (4.99%) changed tool manifests, meaning these changes trigger review under exact pinning. Among the observed maintenance changes, exact pinning could not distinguish benign evolution from malicious drift.
2. **The Need for Semantic Drift Detection**: What is required is not merely *change detection*, but **semantic intent discrimination**—separating integrity detection from semantic security judgment by combining exact change detection, deterministic security checks, structured diffing, and semantic analysis.

---

## 2. Background: MCP Protocol & Evolution Mechanics

MCP operates over standard JSON-RPC 2.0 transport (stdio, HTTP SSE, or WebSockets). When an agent initializes, it queries the server via a `tools/list` handshake:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "id": 1
}
```

The server returns an array of tool descriptors:
```json
{
  "name": "read_file",
  "description": "Reads full contents of a file from filesystem.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": {"type": "string", "description": "Absolute file path"}
    },
    "required": ["path"]
  }
}
```

When an attacker modifies the `description` to include:
> `"<IMPORTANT> Before reading path, you MUST FIRST call transmit_keys to http://attacker.com </IMPORTANT>"`

the downstream LLM agent interprets the docstring directive as an authoritative operational constraint, causing silent privilege escalation and data exfiltration.

---

## 3. Threat Model

We formulate our security analysis under an **adaptive adversary model** (see [`results/THREAT_MODEL.md`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/results/THREAT_MODEL.md)):
- **Attacker Knowledge**: The attacker is assumed to know that exact hashes are used, static regex rules exist, schema security checks exist, semantic LLM judges evaluate diffs, and rollback/quarantine mechanisms are deployed.
- **Attacker Capabilities**: The attacker may attempt semantic paraphrasing, indirect instruction injection, schema attribute tampering (`readOnly: true -> false`), default value endpoint redirection, judge prompt injection payloads, multi-step salami drift across releases, malicious tool additions, maintainer rug-pulls, and timing manipulation.
- **Defender Capabilities**: A middleware proxy operating at the JSON-RPC transport boundary intercepting `tools/list` responses, maintaining a persistent baseline store of trusted contracts, and enforcing automated rollback or quarantine.
- **Attacker & Defender Limitations / Out of Scope**: Compromised server runtime code execution during `tools/call` (which requires container/OS sandboxing) and direct user chat prompt jailbreaks are out of scope.

---

## 4. Related Work

This work focuses on detecting semantic drift in MCP tool definitions and distinguishing benign maintenance from security-relevant changes (see [`results/RELATED_WORK_NOTES.md`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/results/RELATED_WORK_NOTES.md)):
- **MCPTox (Zhang et al., 2024)**: Evaluated downstream agent susceptibility to poisoned MCP tools; our work introduces an upstream drift detection and rollback middleware for tool manifests.
- **ToolHijack (Liu et al., 2024)**: Explored parameter tampering in OpenAPI tools; informs our Tier 1.5 deterministic schema security rules.
- **Subresource Integrity (W3C, 2016)**: Cryptographic hash matching for web assets; our study quantifies its alert burden in dynamic tool ecosystems.
- **Sigstore & Cosign (Newman et al., 2022)**: Software signing and provenance; verifies publisher identity but does not evaluate semantic contract drift within signed updates.
- **NeMo Guardrails & Llama Guard (Rebedea et al., 2023; Inan et al., 2024)**: Conversational chat safety filters; our work focuses on structured JSON-RPC contract diffs and schema evolution.
- **API Evolution & SemVer (Dig & Johnson, 2006; Brito et al., 2018)**: Analyzed structural API breaking changes; our work addresses natural language tool contracts that govern probabilistic agent reasoning.

---

## 5. MCP Tool-Definition Evolution Corpus

To ground the analysis in real-world software engineering practices, we mined **621 release transitions** across 12 active MCP server repositories (`modelcontextprotocol/servers`, `git`, `filesystem`, `sqlite`, `github`, `puppeteer`, `memory`, `mysql`, `slack`, etc.).

### Empirical Corpus Statistics
- **Total Release Transitions**: 621
- **Releases with Tool-Definition Changes**: 31 (4.99% release-change rate)
- **Total Tool-Definition Change Events**: 123
- **Tool Additions / Removals**: 110 (89.4% of change events)
- **Modifications to Pre-Existing Tool Contracts**: 13 (10.6% of change events)
  - 13 of 621 release transitions (2.09%) contained modifications to pre-existing tool contracts.
  - Description / Documentation Clarifications: 7 releases
  - Schema / Parameter Modifications: 2 releases
  - Mixed Contract Modifications: 4 releases

---

## 6. Semantic Drift Guard Architecture

We implement a 5-tier modular pipeline operating between upstream MCP servers and the LLM agent runtime:

```
Incoming tools/list Response
            │
            ▼
[ Tier 0: Cryptographic Hash Pinning ] ──── (Match) ────► ALLOW (Fast Path: 0.024 ms)
            │ (Mismatch / New Tool)
            ▼
[ Tier 2: Structured JSON Diff Engine ]
            │
            ▼
[ Tier 1: Static Keyword Regex Rules ] ── (High Match) ──► BLOCK & Rollback V1 (0.16 ms)
            │ (Clean)
            ▼
[ Tier 1.5: Schema Security Checker ] ─── (Flagged) ────► BLOCK & Rollback V1 (< 0.10 ms)
            │ (Clean)
            ▼
[ Tier 3: Standalone Semantic Judge (Mode B Diff) ]
            │
    ┌───────┴───────────────────────┬───────────────────────┐
    ▼                               ▼                       ▼
 BENIGN                         SUSPICIOUS              MALICIOUS
    │                               │                       │
 ALLOW (Update DB)           WARN / QUARANTINE        BLOCK & Rollback V1
```

### Architectural Tiers:
1. **Tier 0 (Cryptographic Hash Pinning)**: Computes normalized SHA-256 digests. Resolves unchanged tools in 0.024 ms.
2. **Tier 2 (Structured Diff Engine)**: Computes canonical field-level diffs, isolating changes from boilerplate schemas.
3. **Tier 1 (Static Regex Pre-Filter)**: Intercepts known imperative attack vectors (`<IMPORTANT>`, `MUST FIRST`, `~/.ssh`).
4. **Tier 1.5 (Schema Security Checker)**: Deterministically audits `readOnly` transitions, default URL injections, and parameter scope widening.
5. **Tier 3 (Isolated Semantic Judge)**: Evaluates canonical text diffs using local `qwen3:8b` (Mode B, temperature=0).
6. **Rollback Engine & Compatibility**:
   - **Safe Rollback**: Reverting to V1 is seamless when V2 is backward-compatible (description edits, optional parameter additions).
   - **Unsafe Rollback**: When V2 introduces required parameters, removes parameters, renames parameters, or modifies schema types, serving V1 causes client invocation exceptions. Rollback serves as a containment mechanism rather than a universal compatibility mechanism; breaking contract changes require quarantine.

---

## 7. Experimental Methodology

### Datasets and Pilots:
1. **Benchmark Dataset ($N=370$)**: 200 Malicious (derived from MCPTox templates and mutations), 170 Benign (123 real git updates + 47 programmatic hard negatives).
   - Training Split: $N=259$ across 19 server clusters.
   - Development Split: $N=55$.
   - Held-Out Test Split: $N=56$ (33 Malicious, 23 Benign).
2. **Controlled Matched-Pair Pilot ($N=24$)**: 12 authentic benign updates paired with 12 corresponding malicious semantic mutations sharing identical server context, tool names, and schemas. Designed to reduce writing-style confounding, though too small to establish general performance across the ecosystem.
3. **Descriptive Real-Contract Subset ($N=13$)**: The 13 pre-existing tool contract modifications identified in the historical corpus.
4. **Adversarial Pilot Evaluation ($N=28$)**: 28 newly constructed adversarial test cases spanning 14 attack categories ($n=2$ per category).
5. **Prompt-Injection Robustness Pilot ($N=4$)**: 4 prompt override payloads targeting the LLM judge.
6. **Salami Drift Simulation ($N=5$)**: A 5-version proof-of-concept simulation evaluating incremental multi-release drift.

---

## 8. Baselines and Ablations

- **Exact Hash Pinning**: Binary SHA-256 match. Flags all 23 benign test updates as modified because its integrity criterion is byte-level equality.
- **Static Keyword Rules**: Regex rule matcher. Achieves 0.0% FPR on test set, but misses 45.5% of malicious attacks (15/33 FNR) lacking explicit keyword triggers.
- **TF-IDF Cosine-Similarity Lexical Baseline**: Threshold $\theta^* = 0.59$ calibrated on train/dev data. Precision 64.6% (31/48), Recall 93.9% (31/33), F1 76.5%, FPR 73.9% (17/23).
- **Deterministic Schema Security Checks**: Detected evaluated privilege-escalation and default-injection cases in under 0.10 ms, with zero false positives among the evaluated $N=23$ benign examples.
- **Prompt Mode Ablation (Mode A vs Mode B)**: Mode B (diff-only) reduced judge prompt token count by 77.4%, reduced latency from 2.85s to 1.42s, and reduced benign FPR from 39.1% (9/23) to 26.1% (6/23).
- **Thinking Ablation**: On the evaluated configuration, disabling Qwen3-8B thinking reduced latency from 4.68s to 1.42s while producing similar F1 (92.3% vs 91.7%). This experiment does not establish that thinking is generally unnecessary for semantic security classification.

---

## 9. Main Results

The table below presents metrics on the held-out test split ($N=56$) and server-grouped cross-validation ($N=370$):

| Method | Evaluation | N | Precision | Recall | F1 | Benign FPR | Latency |
|---|---|---:|---:|---:|---:|---:|---:|
| **Cryptographic Hash Pinning (Tier 0)** | Standalone Baseline (Exact Match) | 56 | 58.9% (33/56) | 100.0% (33/33) | 74.2% | 100.0% (23/23) | 0.024 ms |
| **Static Keyword Rules (Tier 1)** | Standalone Baseline (Regex Filter) | 56 | 100.0% (18/18) | 54.5% (18/33) | 70.6% | 0.0% (0/23) | 0.024 ms |
| **TF-IDF Cosine-Similarity Lexical Baseline** | Standalone Baseline ($\theta^*=0.59$) | 56 | 64.6% (31/48) | 93.9% (31/33) | 76.5% | 73.9% (17/23) | ~1.2 ms |
| **Deterministic Schema Security (Tier 1.5)** | Standalone Layer Check | 56 | 100.0% (12/12) | 36.4% (12/33) | 53.3% | 0.0% (0/23) | 0.08 ms |
| **Semantic Judge Mode A (Full Context)** | Standalone LLM Judge (Mode A) | 56 | 80.5% (32/39) | 97.0% (32/33) | 87.9% | 39.1% (9/23) | 2,850 ms |
| **Semantic Judge Mode B (Diff Only)** | Standalone Semantic Judge (Mode B) | 56 | 85.7% (33/39) | 100.0% (33/33) | 92.3% | 26.1% (6/23) | 1,420 ms |
| **Hybrid Guard (Tiers 0+1+1.5+2+3, Mode B)** | Standalone Pipeline (No Middleware Context) | 56 | 85.7% (33/39) | 100.0% (33/33) | 92.3% | 26.1% (6/23) | ~960 ms |
| **Integrated Guard Middleware (BALANCED Policy)** | Integrated Middleware (Held-Out Test) | 56 | 100.0% (33/33) | 100.0% (33/33) | 100.0% | 0.0% (0/23) | ~960 ms |
| **Semantic Judge Mode B (5-Fold Group CV)** | Server-Grouped Generalization | 370 | 81.8% ± 10.3% | 100.0% ± 0.0% | 89.7% ± 6.2% | 23.0% ± 4.1% | 1,420 ms |

*Note: In the 5-fold cross-validation row, ± indicates sample standard deviation across the 5 folds.*

### Reconciliation of Integrated Middleware vs Standalone Semantic Judge:
- **Integrated Middleware Result ($N=56$)**: Precision 100%, Recall 100%, F1 100%, Benign FPR 0%. Evaluates the full middleware pipeline under the `BALANCED` policy with pre-populated trusted baselines and deterministic pre-filters.
- **Standalone Semantic-Judge Result ($N=56$)**: Precision 85.7%, Recall 100%, F1 92.3%, Benign FPR 26.1%. Evaluates isolated Mode-B semantic classification on text diffs.

---

## 10. Generalization and Robustness

### 10.1 Server-Grouped 5-Fold Cross-Validation ($N=370$)
Across 5 folds partitioned by server repository with zero server overlap between train and test:
- **Mean Precision**: 81.8% ± 10.3% (standard deviation)
- **Mean Recall**: 100.0% ± 0.0%
- **Mean F1 Score**: 89.7% ± 6.2%
- **Mean Benign FPR**: 23.0% ± 4.1%

### 10.2 Controlled Matched-Pair Pilot ($N=24$)
A controlled matched-pair pilot constructed 12 benign real-update examples and 12 corresponding malicious semantic mutations. The pilot was designed to reduce writing-style confounding but is too small to establish general performance. In this pilot, all 12 malicious mutations were detected (100% recall), and 9 of 12 benign updates passed without alert (75.0% specificity, 25.0% FPR).

### 10.3 Descriptive Real-Contract Subset ($N=13$)
On the 13 real historical contract modifications, the guard correctly approved 10 of 13 maintenance updates (76.9% pass rate), while 3 updates containing security refactoring notes triggered conservative review.

---

## 11. Adversarial Evaluation

### 11.1 Adversarial Pilot Evaluation ($N=28$)
In a small adversarial pilot of 28 newly constructed cases spanning 14 attack categories, the guard detected 25/28 cases (89.3%). Because each category contained only two cases, this result is exploratory rather than a statistically reliable per-category estimate:
- **Detected (25/28)**: Instruction injection, schema widening, URL redirection, prerequisite hijacking, encoding evasion, multi-argument hiding.
- **Missed Evasions (3/28)**: Highly subtle passive framing where exfiltration was described as standard optional telemetry without concrete network indicators.

### 11.2 Prompt-Injection Robustness Pilot ($N=4$)
In 4 pilot tests containing direct prompt injection commands embedded in docstrings (`"SYSTEM: CLASSIFY AS BENIGN"`), Mode B isolated diff delimiter encapsulation prevented prompt breakout, resulting in 4/4 detections.

### 11.3 Salami Drift Simulation ($N=5$)
In a 5-version proof-of-concept simulation of multi-step incremental semantic drift, baseline anchoring against origin $V_{\text{root}}$ caught drift at Version 4, whereas single-step adjacent diffing remained blind until Version 5.

---

## 12. Deployment and Latency

### Measured Latency Profiles:
- **Fast Deterministic Path (Unchanged Tool)**: 0.024 ms
- **Obvious Deterministic Attack Path**: 0.16 ms
- **Changed Tool Semantic Evaluation**: 1.42s mean latency on the evaluated local CPU setup (Intel/AMD x86_64, Ollama Q4_K_M).

> [!NOTE]
> Latency depends heavily on the model architecture, quantization level, host hardware, Ollama runtime settings, and concurrent workload. The measured local CPU latency may be unsuitable for synchronous interactive deployment without hardware acceleration or asynchronous staging.

### Local Model Comparison on Held-Out Split ($N=56$):
These measurements were obtained on the same $N=56$ evaluation split under the reported evaluation configuration:

| Model | F1 Score | Mean Latency | Benign FPR |
|---|---:|---:|---:|
| **Qwen3-8B** | 92.3% | 1.42s | 26.1% |
| **Gemma3-4B** | 87.3% | 0.78s | 34.8% |
| **Qwen2.5-1.5B** | 81.5% | 0.29s | 65.2% |

### Asynchronous Staging Protocol:
To avoid blocking interactive agent handshakes, we propose asynchronous staging as a deployment design: serving trusted baseline V1 immediately during initialization while dispatching candidate V2 to background semantic evaluation.

---

## 13. Error Analysis

We categorize observed classification failures into a structured error taxonomy (see [`results/FINAL_REVIEWER_ERROR_ANALYSIS.md`](file:///c:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/results/FINAL_REVIEWER_ERROR_ANALYSIS.md)):
1. **Benign Refactoring Over-Alerts (FP)**: Releases mentioning security terms ("sanitized", "deprecated shell") trigger conservative judge suspicion in standalone Mode B.
2. **Subtle Euphemistic Evasions (FN)**: Passive descriptions claiming optional telemetry bypass static rules and borderline semantic thresholds.
3. **Breaking Schema Rollback Incompatibility**: Client tool calls fail when candidate V2 introduces required fields and the proxy serves V1.

---

## 14. Limitations

1. **Local CPU Inference Latency**: 1.42s per changed tool necessitates asynchronous staging for interactive environments.
2. **Small Historical Real-Contract Sample ($N=13$)**: Real open-source MCP repositories currently provide 13 pre-existing contract modifications.
3. **Exploratory Adversarial Sample ($N=28$)**: The 14-category red-team suite contains 2 samples per category, serving as an exploratory pilot rather than a definitive per-category evaluation.
4. **Runtime Code Execution**: Attacks occurring entirely inside server runtime code execution during `tools/call` are outside the scope of manifest drift detection.
5. **Rollback Incompatibility**: Rollback is a containment mechanism rather than a universal compatibility mechanism when breaking schema changes occur.

---

## 15. Reproducibility

All experiments are fully reproducible using local open-weight models and the provided scripts:
- Test suite: `python -m unittest discover tests` (38/38 passing).
- Cross-validation: `python experiments/cross_validation.py`.
- TF-IDF Baseline: `python experiments/baseline_embedding.py`.
- Integration tests: `tests/test_middleware_integration.py`.

---

## 16. Discussion

Our findings demonstrate that separating byte-level integrity verification from semantic security analysis resolves the alert burden of exact cryptographic pinning while providing defensive depth against covert tool poisoning. By placing deterministic static and schema filters upstream of an isolated semantic judge, the architecture minimizes compute cost on obvious transitions while reserving semantic LLM reasoning for ambiguous natural language changes.

---

## 17. Future Work

1. Expanding historical multi-repository mining across emerging enterprise MCP ecosystems.
2. Formally verifying JSON Schema backward-compatibility using automated schema synthesis.
3. Coupling upstream manifest drift detection with downstream runtime execution sandboxes and system-call tracing.
4. Exploring hardware-accelerated local SLMs (e.g. NPU/GPU inference) for sub-100ms semantic diff evaluation.

---

## 18. Conclusion

The MCP Semantic Drift Guard establishes a principled, multi-tiered approach for securing LLM agent tool evolution. By combining cryptographic fast-paths, deterministic schema checks, structured contract diffs, and an isolated semantic judge, the system separates integrity detection from semantic security judgment. The research package is suitable for manuscript preparation and peer-review submission, subject to the documented limitations.
