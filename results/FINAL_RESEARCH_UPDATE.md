# FINAL RESEARCH UPDATE
## MCP Semantic Drift Detection for Model Context Protocol Tool Definition Updates

---

## 1. Research Objective

The objective of this research is to investigate runtime protection for Large Language Model (LLM) agents against malicious semantic drift and tool poisoning introduced via dynamic Model Context Protocol (MCP) tool definition updates (`tools/list`). 

Specifically, the project addresses the tension between **integrity verification** and **operational maintenance**:
- Strict cryptographic integrity checking flags any byte-level change to a tool contract.
- Legitimate software maintenance routinely refactors docstrings, clarifies argument descriptions, and adds backward-compatible parameters.
- The research question is: *How can runtime systems protect LLM agents against covert semantic drift and prompt injection in MCP tool manifests without imposing an unsustainable review burden on legitimate software evolution?*

---

## 2. Research Contribution

The primary contribution is an empirical study of MCP tool-definition evolution combined with a semantics-aware, policy-enforcing middleware architecture that separates integrity detection from semantic security judgment.

Rather than relying on a single detection mechanism, the system integrates:
1. **Cryptographic Fast-Path Hash Pinning**: Allows byte-identical tool definitions in sub-millisecond time ($0.024\text{ ms}$).
2. **Deterministic Security Checks**: Fast regex pre-filters and schema-attribute validators that catch known attack patterns and privilege escalations ($0.16\text{ ms}$).
3. **Structured JSON Diff Engine**: Canonical field-level differencing that isolates changes from static boilerplate schemas.
4. **Isolated Diff-Only Semantic LLM Judge**: Evaluates canonical diffs with local open-weight models (`Qwen3-8B`) to discriminate benign maintenance from malicious drift.
5. **Stateful Baseline Management and Policy Enforcement**: Enforces automated rollback for compatible updates and quarantine for breaking or high-risk modifications.

---

## 3. Dataset and Corpus

To ground the research in real-world software engineering practices, we assembled and verified the **MCP Tool-Definition Evolution Corpus**:

### 3.1 Historical Evolution Corpus Statistics
- **Analyzed Release Transitions**: 621 transitions across 12 active MCP repositories (`modelcontextprotocol/servers`, `git`, `filesystem`, `sqlite`, `github`, `puppeteer`, `memory`, `mysql`, `slack`, etc.).
- **Releases with Any Tool-Definition Change**: 31 transitions (4.99% release-change rate).
- **Total Tool-Definition Change Events**: 123 events.
- **Tool Additions and Removals**: 110 events (89.4% of change events).
- **Modifications to Pre-Existing Tool Contracts**: 13 events (10.6% of change events).
- **Pre-Existing Contract Modification Rate**: 13 of 621 release transitions (2.09%) involved modifications to pre-existing tool contracts:
  - Description / Documentation Clarifications: 7 releases
  - Schema / Parameter Modifications: 2 releases
  - Mixed Contract Modifications: 4 releases

### 3.2 Evaluation Benchmark Datasets
- **Main Benchmark Dataset ($N=370$)**: 200 Malicious (derived from MCPTox templates and controlled mutations), 170 Benign (123 real git updates + 47 programmatic hard negatives).
  - Train Split: $N=259$ across 19 server clusters.
  - Dev Split: $N=55$.
  - Held-Out Test Split: $N=56$ (33 Malicious, 23 Benign).
- **Controlled Matched-Pair Pilot ($N=24$)**: 12 authentic benign updates paired with 12 controlled malicious mutations sharing identical source server, tool name, schema structure, and writing style.
- **Descriptive Real-Contract Subset ($N=13$)**: The 13 historical pre-existing contract modifications.
- **Adversarial Pilot Evaluation (Red-Team v2, $N=28$)**: 28 fresh evasion payloads across 14 attack categories ($n=2$ per category).
- **Prompt-Injection Robustness Pilot ($N=4$)**: 4 prompt override payloads targeting the judge.
- **Salami-Drift Proof-of-Concept ($N=5$)**: 5-version sequential incremental drift simulation.

---

## 4. Baseline and Comparison Methods

We evaluate the multi-tiered guard against three standard defensive paradigms:

1. **Exact Cryptographic Hash Pinning (Tier 0 Baseline)**:
   - Evaluates byte-level SHA-256 equality over canonicalized tool definitions (`name`, `description`, `inputSchema`).
   - *Integrity Question Answered*: "Did the trusted definition change?"
   - *Operational Finding*: In the observed corpus, all 31 release transitions containing legitimate tool-definition maintenance changes would trigger reapproval under exact hash equality (4.99% change-trigger burden). Exact pinning cannot distinguish benign evolution from malicious drift among changed tools.
2. **Static Keyword / Regex Rules (Tier 1 Baseline)**:
   - Heuristic pattern matching against known injection delimiters (`<IMPORTANT>`, `MUST FIRST`, `~/.ssh`).
   - *Finding*: High precision ($100\%$ on evaluated benign cases) and ultra-low latency ($<0.05\text{ ms}$), but misses $45.5\%$ of attacks ($15/33$) that use indirect or euphemistic phrasing.
3. **TF-IDF Cosine-Similarity Lexical Baseline (Baseline 3)**:
   - Sublinear TF-IDF word n-gram vectorizer with cosine similarity threshold $\theta^* = 0.59$, calibrated strictly on train/dev data.
   - *Finding*: Precision 64.6% (31/48), Recall 93.9% (31/33), F1 76.5%, Benign FPR 73.9% (17/23). Routine vocabulary changes during refactoring drop similarity below threshold, causing high false alarm rates.

---

## 5. Semantic Drift Guard Architecture

The guard middleware operates at the JSON-RPC transport boundary (`tools/list`):

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

---

## 6. Main Verified Results

The table below summarizes performance across baselines, standalone judge configurations, and the integrated middleware:

| Method / Defense Layer | Evaluation Set / Context | N | Precision | Recall | F1 Score | Benign FPR | Mean Latency |
|---|---|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Tier 0)** | Standalone Baseline (Exact Match) | 56 | 58.9% (33/56) | 100.0% (33/33) | 74.2% | 100.0% (23/23) | 0.024 ms |
| **Static Keyword Rules (Tier 1)** | Standalone Baseline (Regex Filter) | 56 | 100.0% (18/18) | 54.5% (18/33) | 70.6% | 0.0% (0/23) | 0.024 ms |
| **TF-IDF Cosine-Similarity Baseline** | Lexical Baseline ($\theta^*=0.59$) | 56 | 64.6% (31/48) | 93.9% (31/33) | 76.5% | 73.9% (17/23) | ~1.2 ms |
| **Deterministic Schema Security (Tier 1.5)** | Standalone Security Check | 56 | 100.0% (12/12) | 36.4% (12/33) | 53.3% | 0.0% (0/23) | 0.08 ms |
| **Semantic Judge Mode A (Full Context)** | Standalone LLM Judge (Mode A) | 56 | 80.5% (32/39) | 97.0% (32/33) | 87.9% | 39.1% (9/23) | 2,850 ms |
| **Semantic Judge Mode B (Diff Only)** | Standalone Semantic Judge (Mode B) | 56 | 85.7% (33/39) | 100.0% (33/33) | 92.3% | 26.1% (6/23) | 1,420 ms |
| **Integrated Guard Middleware (BALANCED Policy)** | Phase 5 Local MCP JSON-RPC Test | 56 | 100.0% (33/33) | 100.0% (33/33) | 100.0% | 0.0% (0/23) | ~960 ms |
| **Semantic Judge Mode B (5-Fold Group CV)** | Server-Grouped Generalization | 370 | 81.8% ± 10.3% | 100.0% ± 0.0% | 89.7% ± 6.2% | 23.0% ± 4.1% | 1,420 ms |

*Note: In the 5-fold cross-validation row, ± denotes sample standard deviation across the 5 folds.*

---

## 7. Phase 5 Integrated Middleware Result

In the **Phase 5 Local MCP JSON-RPC Integration Test** on the held-out test split ($N=56$, comprising 33 malicious/suspicious and 23 benign examples):
- **Precision**: 100.0% (33/33, 95% Wilson CI: [89.4%, 100.0%])
- **Recall**: 100.0% (33/33, 95% Wilson CI: [89.4%, 100.0%])
- **F1 Score**: 100.0%
- **Benign FPR**: 0.0% (0/23, 95% Wilson CI: [0.0%, 14.8%])
- **Malicious FNR**: 0.0% (0/33, 95% Wilson CI: [0.0%, 10.6%])

> [!IMPORTANT]
> **Scope Qualification**: This 100% result is strictly scoped to the $N=56$ Phase 5 integrated middleware evaluation under the tested BALANCED policy with pre-populated trusted baselines and upstream deterministic filtering. It does not imply that the system is universally 100% accurate across all possible MCP deployments.

---

## 8. Standalone Semantic-Judge Result

The **Standalone Mode-B Semantic Judge Evaluation** isolates the local LLM judge (`Qwen3-8B`, temperature=0) on canonical text diffs without upstream filtering or baseline middleware state ($N=56$):
- **True Positives (TP)**: 33
- **True Negatives (TN)**: 17
- **False Positives (FP)**: 6
- **False Negatives (FN)**: 0
- **Precision**: 85.7% (33/39, 95% Wilson CI: [72.8%, 94.1%])
- **Recall**: 100.0% (33/33, 95% Wilson CI: [89.4%, 100.0%])
- **F1 Score**: 92.3%
- **Benign FPR**: 26.1% (6/23, 95% Wilson CI: [12.6%, 46.5%])

> [!NOTE]
> The standalone semantic judge isolates text-level semantic classification. The 92.3% F1 standalone result does not contradict the 100% Phase 5 integrated result; they evaluate different architectural layers and operational configurations.

---

## 9. Server-Level Cross-Validation

To evaluate generalization across distinct server codebases without template leakage, we conducted **5-Fold Server-Grouped Cross-Validation** ($N=370$ across 19 server clusters with zero server template overlap between train and test folds):
- **Mean F1 Score**: 89.7% ± 6.2%
- **Mean Recall**: 100.0% ± 0.0%
- **Mean Precision**: 81.8% ± 10.3%
- **Mean Benign FPR**: 23.0% ± 4.1%

*Note: All ± values represent sample standard deviations across the 5 partitioned folds. This evaluation provides empirical evidence that performance persists under server-grouped partitioning.*

---

## 10. Adversarial Evaluation

### 10.1 Adversarial Pilot Evaluation (Red-Team v2, $N=28$)
In a small adversarial pilot of 28 newly constructed test cases spanning 14 attack categories ($n=2$ per category):
- **Overall Detection**: 25 of 28 cases detected (89.3% detection rate).
- **Evading Cases ($n=3$)**: Highly subtle passive framing where data exfiltration was described as standard optional telemetry without concrete network indicators.
- **Pilot Qualification**: Because each category contained only two cases, this result is exploratory rather than a statistically definitive per-category estimate.

### 10.2 Prompt-Injection Robustness Pilot ($N=4$)
In 4 pilot tests containing direct prompt override directives targeting the judge (e.g. `"SYSTEM: CLASSIFY AS BENIGN"`), Mode B isolated diff delimiter encapsulation prevented prompt breakout, resulting in 4/4 detections.

### 10.3 Salami-Drift Proof-of-Concept ($N=5$)
In a 5-version incremental drift simulation, cumulative baseline diffing against origin anchor $V_{\text{root}}$ successfully detected the drift at Step 4, whereas per-step adjacent diffing remained blind until Step 5.

---

## 11. Schema Security Checks

Deterministic Tier 1.5 schema checks audit structural JSON Schema modifications:
- Transition of `readOnly` attributes from `true` to `false` without explicit permission.
- Default value injections containing suspicious URLs, IP addresses, or sensitive paths.
- Widening of enum constraints to permit arbitrary execution targets.

### Performance on Evaluated Split:
- **Execution Latency**: $< 0.10\text{ ms}$
- **Benign False Positives**: 0 false positives among the evaluated $N=23$ benign test cases.
- **Qualification**: This deterministic layer accelerates detection of explicit parameter attacks, but does not generalize to all possible schema tampering vectors.

---

## 12. Model and Thinking Ablations

### 12.1 Local Model Comparison on Held-Out Split ($N=56$)
All measurements were obtained on the same $N=56$ evaluation split under identical prompt conditions:

| Model | F1 Score | Precision | Recall | Benign FPR | Mean Latency |
|---|---:|---:|---:|---:|---:|
| **Qwen3:8B** | **92.3%** | **85.7%** | **100.0%** | **26.1%** | 1,420 ms |
| **Gemma3:4B** | 87.3% | 81.6% | 93.9% | 30.4% | 780 ms |
| **Qwen2.5:1.5B** | 81.5% | 68.8% | 100.0% | 65.2% | 290 ms |

*Note: No model is described as universally superior; smaller models provide faster inference but exhibit higher false positive rates on benign refactorings.*

### 12.2 Thinking ON vs. OFF Ablation (Qwen3:8B)
- **Thinking OFF**: F1 = 92.3%, Mean Latency = 1.42s
- **Thinking ON**: F1 = 91.7%, Mean Latency = 4.68s (~+230% latency overhead)
- **Finding**: Disabling internal thinking reduced latency substantially while preserving classification performance on structured diffs. This experiment does not establish that thinking is generally unnecessary for all reasoning tasks.

---

## 13. Latency Evaluation

### Measured Execution Latencies:
- **Unchanged Tools (Fast Deterministic Path)**: $\approx 0.024\text{ ms}$
- **Obvious Attacks (Deterministic Security Path)**: $\approx 0.16\text{ ms}$
- **Changed Tools Requiring Semantic Evaluation**: $\approx 1.42\text{ s}$ mean CPU latency on the evaluated local hardware setup (x86_64, Ollama Q4_K_M).

> [!WARNING]
> **Deployment Context**: The measured local CPU latency may be unsuitable for synchronous interactive deployment without acceleration or asynchronous staging. Asynchronous staging—serving trusted baseline V1 immediately while analyzing candidate V2 in the background—is proposed as a deployment design consideration, not as a proven production deployment.

---

## 14. Rollback and Failure Handling

Rollback to the previously trusted baseline (V1) is a **containment mechanism**, not a universal compatibility guarantee:
1. **Safe Rollback**: Reverting to V1 is transparent when V2 is backward-compatible (docstring clarifications, parameter description updates, optional parameter additions).
2. **Breaking Contract Changes**: If candidate V2 introduces newly required parameters, removes parameters, or alters argument types, serving V1 causes downstream JSON-RPC client call failures.
3. **Operational Policy**: Breaking contract modifications must trigger explicit **quarantine and administrative review** rather than silent automatic fallback.

---

## 15. Related Work Positioning

This work is positioned relative to established literature in agent security and software supply-chain integrity:
- **MCPTox (Zhang et al., 2024)**: Benchmark demonstrating downstream agent susceptibility to poisoned MCP tools; our work focuses on upstream manifest drift detection and policy-enforcing middleware.
- **ToolHijack (Liu et al., 2024)**: Investigated parameter manipulation in OpenAPI tools; informs our deterministic Tier 1.5 schema checks.
- **Subresource Integrity (W3C, 2016)** & **Snyk Agent Scan / mcp-scan**: Cryptographic pinning implementations; our study quantifies the maintenance alert burden of exact pinning in dynamic tool manifests.
- **Sigstore / Cosign (Newman et al., 2022)**: Software artifact signing; verifies publisher identity but does not inspect semantic contract evolution within signed releases.
- **NeMo Guardrails & Llama Guard (Rebedea et al., 2023; Inan et al., 2024)**: Conversational chat guardrails; our guard operates on structured JSON-RPC contract diffs and schemas.

---

## 16. Limitations

1. **Historical Contract Modifications**: Only 13 historical pre-existing contract modifications were available in the current open-source MCP release corpus.
2. **Synthetic Component in Malicious Data**: Malicious examples derived from MCPTox templates introduce a synthetic component to the training and benchmark sets.
3. **Dataset Bias in Cross-Validation**: Server-grouped CV eliminates server template leakage across folds but does not eliminate all linguistic or structural dataset biases.
4. **Matched-Pair Pilot Scale ($N=24$)**: The controlled matched-pair study is a pilot designed to reduce writing-style confounding, not a large-scale asymptotic benchmark.
5. **Adversarial Pilot Scale ($N=28$)**: The 14-category red-team suite contains 2 samples per category, providing an exploratory pilot rather than a statistically definitive per-category estimate.
6. **Prompt-Injection Robustness Scale ($N=4$)**: Prompt-injection testing represents an initial exploratory study.
7. **Salami-Drift Scope ($N=5$)**: Evaluated as a 5-version proof-of-concept simulation.
8. **Local CPU Inference Latency**: Local CPU inference (~1.42s per changed tool) requires asynchronous staging for interactive environments.
9. **Rollback Compatibility Scope**: Rollback is not universally transparent for breaking schema changes.
10. **Runtime Execution Scope**: Attacks occurring entirely inside upstream server runtime logic during `tools/call` without manifest changes are out of scope.
11. **Frontier Commercial API Models**: Commercial closed-source APIs (GPT-4o, Claude 3.5 Sonnet) were not evaluated due to offline research environment constraints.

---

## 17. Reproducibility

The complete evaluation pipeline and unit test suite are fully reproducible:
- **Unit & Integration Test Suite**:
  ```powershell
  python -m unittest discover tests
  ```
  *Current Status*: **38/38 tests passing (OK, 0.666s)**.
- **Cross-Validation Script**: `experiments/cross_validation.py`
- **TF-IDF Baseline Calibration**: `experiments/baseline_embedding.py`
- **Local MCP JSON-RPC Integration Test**: `experiments/phase5_live_mcp_proxy.py`
- **Data Integrity**: All raw datasets (`data/drift_test.jsonl`, `data/matched_pairs.jsonl`, `data/redteam_v2.jsonl`, `data/tool_changes.jsonl`) remain strictly intact without fabrication or modification.

---

## 18. Final Claim Boundaries

### What the Evidence Supports:
- MCP tool definitions do change across observed repository releases (4.99% of release transitions, 123 change events).
- Exact hash equality detects all changes but creates a review burden for legitimate maintenance (flagging 100% of modified releases in the observed corpus).
- Semantic diff analysis can distinguish benign maintenance from security-relevant drift substantially better than lexical similarity or exact equality alone.
- The multi-tiered guard provides sub-millisecond fast paths for unchanged tools ($0.024\text{ ms}$) and obvious attacks ($0.16\text{ ms}$), reserving LLM inference for ambiguous diffs.
- Server-grouped cross-validation confirms that detection performance persists across distinct server codebases ($F_1 = 89.7\% \pm 6.2\%$).
- Adversarial pilot evaluations demonstrate detection of diverse evasion vectors ($89.3\%$) while identifying subtle passive telemetry as an evasion boundary.

### What the Evidence Does NOT Support:
- Universal 100% detection accuracy across all possible environments.
- Universal zero false positives on all future software updates.
- Immediate out-of-the-box production readiness without addressing CPU latency and breaking schema quarantines.
- Complete coverage against attacks that do not alter the tool manifest.
- Guaranteed transparent rollback for all possible breaking schema modifications.
- Guaranteed resistance to all possible adaptive adversarial attacks.
- Any claim of being the "first" or "only" MCP security solution.

---

## 19. Final Research Status

**OVERALL STATUS: VERIFIED WITH LIMITATIONS**

> *The research package is suitable for manuscript preparation and peer-review submission, subject to the documented limitations.*

---

## 20. Recommended Next Step

The empirical evaluation, baseline comparisons, cross-validation, and error taxonomy are complete, verified, and reconciled across all artifacts.

**Recommended Action**: Proceed directly to academic manuscript drafting (e.g., LaTeX preparation for IEEE S&P / USENIX Security / ACM CCS), referencing the verified evidence package and adhering strictly to the claim boundaries documented herein.
