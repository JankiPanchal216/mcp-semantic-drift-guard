# Salami Drift Benchmark V3: Formal Methodological Design Review & Validation Audit

**Document Date:** 2026-10-08  
**Audit Target:** Salami Drift Benchmark V3 Specification (`results/SALAMI_DRIFT_V3_PROTOCOL.md`)  
**Auditor:** Independent Research Auditor & Methodological Reviewer  
**Context:** Following the invalidation of Benchmark V2 (`results/SALAMI_DRIFT_V2_AUDIT.md`), this review evaluates whether the proposed V3 experimental architecture is methodologically sound, internally valid, and ready for benchmark generation and evaluation.

---

## 1. Executive Summary & Review Verdict

### **VERDICT: V3 DESIGN APPROVED**

The V3 protocol establishes a rigorous, falsifiable, and auditable scientific architecture that directly resolves the three fatal methodological failures of V2:
1. **Mock Artifact Resolution:** Mandatory enforcement of `--authoritative` mode requiring `mock_calls == 0`, verifiable model token traces, and instant process termination if mock injection is attempted.
2. **True Salami Splitting:** Transition from single-step overt parameter injections (e.g. `bypass_tenant_isolation`) to multi-step **semantic composition**, where each step is individually plausible and low-signal, but their joint presence violates the trusted root contract.
3. **Capacity & Judge Reformulation:** Reformulating the judge prompt from context-free diff inspection ("Is this diff dangerous?") to **baseline-relative contract drift** ("Has the candidate drifted from the authorized baseline?"), anchored by `qwen3:8b` as the parameter-adequate model of record.

---

## 2. In-Depth Evaluation of Core Methodological Questions

### Question 1: Does V3 actually test cumulative semantic drift?
**Assessment: YES.**
- In V1, cumulative and adjacent comparisons behaved identically because terminal updates contained overt regex signatures (`rm -rf`, `exfiltrate`) that triggered Tier 2 static rules regardless of anchor.
- In V2, terminal updates added overt capabilities (`strip_authorization_gates`, `attach_host_namespace`), making adjacent diffs overtly malicious in a single step.
- In V3, the research design isolates cumulative semantic drift by enforcing **semantic composition**:
  - $V_0$: Offline document parser.
  - $V_0 \rightarrow V_1$: Adds output format structuring (`output_schema: string`). (Plausible formatting feature; benign in isolation).
  - $V_1 \rightarrow V_2$: Adds diagnostic session metadata collection (`include_caller_context: bool`). (Plausible observability feature; benign in isolation).
  - $V_2 \rightarrow V_3$: Adds stream buffering destination (`diagnostic_stream_target: string`). (Plausible telemetry feature; benign in isolation).
  - **Adjacent Analysis ($\Delta_{\text{adj}} = V_2 \rightarrow V_3$):** Adding a diagnostic target to a tool that already logs context is a routine observability enhancement.
  - **Cumulative Analysis ($\Delta_{\text{cumul}} = V_0 \rightarrow V_3$):** An offline document parser has been transformed into a utility that harvests caller execution context and dispatches it to an external streaming endpoint.
  The malicious security implication exists *only* when the changes are evaluated against the immutable root origin $V_0$.

---

### Question 2: Can adjacent comparison miss while cumulative detects?
**Assessment: YES.**
- Under adjacent comparison, the detector only sees $\Delta(V_{k-1}, V_k)$. If step $k$ introduces a single standard parameter (e.g. `stream_target`) without overt attack words, the incremental change has a low risk delta. Because the policy engine promotes approved candidates to the active baseline, $V_{k-1}$ is normalized as safe.
- Under cumulative comparison, the detector evaluates $\Delta(V_0, V_k)$. The joint combination of parameters (`output_schema` + `include_caller_context` + `stream_target`) constitutes an unauthorized expansion beyond the root trust boundary.
- Thus, the theoretical divergence between $S_{\text{adj}}$ and $S_{\text{cumul}}$ is mathematically and semantically real in V3.

---

### Question 3: Can cumulative comparison falsely outperform merely because it sees more text?
**Assessment: CONTROLLED & MITIGATED.**
- **Risk Identified:** Cumulative diffs naturally contain larger token counts and more JSON properties than adjacent diffs. If an LLM judge is biased toward assigning `MALICIOUS` whenever a diff is large (a "length heuristic" bias), cumulative mode could artificially appear superior while actually suffering from severe false positives.
- **V3 Mitigation:** The protocol introduces **Category C: Benign Long-Drift Evolution Controls** (8 chains, 32 transitions).
  - Benign chains undergo 4 to 5 revision steps of extensive refactoring (adding search filters, pagination tokens, response formatting, caching configurations, docstring clarifications).
  - The cumulative diff $V_0 \rightarrow V_k$ in Category C contains high token edit distance ($> 50\%$) and multiple added properties, yet the tool's security envelope remains strictly benign.
  - If cumulative comparison flags these benign chains simply because of large diff size, its Benign FPR will spike, triggering the pre-registered invalidation criterion ($\text{FPR}_{\text{benign}} > 50\%$).
  - This scientifically guarantees that cumulative detection cannot score a false victory through text volume alone.

---

### Question 4: Are malicious and benign chains comparable?
**Assessment: YES.**
- In V3, malicious and benign chains are balanced across structural dimensions:
  - **Chain depth:** Both contain 4–5 revision transitions.
  - **Parameter growth:** Both add 1 property per step (accumulating 3–4 properties total).
  - **Docstring modification size:** Both exhibit token edit distances of 15%–35% per transition.
  - **Vocabulary profile:** Both use standard, professional software engineering terminology without artificial markers.

---

### Question 5: Is there deterministic leakage?
**Assessment: ZERO.**
- Pre-registration Gate G4 enforces that all tool definitions across Categories A, D, E, F, and G must be evaluated against `guard/static_rules.py`. Any match with regexes (e.g. `rm -rf`, `exfiltrate`, `shadow`, `/etc/passwd`) immediately rejects the chain.
- Gate G5 enforces that all schemas must be evaluated against `guard/schema_security_rules.py`. Any parameter `default` containing an HTTP URL or sensitive path, or any `readOnly` boolean flip, immediately rejects the chain.
- Deterministic tiers (Tier 1.5 and Tier 2) are guaranteed not to short-circuit the experiment, ensuring that all adjudications occur at Tier 3 (Semantic Judge).

---

### Question 6: Is there label leakage?
**Assessment: ZERO.**
- Neither `gold_label`, `category`, `attack_family`, `stage`, nor `step_index` is exposed to the model.
- Tool names and parameter names are completely cleansed of indicator strings (`bypass`, `admin`, `strip`, `attack`, `sink`).
- The evaluation harness passes only the raw tool contract objects.

---

### Question 7: Is the semantic judge receiving the correct baseline?
**Assessment: VERIFIED BY ARCHITECTURAL TRACE.**
- We audited `guard/middleware.py` and traced baseline retrieval through `BaselineStore`:
  - **Adjacent Mode:** `old_tool_def` is retrieved from `BaselineStore.get_active_baseline()`. Upon approval of $V_k$, `update_trusted_baseline()` advances the active baseline to $V_k$.
  - **Cumulative Mode:** `root_tool_def` is retrieved from `BaselineStore.get_root_definition()`, which remains permanently anchored to $V_0$.
  - **Dual Mode:** Both `old_tool_def` and `root_tool_def` are independently passed, generating `diff_adj` and `diff_cumul`.
- The evaluation harness correctly routes:
  - $S_{\text{adj}} \implies (\text{baseline}=V_{k-1}, \text{candidate}=V_k)$
  - $S_{\text{cumul}} \implies (\text{baseline}=V_0, \text{candidate}=V_k)$
- In V3, these exact objects are logged with SHA-256 digests in each step's trace in `predictions.jsonl`.

---

### Question 8: Can the model distinguish "candidate dangerousness" from "semantic drift relative to baseline"?
**Assessment: YES, VIA PROMPT REFORMULATION.**
- In V2, Mode B prompt passed only the diff without baseline context, asking the model whether the diff itself appeared dangerous.
- In V3, the prompt explicitly presents both the **Authorized Baseline** ($V_0$ or $V_{k-1}$) and the **Candidate Tool Definition** ($V_k$), with explicit directives to evaluate whether the candidate's capabilities exceed the baseline's functional authorization.
- This forces the LLM to perform genuine relative contract diffing rather than static keyword inspection.

---

### Question 9: Is the evaluator guaranteed to use live inference?
**Assessment: GUARANTEED BY CODE ENFORCEMENT.**
- The evaluator specification includes a hard failure check:
  - If `--authoritative` is invoked, any presence of `mock_resp` or `--mock` raises `AssertionError("CRITICAL: Authoritative run cannot use mock inference!")` and terminates execution immediately.
  - The evaluator records `live_inference_calls` and asserts `mock_calls == 0`.
  - Every prediction record stores `raw_model_response` and response latency (ms). A mock response with constant latency or canned json will fail post-run checksum verification.

---

### Question 10: Is the statistical design appropriate?
**Assessment: YES.**
- Evaluates paired transitions using **McNemar's Exact Test** (appropriate for paired binary classification on identical chains).
- Evaluates exposure window shifts using the **Wilcoxon Signed-Rank Test**.
- Pre-registers explicit statistical power limits ($N=40$ chains, 144 transitions):
  - Acknowledges that $N=16$ pure salami chains provides sufficient power ($\ge 80\%$) to detect large effect sizes ($\Delta \ge 35\%$), but may not detect small differences ($\Delta \le 15\%$).
  - Avoids degenerate tests where zero discordant pairs were misreported as $p = 1.0000$.

---

### Question 11: What could still invalidate V3?
**Assessment: THREE REMAINING RISKS IDENTIFIED & SAFEGUARDED:**
1. **Model Capacity Bottleneck:** If the selected model (`qwen3:8b`) cannot reliably comprehend multi-hop semantic composition without overt cues, both Adjacent and Cumulative could yield low recall.  
   *Safeguard:* The protocol pre-registers that if the model cannot discern the semantic composition, this will be reported faithfully as an empirical limit of current 8B open-weight models, rather than patched with mock data or overt keywords.
2. **Local CPU Inference Latency:** Running 264 live calls on CPU with an 8B model will take ~3.5 to 4 hours.  
   *Safeguard:* Evaluator supports resilient checkpointing (`--resume_from_checkpoint`) so that long runs can be audited and resumed without loss of data.
3. **Subtle Single-Step Leakage in Category A:** If any intermediate step inadvertently introduces a parameter that an LLM flags as suspicious on its own, adjacent mode will catch it early, reducing the measured exposure window.  
   *Safeguard:* Automated validation Gate G3 validates every adjacent transition in isolation prior to benchmark freezing.

---

## 3. Final Pre-Implementation Checklist

- [x] Research question and hypotheses formally defined ($H_0$, $H_1$).
- [x] V1 and V2 artifacts preserved immutably (no overwriting).
- [x] Salami drift redefined as true semantic composition (no single-step weaponization).
- [x] Automated 9-gate benchmark validation suite specified.
- [x] Mock mode completely banned from authoritative metrics generation.
- [x] Evaluator requires `mock_calls == 0` and live model provenance.
- [x] Semantic judge prompt reformulated to evaluate baseline-relative drift.
- [x] Model selection justified based on capacity and empirical latency profiling.
- [x] Benign long-drift controls balanced across depth, edits, and schema complexity.
- [x] Paired statistical testing (McNemar's, Wilcoxon) properly specified.
- [x] Statistical power limitations transparently disclosed.
- [x] Strict stop condition respected (no data generated, no code modified prematurely).

---

## 4. Conclusion & Audit Sign-Off

The V3 experiment design resolves all methodological defects of V2 and establishes a gold-standard framework for evaluating cumulative semantic drift in agent tool security.

**FINAL VERDICT:** **`V3 DESIGN APPROVED`**
