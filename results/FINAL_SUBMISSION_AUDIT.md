# Final Submission Audit: MCP Semantic Drift Detection Project

**Final Project Audit and Manuscript Preparation Readiness Report**

---

## 1. Research Question

How can runtime systems protect Large Language Model (LLM) agents against malicious semantic drift and supply-chain poisoning in dynamic Model Context Protocol (MCP) tool definitions without imposing an unsustainable review burden on legitimate software maintenance?

---

## 2. Main Contribution

The system separates integrity detection from semantic security judgment by combining exact change detection, deterministic security checks, structured diffing, and semantic analysis.

Specifically, the architecture:
1. Employs fast-path cryptographic SHA-256 hash pinning to allow unchanged tools in 0.024 ms.
2. Applies deterministic JSON Schema checks and static rules to catch known attack vectors in under 0.16 ms.
3. Computes canonical field-level structured diffs to isolate modified tool contracts from unchanged boilerplate.
4. Uses an isolated, diff-only local semantic LLM judge (Qwen3-8B) to discriminate benign software maintenance from covert semantic drift.
5. Implements automated baseline management with safe rollback and quarantine handling for breaking schema changes.

---

## 3. Corpus Evidence

From empirical mining of **621 release transitions** across 12 active MCP server repositories:
- **Releases with Tool-Definition Changes**: 31 transitions (4.99% release-change rate).
- **Total Tool-Definition Change Events**: 123 events.
- **Tool Additions / Removals**: 110 events (89.4%).
- **Modifications to Pre-Existing Tool Contracts**: 13 events (10.6%).
- **Pre-Existing Contract Modification Rate**: 13 of 621 release transitions (2.09%) contained modifications to pre-existing tool contracts.
- **Exact Pinning Alert Burden**: Exact hash pinning flags every observed tool-definition change because its integrity criterion is byte-level equality. In the observed corpus, 31 of 621 release transitions (4.99%) changed tool manifests, meaning all these changes trigger review under exact pinning. Among observed maintenance changes, exact pinning could not distinguish benign evolution from malicious drift.

---

## 4. Integrated Guard Result

In the integrated middleware evaluation on the held-out test split ($N=56$, `data/drift_test.jsonl`):
- **Precision**: 100.0% (33/33, 95% Wilson CI: [89.4%, 100.0%])
- **Recall**: 100.0% (33/33, 95% Wilson CI: [89.4%, 100.0%])
- **F1 Score**: 100.0%
- **Benign FPR**: 0.0% (0/23, 95% Wilson CI: [0.0%, 14.8%])
- **Context**: Evaluates the full integrated middleware (`guard/middleware.py`) under the `BALANCED` policy with pre-populated trusted baselines and upstream deterministic filtering.

---

## 5. Standalone Semantic Result

In the conservative standalone semantic judge evaluation isolating Mode-B classification on text diffs ($N=56$):
- **Precision**: 85.7% (33/39, 95% Wilson CI: [72.8%, 94.1%])
- **Recall**: 100.0% (33/33, 95% Wilson CI: [89.4%, 100.0%])
- **F1 Score**: 92.3%
- **Benign FPR**: 26.1% (6/23, 95% Wilson CI: [12.6%, 46.5%])
- **Context**: Isolates local LLM semantic classification behavior on structured diffs without upstream deterministic filtering or end-to-end middleware state context.

---

## 6. Cross-Validation Result

In 5-fold server-grouped cross-validation across 370 examples and 19 servers (with zero server overlap between train and test within folds):
- **Mean Precision**: 81.8% ± 10.3%
- **Mean Recall**: 100.0% ± 0.0%
- **Mean F1 Score**: 89.7% ± 6.2%
- **Mean Benign FPR**: 23.0% ± 4.1%
- *Note: ± indicates sample standard deviation across the 5 server-partitioned folds.*

---

## 7. Adversarial Result

In an exploratory adversarial pilot of 28 newly constructed cases spanning 14 attack categories ($n=2$ per category, `data/redteam_v2.jsonl`):
- **Overall Detection**: 25 of 28 cases detected (89.3%).
- **Observed Boundaries**: 3 subtle passive telemetry framing evasions bypassed static rules and borderline confidence thresholds.
- **Scope Note**: Because each category contained only two cases, this result is exploratory rather than a statistically reliable per-category estimate.

---

## 8. Main Limitations

1. **Local CPU Inference Latency**: Changed tools requiring semantic evaluation incur a mean latency of 1.42s on the evaluated local CPU setup (Intel/AMD x86_64, Ollama Q4_K_M). Asynchronous staging is a necessary deployment design for interactive environments.
2. **Historical Contract Modification Sample ($N=13$)**: Real open-source MCP repositories currently provide 13 modified tool contracts.
3. **Runtime Execution Attacks**: Attacks executing entirely inside server backend runtime logic during `tools/call` are out of scope for manifest drift detection and require container sandboxing.
4. **Breaking Rollback Call Incompatibility**: Reverting to V1 fails runtime client RPC calls if V2 introduced breaking schema changes (e.g. newly required fields), requiring explicit quarantine.

---

## 9. Small-Sample Experiments

All small-sample experiments are explicitly labeled as exploratory pilots:
- **Controlled Matched-Pair Pilot ($N=24$)**: 12 benign updates paired with 12 malicious mutations. Caught 12/12 attacks with 3 benign false alarms (FPR = 25.0%). Designed to reduce style confounding, though too small to establish general performance.
- **Descriptive Real-Contract Subset ($N=13$)**: Correctly passed 10/13 historical maintenance updates (76.9% pass rate).
- **Adversarial Pilot Evaluation ($N=28$)**: 14 categories, $n=2$/category, 89.3% detection rate.
- **Prompt-Injection Robustness Pilot ($N=4$)**: 4 override cases; 4/4 resisted via Mode B diff isolation.
- **Salami Drift Simulation ($N=5$)**: 5-version proof-of-concept simulation showing origin anchoring caught drift at Version 4.

---

## 10. Reproducibility

- **Test Suite**: 38/38 unit and integration tests passing (`python -m unittest discover tests`).
- **Deterministic Evaluation**: Temperature=0 execution yields consistent categorical labels across repeated runs.
- **Artifact Provenance**: Raw datasets, ground-truth annotations, and experimental scripts are preserved without fabrication.

---

## 11. Related Work

Properly contextualized against established literature:
- Downstream tool poisoning benchmark: MCPTox (Zhang et al., 2024).
- OpenAPI parameter manipulation: ToolHijack (Liu et al., 2024).
- Cryptographic asset integrity: W3C Subresource Integrity (2016).
- Supply-chain signing: Sigstore/Cosign (Newman et al., 2022).
- Conversational guardrails: NeMo Guardrails (Rebedea et al., 2023), Llama Guard (Inan et al., 2024).
- API breaking change analysis: Dig & Johnson (2006), Brito et al. (2018).

---

## 12. Remaining Risks

1. **Hardware & Environment Latency Variance**: Latency depends on host CPU/GPU hardware, Ollama threading, and quantization.
2. **Evolving Attack Payloads**: Highly indirect docstrings that omit network/file keywords require continuous few-shot prompt updates.
3. **Ecosystem Evolution**: As MCP server tooling matures, additional schema migration patterns must be monitored.

---

## 13. Final Claim Recommendations

1. Frame the core contribution as separating integrity verification from semantic security judgment.
2. Report integrated middleware ($100\%$ F1 on $N=56$), standalone semantic judge ($92.3\%$ F1 on $N=56$), and server-grouped cross-validation ($89.7\% \pm 6.2\%$ F1) as distinct, complementary evaluations.
3. Quantify hash pinning's alert burden empirically without claiming universal failure.
4. Maintain explicit sample sizes ($N$) and confidence intervals / standard deviations for all statistics.
5. Clearly distinguish safe compatible rollbacks from breaking schema quarantines.

---

## 14. Final Status

**OVERALL STATUS: VERIFIED WITH LIMITATIONS**

The research package is suitable for manuscript preparation and peer-review submission, subject to the documented limitations.
