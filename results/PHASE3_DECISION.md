# Phase 3 Research Decision — Semantic Drift Detection for MCP

## Final Decision: PROCEED WITH CAUTION

---

## 1. Rationale and Empirical Basis

The empirical evaluation of Phase 3 supports advancing to Phase 4 under a **PROCEED WITH CAUTION** mandate, based strictly on the measured evidence:

### Supporting Evidence for Proceeding
1. **Resolution of Hash Pinning Failure**: Exact cryptographic hash pinning (Baseline 1) produces a **100.0% Benign False Positive Rate (FPR)** on authentic developer maintenance updates, creating an unacceptable operational burden. The **Semantic Drift Judge (Mode B Diff Only)** successfully reduces the benign false alarm rate from 100.0% down to **25.0%**, while retaining **100.0% Recall** ($F_1 = 92.3\%$) against malicious prompt injection attacks.
2. **Outperformance of Static Heuristic Rules**: Static regex rules (Baseline 2) miss 50.0% of attack payloads due to paraphrasing and novel prerequisite redirection techniques ($F_1 = 66.7\%$). The Semantic Drift Judge detects these paraphrased attacks without requiring explicit rule signatures.
3. **Superiority of Diff-Only Representation**: Evaluating structured diffs (Mode B) outperforms full description analysis (Mode A, $F_1 = 83.3\%$), eliminating 8B model JSON formatting errors and reducing inference latency.

---

## 2. Key Cautionary Factors & Technical Risk Factors

Despite these positive findings, Phase 4 MUST NOT proceed as an unconstrained or fully autonomous blocking guard due to three key empirical weaknesses:

1. **Local Model Instability (Output Schema Errors)**: On Full Description inputs (Mode A), `qwen3:8b` exhibited a **20.0% JSON parsing error rate** due to output formatting syntax quirks. In Phase 4, strict schema validation and fallback parsing layers are required.
2. **Non-Zero Benign False-Positive Rate (25.0%)**: While reducing false alarms by 75% relative to hash pinning, a 25.0% false-positive rate on complex parameter modifications is still too high for automated silent blocking in production.
3. **Inference Latency Constraints**: CPU inference latency (~50 seconds per evaluation) requires asynchronous, out-of-band evaluation rather than blocking synchronous inline middleware.

---

## 3. Phase 4 Guidance & Architectural Constraints

For Phase 4 implementation, the following research constraints are strictly required:

- **Asynchronous Guard Architecture**: The Semantic Drift Judge MUST operate asynchronously out-of-band (alerting/flagging queue) rather than blocking inline request/response loops.
- **Diff-Only Primary Policy**: The runtime guard MUST deploy Mode B (Structured Diff Only) as the primary semantic analysis mode.
- **Human-in-the-Loop Escalation**: Flagged updates marked `SUSPICIOUS` or `MALICIOUS` must route to security reviewer queues rather than performing immediate destructive revocation.

---

## 4. Final Verdict

**PROCEED WITH CAUTION**

The Semantic Drift Judge provides clear, empirical value over exact hash pinning and static rules. Phase 4 development is justified, provided architectural safeguards account for local LLM formatting instability and latency constraints.
