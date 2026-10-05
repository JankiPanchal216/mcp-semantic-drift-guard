# Claim Audit & Methodological Reframing Log

This document records the systematic review of all experimental claims, framing statements, and performance assertions across the research package. Every overly strong, unhedged, or uncalibrated claim has been audited, contextualized, and corrected.

---

## 1. Systematic Claim Correction Table

| # | File / Section | Original Risky / Uncalibrated Claim | Corrected Reviewer-Ready Wording | Methodological Rationale |
|---|---|---|---|---|
| **1** | Main Headline | *"We achieve 100% detection accuracy."* | *"The system separates integrity detection from semantic security judgment by combining exact change detection, deterministic security checks, structured diffing, and semantic analysis."* | Item 2: Report integrated middleware (100% F1 on N=56), standalone semantic judge (92.3% F1 on N=56), and 5-fold CV (89.7% ± 6.2% F1) separately. |
| **2** | Phase 5 vs Upgrade | *"Reviewer upgrade replaces Phase 5 100% result with 92.3%."* | *"Integrated middleware result (100.0% F1, 0.0% FPR on N=56) evaluates end-to-end middleware under BALANCED policy with trusted baselines, whereas standalone semantic-judge result (92.3% F1, 26.1% FPR on N=56) isolates Mode-B semantic classification on text diffs."* | Item 1: Explicitly distinguish evaluated layers rather than treating them as conflicting. |
| **3** | Hash Pinning | *"Hash pinning has a 100% False Positive Rate / Hash pinning fails."* | *"Exact hash pinning flags every observed tool-definition change because its integrity criterion is byte-level equality. In the observed corpus, 31 of 621 release transitions (4.99%) changed tool manifests, meaning these changes would trigger review under exact pinning. Among the observed maintenance changes, exact pinning could not distinguish benign evolution from malicious drift."* | Item 3: Frame as empirical alert burden, not a universal failure of cryptographic pinning. |
| **4** | Historical Corpus | *"123 semantic contract changes"* / *"Only 2.09% of tools change"* | *"123 tool-definition change events (110 additions/removals, 13 pre-existing tool-contract modifications). 13 of 621 release transitions (2.09%) contained modifications to pre-existing tool contracts."* | Items 4 & 5: Keep additions/removals separate from modifications; preserve exact denominator for 2.09%. |
| **5** | Red-Team v2 | *"The system is resilient to 14 attack categories."* | *"In a small adversarial pilot of 28 newly constructed cases spanning 14 attack categories, the guard detected 25/28 cases (89.3%). Because each category contained only two cases, this result is exploratory rather than a statistically reliable per-category estimate."* | Item 7: Accurately qualify small-sample adversarial pilot. |
| **6** | Matched-Pair Pilot | *"Matched pairs benchmark resolves dataset confound."* | *"A controlled matched-pair pilot constructed 12 benign real-update examples and 12 corresponding malicious semantic mutations. The pilot was designed to reduce writing-style confounding but is too small to establish general performance."* | Items 6 & 8: Label as pilot, not benchmark. |
| **7** | Cross-Validation | *"Cross validation proves 89.7% confidence interval."* | *"In 5-fold server-grouped cross-validation across 370 examples and 19 servers (zero server overlap between train/test within folds), the standalone judge achieved mean F1 of 89.7% ± 6.2%, recall of 100.0% ± 0.0%, and benign FPR of 23.0% ± 4.1%, where ± denotes sample standard deviation across folds."* | Item 9: Clearly identify ± as standard deviation, not confidence interval. |
| **8** | Latency Claims | *"Production-ready 1.42s guaranteed real-time latency."* | *"Fast deterministic path resolves unchanged tools in 0.024 ms; obvious deterministic attacks are blocked in 0.16 ms; changed tool definitions exhibit 1.42s mean latency on the evaluated local CPU setup. Latency depends on model, quantization, hardware, runtime, and workload. Asynchronous staging is proposed as a deployment design."* | Item 10: No production guarantees; acknowledge hardware/runtime dependencies. |
| **9** | Model Comparison | *"Qwen3-8B is universally superior to other models."* | *"On the same N=56 evaluation split under the reported evaluation configuration, Qwen3-8B achieved 92.3% F1 (1.42s latency), Gemma3-4B achieved 87.3% F1 (0.78s latency), and Qwen2.5-1.5B achieved 81.5% F1 (0.29s latency)."* | Item 11: Scope comparison to evaluated split and configuration. |
| **10** | Thinking Ablation | *"Thinking mode is completely unnecessary."* | *"On the evaluated configuration, disabling Qwen3-8B thinking reduced latency from 4.68s to 1.42s while producing similar F1 (92.3% vs 91.7%). This experiment does not establish that thinking is generally unnecessary for semantic security classification."* | Item 12: Conservative ablation interpretation. |
| **11** | Lexical Baseline | *"Embedding baseline achieved 76.5% F1."* | *"TF-IDF cosine-similarity lexical baseline achieved Precision 64.6%, Recall 93.9%, F1 76.5%, FPR 73.9% with threshold 0.59 calibrated on training/development data."* | Item 13: Accurate naming and calibration documentation. |
| **12** | Schema Checks | *"Schema security layer has universal 0% FPR."* | *"Deterministic schema checks detected the evaluated privilege-escalation and default-injection cases in under 0.10 ms, with zero false positives among the evaluated N=23 benign examples."* | Item 14: Restrict 0% FPR claim to the evaluated N=23 sample. |
| **13** | Rollback Safety | *"Transparent rollback to V1 is completely seamless."* | *"Rollback is a containment mechanism rather than a universal compatibility mechanism. While safe when V2 is compatible with V1, breaking contract changes (required parameters, removed parameters, renamed parameters) require quarantine or coordinated version handling."* | Item 15: Explicitly analyze breaking schema rollback failure modes. |
| **14** | Related Work | *"No prior work exists / First system."* | *"This work focuses on detecting semantic drift in MCP tool definitions and distinguishing benign maintenance from security-relevant changes, building on prior work in agent security (MCPTox, ToolHijack) and software supply chain integrity."* | Item 16: Proper attribution and scope. |
| **15** | Integration Test | *"Live socket proxy / Live production proxy."* | *"Local MCP JSON-RPC integration test."* | Item 21: Accurate technical labeling for local proxy test harness. |
| **16** | Deployment Limitation | *"Operationally impractical on CPU."* | *"The measured local CPU latency may be unsuitable for synchronous interactive deployment without acceleration or asynchronous staging."* | Item 21: Measured and actionable deployment phrasing. |

---

## 2. Explicit Pilot & Sample Size Registry

- **Historical Release Corpus**: $N=621$ release transitions across 12 MCP repositories (31 transitions with tool changes [4.99%], 123 tool-definition change events).
- **Descriptive Real-Contract Subset**: $N=13$ pre-existing tool contract modifications (2.09% of transitions).
- **Tool Additions / Removals**: $N=110$ events.
- **Benchmark Dataset**: $N=370$ total examples ($259$ train, $55$ dev, $56$ held-out test).
- **Controlled Matched-Pair Pilot**: $N=24$ paired cases ($12$ benign real updates, $12$ controlled mutations).
- **Adversarial Pilot Evaluation (Red-Team v2)**: $N=28$ cases across 14 categories ($n=2$ per category).
- **Prompt-Injection Robustness Pilot**: $N=4$ override cases.
- **Salami Drift Simulation**: $N=5$ sequential version increments.
