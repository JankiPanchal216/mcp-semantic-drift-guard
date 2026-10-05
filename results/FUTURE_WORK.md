# Future Work & Evidence-Driven Research Directions

## 1. Overview

Based on the empirical findings, error analyses, and red-team evasion boundaries identified in Phases 1 through 5, this document outlines ten concrete, evidence-driven avenues for future research and engineering.

---

## 2. Evidence-Driven Research Agenda

### 1. Dedicated Schema-Only Semantic Change Validators
- **Motivation**: Red-team evaluation demonstrated that pure boolean schema attribute toggles (`readOnly: True` $\rightarrow$ `False`) evaded text-centric LLM evaluation (0/3 detected).
- **Future Direction**: Develop structural JSON Schema analyzers that compute semantic risk scores for attribute permission relaxation, type widening, and constraint removals prior to LLM evaluation.

---

### 2. Parameter Default Value & Webhook Ingestion Rules
- **Motivation**: Red-team category `optional_parameter_hijacking` achieved 0/3 detection by injecting default URL endpoints into new optional parameters without modifying docstrings.
- **Future Direction**: Implement dedicated static inspection rules that extract and validate default string arguments for external URL domains, IP addresses, and file path redirects.

---

### 3. Multi-Step Intent & Composite Chain Reasoning
- **Motivation**: Attackers splitting exfiltration into multi-step sequences evaded detection in 2 out of 3 cases.
- **Future Direction**: Incorporate multi-hop reasoning prompts or lightweight chain-of-thought verification agents that reconstruct the end-to-end operational consequence of composite sentence sequences.

---

### 4. GPU Acceleration & Asynchronous Out-of-Band Architecture
- **Motivation**: CPU inference latency averaged 30.5 seconds per changed tool update, which is impractical for blocking synchronous inline proxies.
- **Future Direction**: Deploy the Tier 3 judge on GPU infrastructure (e.g. TensorRT-LLM, vLLM) to achieve sub-second inference, and implement an asynchronous out-of-band architecture where tools are quarantined in background staging queues without blocking agent startup.

---

### 5. Large-Scale MCP Repository Expansion & Continuous Ingestion
- **Motivation**: Phase 2 surveyed 28 servers and 621 release transitions.
- **Future Direction**: Build an automated web crawler and repository watcher to continuously index thousands of community MCP servers from GitHub, Smithery, and PulseMCP, tracking tool definition churn across millions of transitions.

---

### 6. Automated Combinatorial Adversarial Fuzzing
- **Motivation**: The 30-case red-team suite identified key failure modes; expanding this to automated fuzzing will uncover additional edge cases.
- **Future Direction**: Develop an automated LLM-in-the-loop red-teaming fuzzer that systematically mutates tool contracts across hundreds of stylistic and semantic dimensions to measure defender evasion surfaces continuously.

---

### 7. Cross-Model Benchmarking with Diverse Judge Architectures
- **Motivation**: The current evaluation utilized local `Qwen3-8B`.
- **Future Direction**: Benchmark alternative open-weight reasoning models (e.g., DeepSeek-R1-Distill, Llama-3.1-8B/70B, Mistral-Small, Gemma-2-9B/27B) to evaluate how judge model size and reasoning architecture affect detection accuracy and latency tradeoffs.

---

### 8. Real-World Client & Gateway Deployments
- **Motivation**: Live proxy interception was demonstrated in a local test fixture.
- **Future Direction**: Integrate the middleware as an official plugin/extension for production MCP clients (e.g., Claude Desktop, Cursor, Cline, OpenHands) and enterprise MCP gateways, collecting real-world operational telemetry.

---

### 9. Hybrid Formal Verification & Model-Assisted Schema Synthesis
- **Motivation**: Pure natural language models struggle with formal contract guarantees.
- **Future Direction**: Combine formal JSON Schema constraint solvers with LLM semantic reasoning to provide mathematical guarantees for parameter types and domain constraints alongside intent classification.

---

### 10. Empirical Confidence Calibration & Dynamic Thresholding
- **Motivation**: Policy engine thresholds currently use static confidence cutoffs ($0.90 / 0.95$).
- **Future Direction**: Apply temperature scaling and conformal prediction techniques to calibrate semantic judge confidence scores, providing statistically guaranteed bounds on false alarm rates under varying enterprise risk profiles.
