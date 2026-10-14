# MCP Literature Search Log (`paper/LITERATURE_SEARCH_LOG.md`)

**Date of Execution:** 2026-10-14  
**Venues Audited:** arXiv, Google Scholar, ACL Anthology, GitHub, Industry AI Security Bulletins  
**Methodology:** Live WebSearch across pre-registered query set targeting MCP security, supply-chain rug pulls, tool poisoning, and drift detection.

---

## 1. Executed Search Queries & Retrieved Top Hits

### Query 1: `"MCP rug pull"` / `"Model Context Protocol rug pull"`
- **Hit 1.1**: *Loginsoft Security Alert: Emerging Vulnerabilities in AI Supply Chains - MCP Server Rug Pulls* (2026). Explains how approved MCP servers can silently mutate descriptions or schemas post-deployment.
- **Hit 1.2**: *IEEE / arXiv: Mas et al., Enhanced Tool Definition Interface (ETDI) for Secure Agent Interoperability* (2026). Proposes cryptographic signing for MCP tool definitions.
- **Hit 1.3**: *ReversingLabs: Post-Deployment Drift and Supply Chain Attacks in Model Context Protocol* (2026). Threat model analysis of time-based tool alterations.
- **Hit 1.4**: *Microsoft AI Security & MCP Gateway: Mitigating Dynamic Tool Tampering* (2026). Recommends runtime proxies and network-level policy controls.

### Query 2: `"MCP tool definition drift"`
- **Hit 2.1**: *Fixzi.ai Engineering: Tool Definition Drift in Agentic Workflows* (2026). Examines divergence between client agent prompt baselines and upstream tool definitions.
- **Hit 2.2**: *OWASP Top 10 for LLMs (LLM07: System Information Leakage & LLM09: Overreliance on Tool Descriptions)* (2025/2026). Details risk of shifting tool descriptions.
- **Hit 2.3**: *MCPManager.ai: Managing Schema Drift Across Distributed MCP Endpoints* (2026). Operational tooling for monitoring breaking schema changes.

### Query 3: `"incremental tool poisoning"`
- **Hit 3.1**: *arXiv: Wang et al., MCPTox: Benchmarking Tool-Use LLMs against Tool Poisoning Attacks* (2025). Benchmark evaluating LLMs against malicious tool descriptions.
- **Hit 3.2**: *Dev.to / AI Security Hub: Phased and Incremental Attacks on LLM Tool Metadata* (2026). Conceptual discussion of multi-stage prompt injection via tool descriptions.
- **Hit 3.3**: *arXiv: Shi et al., ToolHijacker: Exploring Security Risks of Tool Definitions in LLM Agents* (2025). Investigates how subtle phrasing redirects argument generation.

### Query 4: `"MCP tool update monitoring"`
- **Hit 4.1**: *Practical DevSecOps: Continuous Security Monitoring for Model Context Protocol Servers* (2026). Proposes CI/CD static checks for MCP manifests.
- **Hit 4.2**: *Akto.io: MCP Security Gateways and API Change Detection* (2026). Discusses API gateway architectures for inspecting MCP JSON-RPC messages.

### Query 5: `"semantic drift detection tool descriptions"`
- **Hit 5.1**: *Brito et al. (2018) & Dig & Johnson (2006): API Evolution and Breaking Changes in Software Engineering*. Foundational software engineering literature on semantic versioning and API drift.
- **Hit 5.2**: *arXiv: Concept Drift and Semantic Shifts in Natural Language Interfaces* (2024). Evaluates NLP model degradation over shifting domain vocabularies.

### Query 6: `"MCP tool pinning"`
- **Hit 6.1**: *Unbound Compute: Cryptographic Tool Pinning for Model Context Protocol* (2026). Demonstrates SHA-256 digest pinning of tool JSON definitions.
- **Hit 6.2**: *NHIMG / Security: Dependency Pinning vs. Tool Pinning in AI Agent Architectures* (2026). Analyzes operational friction of rigid hash pinning.

---

## 2. Deep-Dive Review of Closest 5 Prior Works

| # | Work / Citation | Core Focus & Coverage | Difference from This Work |
|---|---|---|---|
| **1** | **Mas et al. / ETDI (arXiv, 2026)** | Proposes cryptographic author signing and identity verification for MCP tool definitions to prevent third-party tampering. | Author provenance signing (Tier 0.5) assumes authorized maintainers are non-malicious; blind to insider maintainer rug-pulls or multi-step salami drift where validly signed updates incrementally erode constraints. |
| **2** | **Wang et al. / MCPTox (arXiv, 2025)** | Evaluates downstream LLM agent vulnerability to single-step, point-in-time poisoned tool definitions. | Evaluates downstream execution susceptibility to overt payloads at a single snapshot; does not model or evaluate temporal version drift across sequential releases or multi-step capability creep. |
| **3** | **OWASP Top 10 for LLMs (2025/2026)** | Classifies supply-chain vulnerabilities, indirect prompt injection via tool descriptions, and unvalidated tool execution. | High-level threat taxonomy; does not formulate defense middleware, sequential semantic diffing, or empirical false-alarm benchmarking on benign evolution. |
| **4** | **ReversingLabs MCP Security (2026)** | Analyzes threat vector where external MCP endpoints silently alter tool definitions post-approval. | Qualitative threat advisory recommending exact hash pinning or dependency locking; does not evaluate semantic drift vetting or measure false-alarm costs on legitimate open-source updates. |
| **5** | **Fixzi / Unbound Compute (2026)** | Implements cryptographic hash pinning (SHA-256 over JSON tool schemas) to reject altered definitions. | Exact cryptographic pinning answers only binary identity, triggering a 100% false-alarm rate on benign evolution (13/13 refactorings); this work introduces multi-tier semantic drift vetting to permit benign refactoring while arresting malicious creep. |

---

## 3. Findings & Synthesis

1. **No Prior Multi-Step Drift Defenses**: Across all retrieved literature, no published work proposes, formalizes, or evaluates defenses against **multi-step, incremental tool-definition drift** ("salami attacks") where capability escalation is partitioned across multiple subtle release updates.
2. **Defensive Claim Verification**: The statement in Section 1.3 (*"To our knowledge, no prior defense evaluates whether a sequence of individually subtle updates accumulates into a malicious capability escalation"*) remains **supported and intact**, grounded in this systematic literature search.
3. **Audit History Note**: The prior reference in Section 3.1 noted a search on 13 Oct 2026; this formal log documents the full query set, retrieved records, and comparative analysis executed across 13–14 Oct 2026.
