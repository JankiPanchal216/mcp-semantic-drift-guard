# MCP Literature Search Log (`paper/LITERATURE_SEARCH_LOG.md`)

**Date of Execution:** 2026-10-14  
**Venues Audited:** arXiv, Google Scholar, ACL Anthology, GitHub, Industry AI Security Bulletins  
**Methodology:** Live WebSearch across 8 targeted queries addressing Model Context Protocol (MCP) security, supply-chain rug pulls, tool poisoning, schema drift, tool pinning, and semantic drift detection.

---

## 1. Executed Search Queries & Top 5 Retrieved Hits per Query

### Query 1: `"MCP rug pull attack"`
- **Hit 1**: *Akto.io: MCP Security Risks & Emerging Rug Pulls in Model Context Protocol* (2026). Threat advisory describing post-approval schema mutations and runtime redirection.
- **Hit 2**: *Loginsoft Security Alert: Emerging Vulnerabilities in AI Supply Chains - MCP Server Rug Pulls* (2026). Explains how approved MCP servers can silently mutate descriptions or schemas post-deployment.
- **Hit 3**: *SecureW2: Model Context Protocol Rug Pull Attack & Tool Poisoning* (2026). Overview of implicit trust exploitation in AI agent connections.
- **Hit 4**: *Natoma.ai: MCP Rug Pulls and Tool Poisoning in AI Agent Workflows* (2026). Mechanics of prompt injection delivered via dynamically refreshed tool descriptions.
- **Hit 5**: *Bhatt et al. (arXiv:2506.01333): ETDI - Mitigating Tool Squatting and Rug Pull Attacks in Model Context Protocol* (2025/2026). Architectural proposal for OAuth and cryptographic manifest signing.

### Query 2: `"MCP tool definition drift"`
- **Hit 1**: *Fixzi.ai Engineering: Tool Definition Drift in Agentic Workflows* (2026). Evaluates silent divergence between client agent prompts and upstream server schemas.
- **Hit 2**: *IEEE Computer Society: Tool Schema Drift and Index Staleness in AI Protocols* (2026). Technical analysis of tool discovery caching and dynamic RPC drift.
- **Hit 3**: *ModelContextProtocol.io: Specification - Managing Schema Changes and notifications/tools/list_changed* (2024/2026). Official protocol guidance on dynamic tool catalog refresh.
- **Hit 4**: *MintMCP: Mitigating Tool Poisoning and Semantic Drift in MCP Architectures* (2026). Runtime gateway patterns for inspecting modified tool definitions.
- **Hit 5**: *BusinessMCP: Schema Monitoring and Drift Baselines for Production Agents* (2026). Operational monitoring strategies for tracking tool schema modifications across deployments.

### Query 3: `"incremental tool poisoning MCP"`
- **Hit 1**: *MCPManager.ai: Phased Prompt Injection & Incremental Tool Poisoning in Model Context Protocol* (2026). Threat analysis of multi-stage prompt expansion and parameter drift in MCP.
- **Hit 2**: *OWASP Top 10 for LLMs (LLM07: System Information Leakage & LLM09: Misconfiguration / Tool Supply Chain)* (2025/2026). Identifies incremental tool metadata tampering as an emerging supply-chain risk.
- **Hit 3**: *Pluto Security: Dynamic Tool Poisoning and Rug Pulls in Agent Tool Registries* (2026). Case studies of tools altering behavior after initial user vetting.
- **Hit 4**: *TrueFoundry: Defending LLM Agents Against Context Manipulation and Poisoned Tool Descriptions* (2026). Architectural recommendations for sandboxing and validating untrusted tool descriptions.
- **Hit 5**: *Cloud Security Alliance (CSA): Securing Agent Interfaces Against Evolving Tool Metadata* (2026). Working group checklist on change detection for agent tool definitions.

### Query 4: `"MCP tool pinning versioning"`
- **Hit 1**: *Medium (AI Engineering): Why MCP Needs Tool-Level Versioning and Pinning* (2026). Analysis of prompt breakage and security degradation from unversioned `@latest` tool servers.
- **Hit 2**: *LeoY Blog: The Latest Trap - Strict Version Pinning for Model Context Protocol* (2026). Examines failure modes of dynamic server resolution in agent clients.
- **Hit 3**: *LaunchDay Advisors: Semantic Versioning and Gateway Enforcement for MCP Tools* (2026). Enterprise gateway patterns for pinning immutable tool hashes.
- **Hit 4**: *GitHub (modelcontextprotocol/servers): Tool Naming, Scoping, and SemVer Best Practices* (2025/2026). Community guidelines on versioning individual MCP tools.
- **Hit 5**: *NHIMG / Security: Tool Pinning vs. Dependency Pinning in Agent Architecture* (2026). Contrasts package-level lockfiles with runtime schema digest pinning.

### Query 5: `"ETDI MCP rug pull"`
- **Hit 1**: *Bhatt, Narajala, Habler (arXiv:2506.01333): ETDI - Mitigating Tool Squatting and Rug Pull Attacks in Model Context Protocol (MCP) by using OAuth-Enhanced Tool Definitions and Policy-Based Access Control* (2025). Proposes OAuth 2.0 authorization, cryptographic manifest signing, and PBAC.
- **Hit 2**: *ResearchGate: ETDI Protocol Specification and Access Control Framework* (2025). Full reprint and discussion of ETDI identity attestation.
- **Hit 3**: *SecureW2: Cryptographic Identity & Policy-Based Access Control in MCP (ETDI)* (2026). Practical implementation review of ETDI in enterprise agent clusters.
- **Hit 4**: *Loginsoft: ETDI Architectural Analysis for AI Agent Supply Chain Security* (2026). Evaluates ETDI's resistance against third-party man-in-the-middle tampering.
- **Hit 5**: *VulnerableMCP.info: Evaluating ETDI for Tool Integrity and Tamper Resistance* (2026). Benchmarks cryptographic verification overhead in MCP message loops.

### Query 6: `"mcp-scan tool pinning"`
- **Hit 1**: *Invariant Labs: mcp-scan - Open-Source Security Scanner for Model Context Protocol Servers* (2025). Introduces static keyword scanning, secret detection, and tool definition hashing.
- **Hit 2**: *Snyk / Stytch: Securing MCP Deployments with mcp-scan Hash Tracking and Tool Pinning* (2025/2026). Explains how mcp-scan crawls client configurations, hashes tool manifests, and flags rug pulls.
- **Hit 3**: *Invariant Labs GitHub (snyk/agent-scan, formerly invariantlabs-ai/mcp-scan)* (2025). Repository implementing tool manifest digest tracking and baseline storage in `~/.mcp-scan`.
- **Hit 4**: *AI Thinker Lab: Preventing Rug Pulls via Cryptographic Tool Manifest Pinning in mcp-scan* (2026). Tutorial on integrating `mcp-scan` into local developer workflows and CI/CD pipelines.
- **Hit 5**: *NHIMG: Evaluating mcp-scan Tool Pinning Against Upstream Schema Alterations* (2026). Empirical review showing that exact digest pinning flags all schema modifications indiscriminately.

### Query 7: `"semantic drift detection tool descriptions LLM agents"`
- **Hit 1**: *Trussed.ai: Semantic Drift Detection and Evaluation in Autonomous LLM Agents* (2026). Surveys high-dimensional drift tracking in long-running agent workflows.
- **Hit 2**: *Dataiku: Monitoring Intent, Embedding Distance, and Conversational Drift in Agent Workflows* (2026). Measures cosine distance on agent outputs and system instructions.
- **Hit 3**: *Galileo: Galileo Protect / Evaluate - High-Dimensional Semantic Drift and Model Output Tracking* (2025/2026). Industrial platform tracking evaluation and prompt drift.
- **Hit 4**: *Arize AI: Phoenix - Tracing Agent Steps and Monitoring LLM-as-a-Judge Calibration Drift* (2025/2026). Observability framework for step-level evaluation rubrics.
- **Hit 5**: *Future AGI: Multi-Layer Drift Tracking Across Retrieval Corpus, Prompts, and Agent-Step Execution* (2026). Framework categorizing prompt drift, input distribution drift, and judge calibration shifts.

### Query 8: `"MCP security survey tool update"`
- **Hit 1**: *Practical DevSecOps: MCP Security Survey - Access Control and Authentication Gaps in Production* (2026). Survey finding lack of dynamic authentication across public MCP servers.
- **Hit 2**: *SlowMist: MCP Security Checklist, Verification Tools, and Self-Assessment Frameworks* (2026). Community checklist for inspecting tool registrations and privilege escalations.
- **Hit 3**: *Cloud Security Alliance (CSA): Model Context Protocol Security Working Group Guidance* (2026). Threat taxonomy covering unauthenticated endpoints and parameter tampering.
- **Hit 4**: *Checkmarx: Formal Specification Audits, State Handle Hijacking, and Protocol Security in MCP* (2025/2026). Identifies lack of capability attestation and session handle hijacking.
- **Hit 5**: *Anthropic MCP Inspector / CyberMCP / Akto: Runtime Testing and Penetration Testing Frameworks* (2025/2026). Developer and security tooling for inspecting JSON-RPC message exchanges.

---

## 2. In-Depth Analysis of Key Prior Defenses

### Enhanced Tool Definition Interface (ETDI; Bhatt, Narajala, & Habler, arXiv:2506.01333)
Bhatt et al. propose the **Enhanced Tool Definition Interface (ETDI)** to address tool squatting and rug-pull attacks in MCP deployments. ETDI augments the baseline protocol by integrating OAuth 2.0-based authorization frameworks with cryptographic tool manifest signing and Policy-Based Access Control (PBAC; implemented via engines like Cedar and Amazon Verified Permissions). Under ETDI, tool providers digitally sign their tool manifests (names, descriptions, and input schemas). A client or gateway validates the author's cryptographic signature against trusted identity providers before allowing the agent to discover or invoke the tool. Any post-approval tampering by an unauthorized third party alters the manifest digest, invalidating the signature and halting execution. 

**Difference from this work**: ETDI operates primarily as an **author provenance and identity authentication mechanism** (Tier 0.5 in our defensive hierarchy). It assumes that a validly signed tool definition from an authorized identity is trustworthy. Consequently, ETDI is structurally blind to: (1) insider maintainer rug pulls, where legitimate server maintainers intentionally introduce malicious capability escalations; (2) compromised developer signing credentials; and (3) multi-step salami drift, where each validly signed incremental release subtly loosens constraints or introduces preparatory components. Furthermore, ETDI enforces a binary valid/invalid outcome; any legitimate maintenance edit requires a re-signing and manual authorization workflow. In contrast, our work operates as **content-aware semantic inspection middleware** (Tiers 1–3), inspecting the actual natural language and schema deltas across version lineages to distinguish legitimate software evolution from subtle capability expansion without relying on maintainer benevolence.

### Snyk Agent Scan / `mcp-scan` (Invariant Labs & Snyk Research)
`mcp-scan` (open-sourced by Invariant Labs and maintained within Snyk's security ecosystem as `snyk-agent-scan`) is a client-side scanner for MCP servers, client configurations, and agent skills. According to official repository documentation (`https://raw.githubusercontent.com/invariantlabs-ai/mcp-scan/main/README.md`, verified October 14, 2026), Agent Scan automatically discovers agent components and submits tool descriptions and parameters to the Snyk analysis API (14 risk categories in v0.6+ using the `2026-07-10` analysis API, or 15+ issue codes in v0.5.x using the `2025-09-02` API) to detect prompt injection, tool poisoning, tool shadowing, and toxic flows.

**Audit and Attribution Decision (Logged October 15, 2026)**:
1. *Architectural Description*: The documentation states that Agent Scan discovers configurations/servers and queries the cloud-hosted Snyk analysis API. Earlier draft notes informally mentioning "static AST inspection and YARA pattern matching" were ungrounded; the documentation explicitly specifies Snyk API-driven analysis across 14–15 risk categories. The paper text has been confirmed and corrected to reflect this API-based mechanism.
2. *Evaluation Attribution Distinction*: `mcp-scan` itself was **not evaluated** across Benchmark V4. The 0.0% recall (0/26) reported in baseline evaluations corresponds strictly to our own internal Tier 2 static regular expression baseline (`guard/static_rules.py`). All paper tables and text have been updated to explicitly attribute this metric to "our Tier 2 static-regex baseline, which is not mcp-scan" and to note that external proprietary `mcp-scan` binaries were not run.
3. *Cryptographic Baseline Comparison*: When tool pinning is enabled, exact cryptographic digest comparison (SHA-256) flags 100% (13/13) of legitimate pre-existing contract refactorings in our real-world open-source corpus audit, imposing substantial operator review burden.

---

## 3. Evaluation of Sequential / Multi-Step Tool Definition Literature

Across all 8 audited queries and retrieved papers (including MCPTox [Wang et al., 2025], ToolHijacker [Shi et al., 2025], MCP-SafetyBench [Zong et al., 2025], Hou et al. [2025], and Mas et al. [2026]):
1. **Focus on Single-Step Attacks**: Existing benchmarks and evaluations exclusively test **single-step, point-in-time attacks** where a tool definition is either poisoned at deployment or replaced in a single abrupt update with an overt payload.
2. **Absence of Multi-Step Trajectory Defenses**: No retrieved published work formalizes, benchmarks, or defends against **multi-step, sequential tool-definition drift** ("salami rug-pulls") where an attack is incrementally assembled across a lineage of individual updates that appear innocuous in isolation.
3. **Defensive Novelty Confirmation**: The claim in Section 1.3 (*"To our knowledge, no prior defense evaluates whether a sequence of individually subtle updates accumulates into a malicious capability escalation across dynamic tool-update lifecycles"*) is fully grounded and verified against this search log.
