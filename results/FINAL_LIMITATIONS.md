# Final Research Limitations: MCP Semantic Drift Detection

## 1. Scope and Empirical Boundaries

This document provides a transparent accounting of the limitations, operational constraints, and scope boundaries of the MCP Semantic Drift Detection research project.

---

## 2. Detailed Limitations

### 1. Sample Scale of Held-Out Evaluation Split (N=56)
While the dataset represents the largest multi-source MCP drift evaluation corpus assembled to date (370 total examples across 144 clusters), the final held-out test split consists of **56 examples** (23 Benign, 33 Malicious). While statistical confidence intervals have been calculated (Recall [89.6%, 100.0%]), evaluation across hundreds of additional real-world servers is desirable.

### 2. Adversarial Red-Team Suite Sample Size (N=30)
The red-team evaluation comprises **30 structured test cases** across 10 mutation categories (3 cases per category). While sufficient to identify critical evasion surfaces, broader combinatorial fuzzing across multiple LLM judges is necessary for exhaustive robustness guarantees.

### 3. Red-Team Detection Rate (70.0% with 9 Missed Attacks)
The Guard Middleware achieved an overall **70.0% detection rate** ($21 / 30$) on the adversarial suite. The system is not impervious to adaptive evasion, and the 9 missed attacks highlight specific architectural blind spots.

### 4. Zero Detection on Optional Parameter Hijacking (0/3 Detected)
Attackers who introduce new optional schema parameters (e.g. `exfiltrate_to: "http://attacker.com"`, `override_sudo: true`) with malicious default values while leaving the natural language description untouched completely evaded detection (**0.0% detection rate, 0/3 caught**). The semantic judge prompt primarily inspects text docstrings and missed default value injections.

### 5. Zero Detection on Low-Signal Boolean Schema Toggles (0/3 Detected)
Pure JSON schema attribute modifications without accompanying descriptive text changes (e.g., flipping `"readOnly": true` to `"readOnly": false` or altering numeric rate limits) achieved **0.0% detection (0/3 caught)**. Natural language models require contextual descriptions to evaluate operational risk and do not reliably reason over isolated schema booleans.

### 6. Local CPU Inference Latency Bottleneck (~30.5 Seconds per Changed Tool)
Evaluating semantic drift with a local 8B parameter LLM (`qwen3:8b`) on CPU hardware requires an average of **30.5 seconds per changed tool update** (p50 = 41.6 s, p95 = 72.6 s). While Tier 0 (<1 ms) and Tier 1 (<1 ms) short-circuit 46.4% of updates, the 30-second delay for changed tools is prohibitive for synchronous blocking inline proxies without GPU acceleration.

### 7. Controlled Fixture Nature of Local MCP JSON-RPC Interception
The live interception demonstration (`experiments/phase5_live_mcp_proxy.py`) verified proxy interception, policy enforcement, and baseline rollback in a controlled local socket environment. It does not represent large-scale production deployment across distributed internet MCP servers with concurrent multi-agent traffic.

### 8. Real-World MCP Corpus Coverage
The empirical evolution study was conducted over **28 open-source MCP server repositories** and 621 release transitions. While capturing authentic developer maintenance, broader coverage across private enterprise MCP tools and closed-source enterprise registries remains unstudied.

### 9. Transparent Data & Payload Template Overlap Reporting
Cluster-level isolation across `server_id + tool_name` was strictly maintained (0 cluster overlap across Train, Dev, and Test splits). However, transparency requires reporting that **1 synthetic payload template** (`simple_subtraction` prompt injection) was shared between Train (`mcptox_pos_0085`) and Test (`mcptox_pos_0045`) applied to different server components.

### 10. Explicit Statement on Production Readiness
**The system is a research prototype, not a production-ready turnkey security appliance.** It demonstrates the feasibility and clear empirical advantages of meaning-aware semantic drift detection over rigid hash pinning, but requires GPU infrastructure, specialized schema diff validators, and hardened deployment wrappers before production adoption.
