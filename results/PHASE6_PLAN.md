# Phase 6 Research Plan — Final Research Package Consolidation

## 1. Objective

Phase 6 represents the synthesis, consolidation, and packaging phase of the **MCP Semantic Drift Detection** research project. The objective is to produce a cohesive, transparent, and empirically grounded final research package that unifies all findings from Phases 1 through 5 into comprehensive documentation, error analyses, architectural specifications, reproducibility guides, and the master research report.

---

## 2. Completed Experimental Evidence Base

The research package is built strictly upon the completed empirical trajectory:
- **Phase 1 (Baseline Replication & Vulnerability Audit)**: Exact reproduction of the MCPTox benchmark on local `Qwen3-8B` (ASR = 41.76% Think / 13.97% No-Think across 1,348 instances), verifying the "Capability Paradox" where reasoning increases attack adherence. Audit of SHA-256 exact tool pinning (`snyk-agent-scan` / `mcp-scan`).
- **Phase 2 (Real-World MCP Evolution Corpus)**: Mining and static analysis of 28 open-source MCP servers across 621 release transitions and 4,961 tool comparisons, measuring a 4.99% release-level change rate (123 tool modifications) where 100% of legitimate updates trigger exact hash-pinning false alarms.
- **Phase 3 (Semantic Drift Detector Development)**: Construction of a 370-example cluster-isolated dataset (0 leakage across splits) and benchmarking of local zero-temperature `qwen3:8b` semantic judges, proving that Diff-Only Mode B ($F_1 = 92.3\%$) eliminates 75% of hash false alarms while catching 100% of injection attacks.
- **Phase 4 (Middleware Implementation & Replay Evaluation)**: Implementation of `MCPGuardMiddleware` featuring a 4-Tier pipeline (Tier 0 Hash $\rightarrow$ Tier 1 Static $\rightarrow$ Tier 2 Diff $\rightarrow$ Tier 3 Semantic Judge), configurable policy engine (`BALANCED`, `STRICT`, `AUDIT`), persistent SQLite baseline store, and rollback verification across 28 unit tests.
- **Phase 5 (Full Held-Out & Adversarial Red-Team Evaluation)**: Full-scale evaluation across the complete 56-example held-out test split ($F_1 = 100.0\%$, Benign FPR = 0.0%), a 30-case adversarial red-team suite (70.0% detection rate across 10 mutation categories), and a live local JSON-RPC socket proxy fixture (`LiveMCPGuardProxy` - Status: PASS).

---

## 3. Final Research Contribution

1. **Exact Hash Pinning Baseline**: Demonstrates that exact tool-definition hashing acts as a change detector but produces a prohibitive 100% false alarm rate on legitimate software maintenance.
2. **Empirical MCP Evolution Rates**: Measures that open-source MCP tools evolve at ~5% of releases, proving that legitimate updates are an inherent operational reality.
3. **Semantic Drift Analysis**: Shows that meaning-aware LLM evaluation over structured diffs successfully distinguishes benign documentation/schema refactoring from malicious injections.
4. **Enforcement Middleware**: Demonstrates an integrated 4-tier middleware architecture that combines sub-millisecond fast-path short-circuiting with automated policy enforcement and rollback.
5. **Trusted Baselines & Rollback**: Proves that maintaining trusted baselines prevents poisoned tool definitions from silently becoming the new trust anchor.
6. **Red-Team Robustness & Evasion Boundaries**: Evaluates adaptive attackers across 10 evasion categories, establishing clear defensive capabilities and pinpointing remaining vulnerabilities in optional parameter defaults and boolean schema attribute toggles.

---

## 4. Results Consolidation

Consolidate all quantitative measurements into a master summary document (`FINAL_RESULTS_SUMMARY.md`) and a unified comparison table (`FINAL_COMPARISON_TABLE.md`) that maintains strict separation between datasets (N=56 held-out test split, N=30 red-team suite, N=10 Phase 4 replay sample, N=10 Phase 3 sample).

---

## 5. Error Analysis

Synthesize all observed failure modes in `FINAL_ERROR_ANALYSIS.md`:
- Legitimate update false alarms under hash pinning.
- Static-rule false negatives on paraphrased and novel payloads.
- Context bloat and JSON parsing errors in Full Definition vs. Diff-Only representations.
- Red-team evasion misses (Optional parameter hijacking 0/3, Low-signal schema toggles 0/3, Multi-step intent 1/3).
- Local CPU inference latency overhead (~30.5 s average per changed tool update).

---

## 6. Architecture Documentation

Produce `FINAL_ARCHITECTURE.md` detailing the client-to-server interception boundary, the 4-tier inspection pipeline, policy evaluation mechanics, baseline SQLite schema, rollback routines, and audit logging contracts.

---

## 7. Threat Model

Formulate `THREAT_MODEL.md` defining attacker capabilities, attack surfaces (tool descriptions, input schemas, parameter docstrings), defender boundaries, and explicit out-of-scope risks.

---

## 8. Reproducibility Package

Compile `FINAL_REPRODUCIBILITY.md` detailing the exact environment (Windows, Python 3.12, Ollama `qwen3:8b` Q4_K_M, $T=0$), repository layout, test runner invocations, and experiment script mappings.

---

## 9. Final Limitations & Future Work

Document real-world operational constraints in `FINAL_LIMITATIONS.md` and evidence-driven next steps in `FUTURE_WORK.md`, highlighting the need for GPU acceleration, specialized schema validators, and expanded real-world testing.

---

## 10. Research Report Structure

Structure the final research paper (`FINAL_RESEARCH_REPORT.md`) into 15 formal sections following standard academic peer-review structure.
