# Research Paper Changelog (`paper/CHANGES.md`)

This changelog records all substantive and structural modifications made to `paper.md`, tracking rationale and mapping each change to specific reviewer findings.

---

## [Phase A–E Overhaul] - 2026-10-08 - Decision Rule Audit, Trace Provenance & Complete Bibliography Verification

### Decision Rule & Metric Reconciliation (`paper/DECISION_RULE_AUDIT.md`)
- Conducted full audit of transition-level vs. chain-level decision rules across `experiments/evaluate_salami_drift_v3.py`, `scripts/stats.py`, and `results/salami_drift_v3_*/predictions.jsonl`.
- Evaluated and reported 3 decision rule variants side-by-side: (a) Strict MALICIOUS only, (b) Non-BENIGN alert (strict $k \ge m$), and (c) Directly parsed decisions only (excluding fallbacks).
- Analyzed parse fallbacks (31/576 calls, 5.4%): confirmed that fallbacks occurred primarily on benign chains (10 benign vs. 3–5 malicious), inflating benign-chain FPR to 50.0% (8/16 chains). Directly parsed benign-chain FPR is 12.5% (2/16). Salami-only chain recall is 93.8% (15/16) with or without fallbacks.
- Corrected early-false-alarm bug: enforced strict step $k \ge m$ condition, preventing preemptive credit for alerts before attack steps.

### Salami-Only vs. Fast-Jump Split & Head-to-Head Comparison
- Split malicious trajectories into **Salami-only** (16 chains: Categories A, D, E, F, G) and **Fast-jump positive controls** (8 chains: Category B).
- Promoted Salami-only recall (Observed **93.8% (15/16)** [95% CI: 69.8%, 99.8%]) as the headline empirical result.
- Compared Cumulative and Dual-Anchor head-to-head: confirmed identical chain recall (91.7% / 93.8% Salami), identical benign chain FPR (50.0% / 12.5% parsed), and non-significant transition difference ($p = 0.37500$), establishing that Dual-Anchor does not statistically outperform pure Cumulative comparison while incurring 2x LLM cost.
- Replaced all bootstrap means presented as point estimates with exact observed point estimates and Wilson score CIs.

### Bibliography & Provenance Verification (`paper/CITATION_CHECK.md`)
- Confirmed every citation in `paper/references.bib` against live sources (arXiv, publisher DOIs, DBLP).
- Corrected exact metadata for:
  - Wang et al. (MCPTox; arXiv:2508.14925; full 9-author list)
  - Zong et al. (MCP-SafetyBench; arXiv:2512.15163 / ICLR 2026; full 5-author list)
  - Shi et al. (ToolHijacker / Tool Selection Prompt Injection; arXiv:2504.19793 / NDSS 2025; full 6-author list)
  - Mas et al. (Trustworthy MCP Registry; *Future Internet* 2026, 18(5):243, DOI: 10.3390/fi18050243)
  - Newman, Meyers, & Torres-Arias (Sigstore; ACM CCS 2022, pp. 2353–2367, DOI: 10.1145/3548606.3560673)
  - Brito, Xavier, Hora, & Valente (*Why and How Java Developers Break APIs*; IEEE SANER 2018, pp. 255–265)
  - Dig & Johnson (JSME 2006, 18(2):83–107)
  - Rebedea et al. (NeMo Guardrails; EMNLP 2023 System Demos, pp. 431–445)
  - Inan et al. (Llama Guard; arXiv:2312.06674)
  - Snyk Research / Invariant Labs (`snyk-agent-scan` / `mcp-scan`, 2025)
  - W3C Subresource Integrity (2016)
- Built `scripts/check_citations.py` ensuring bidirectional consistency.

### Expected Failures Documentation (4 Tests)
The test suite reports `Ran 93 tests in 1.188s, OK (expected failures=4)`. The 4 expected failures are:
1. `TestCorruptedPaperMustFail.test_corrupted_table_tp_fails`: Intentionally injects corrupted TP (99 vs 33) into Table 6.2 to prove that test assertions catch paper corruption.
2. `TestCorruptedPaperMustFail.test_corrupted_table_precision_ci_fails`: Intentionally injects corrupted CI into Table 6.2 to prove that CI validation catches table tampering.
3. `TestCorruptedPaperMustFail.test_legacy_latency_injection_fails`: Intentionally injects an unverified legacy number (1.42s) into paper text to prove that legacy token scanners trigger test failures.
4. `TestRollbackSafety.test_breaking_schema_rollback_incompatibility`: Verifies that introducing required arguments causes upstream RPC runtime rejection, demonstrating why breaking changes must escalate to Full Tool Quarantine rather than transparent rollback.

---

### Claims & Traceability Verification
- Created `paper/CLAIMS_MATRIX.md` mapping every empirical claim, quantitative metric, and statistical significance test in `paper.md` directly to its backing results artifact, script, and git commit (`93834f9`).
- Confirmed zero placeholder leaks or unauthorized claims across `paper.md`.
- Verified that all 93 unit and regression tests in `tests/` pass with zero regressions.

---

## [Phase 6] - 2026-10-08 - Paper Narrative Reframing & Contributions

### Title & Narrative Positioning
- Updated paper title to: **"Salami Rug-Pulls in the Model Context Protocol: Detecting Incremental Tool-Poisoning Attacks via Dual-Anchor Semantic Drift Vetting"**.
- Reframed the Abstract to lead directly with the multi-step incremental semantic drift (Salami Drift) threat model, contrasting semantic vetting against exact byte-level pinning and static scanners, and highlighting Dual-Anchor monitoring gains ($70.0\%$ transition recall, $91.7\%$ chain detection, $0.38$ mean exposure window).

### Contributions & Boundaries
- Expanded Section 1.4 into 5 distinct, rigorous contributions:
  1. Longitudinal measurement of open-source MCP evolution ($N=621$ releases, $4.99\%$ change rate).
  2. Formalization of Salami Drift and the leakage-screened Benchmark V3 ($N=144$ transitions, 40 chains).
  3. Multi-tier Guard middleware architecture ($< 0.25\text{ ms}$ fast-paths + XML-sandboxed LLM reasoning).
  4. Dual-Anchor monitoring and cluster-bootstrapped trajectory statistical validation.
  5. Transparent open reproducibility suite pinned at commit `93834f9`.
- Enhanced Section 11 (Limitations & Methodological Boundaries) with 10 explicit operational frontiers (intra-tool scope, benign accumulation over long sequences, JSON parse fallback dynamics, and oracle baseline evaluation boundaries).

---

## [Phase 5] - 2026-10-08 - Table Generation Automation & Trace Provenance

### Automated Table Regeneration Engine (`scripts/make_tables.py`)
- Implemented `scripts/make_tables.py` parsing raw prediction traces (`results/main_test_hash/predictions.jsonl`, `results/main_test_static/predictions.jsonl`, `results/main_test_tfidf/predictions.jsonl`, `results/salami_drift_v3/computed_metrics.json`, and `results/STATISTICAL_REPORTING.json`).
- Recomputes exact confusion matrices, Wilson score 95% CIs, cluster bootstrap 95% CIs, and mean CPU latencies without hardcoding.
- Generates master Markdown tables in `results/tables/tables_markdown.md` for:
  - Table 1: Comparative Taxonomy Matrix of Defensive Paradigms.
  - Table 2: Held-Out Benchmark Results ($N=56$).
  - Table 3: Master Evaluation Comparison Matrix (Configs A–H).
  - Table 4: Transition-Level Salami Drift Benchmark V3 Results ($N=144$).
  - Table 5: Chain-Level Trajectory Outcomes ($N=40$).
  - Table 6: Multi-Model Local Judge Comparison ($N=56$).
- Added regression test suite `tests/test_make_tables.py`.

---

## [Phase 4] - 2026-10-08 - Judge Interface, Schema Parsing & Model Verification

### Judge Architecture & XML Sandboxing (`guard/semantic_judge.py`)
- Standardized Mode B diff prompt encapsulation using `<untrusted_diff>` XML sandboxing delimiters across `guard/semantic_judge.py` to ensure consistency with architectural specifications and injection-resistance requirements.
- Confirmed JSON schema extraction and repair flow:
  1. Deep `<think>...</think>` reasoning token removal.
  2. Substring JSON object extraction with `\{[\s\S]*\}`.
  3. Strict label vocabulary normalization (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`).
  4. Single-retry temperature-0 JSON converter fallback before triggering `BALANCED` policy quarantine.
- Documented model trade-off: `gemma3:4b` provides high parse stability (100% in diagnostic, ~13.8s on CPU) for live multi-step benchmark execution, while `qwen3:8b` serves as the primary GPU/high-capacity baseline.

---

## [Phase 3] - 2026-10-08 - Statistical Rigor, Bootstrap CIs & Exposure Metrics

### Statistical Module (`scripts/stats.py`)
- Created `scripts/stats.py` implementing exact McNemar tests across both transition and chain levels.
- Implemented stratified cluster bootstrap ($B=10,000$ iterations, fixed seed `42`) over 40 chains (24 malicious, 16 benign) to compute empirical 95% confidence intervals and standard errors for Chain Recall, Benign Chain FPR, Chain Precision, Chain $F_1$, and Mean Exposure Window.
- Generated verifiable statistical reporting artifact at `results/STATISTICAL_REPORTING.json`.
- Added regression test suite `tests/test_stats.py` verifying exact reproduction of transition McNemar $p$-values ($p=0.21011$ and $p=0.02246$) and edge case behavior.

### Paper Enhancements (`paper.md`)
- **Section 5.1**: Added Section 5.1.4 formally defining multi-step trajectory metrics: Chain Recall, Benign Chain FPR, and the mathematical formulation of the Mean Exposure Window ($\bar{W}_e$).
- **Section 9.5.4 & 9.5.5**: Enriched transition and chain-level outcome tables with 95% Wilson and Cluster Bootstrap confidence intervals.
- **Hypothesis Testing**: Added paired chain-level McNemar exact test on malicious trajectories ($p = 0.00781$, showing statistically significant superiority of Dual-Anchor over Adjacent monitoring in recovering evasive chains) and empirical bootstrap difference distributions.

---

## [Phase 2] - 2026-10-08 - Related Work Rewrite & Taxonomy

### Related Work Overhaul (Section 3)
- Restructured Section 3 into five rigorous thematic subsections:
  1. *Tool-Poisoning Attacks and Agent Safety Benchmarks* (MCPTox, MCP-SafetyBench / Hou et al., ToolHijacker).
  2. *Cryptographic Signing, Provenance, and Pinning* (Mas et al., Sigstore, in-toto).
  3. *Static Capability Scanners and Monolithic LLM Vetting* (mcp-scan / Shen et al., SecAgent / Hasan et al.).
  4. *API Evolution, Breaking Changes, and Semantic Drift* (Hu et al., Bhardwaj et al.).
  5. *Comparative Analysis of Defensive Paradigms*.
- Constructed Table 1: Comparative taxonomy mapping defenses (Exact Pinning, Cryptographic Signing, Static Scanners, Monolithic LLM Vetting, and MCP Semantic Drift Guard) against Threat Model, Detection Targets, Blind Spots, and Operator Review Burden.
- Expanded `paper/references.bib` and in-text bibliography with AAAI, IEEE S&P, ICSE, and FSE citations (Hou et al. 2025, Mas et al. 2026, Shen et al. 2024, Hasan et al. 2024, Hu et al. 2023, Bhardwaj et al. 2024).

---

## [Phase 1] - 2026-10-08 - Citations, Terminology & Structural Corrections

### Bibliographic & Citation Fixes
- Created verified BibTeX file at `paper/references.bib`.
- Corrected primary authorship of MCPTox from Zhang et al. to **Wang, Li, Zhao, Zhang, & Xie (AAAI 2026 / arXiv:2508.14925)** across all in-text citations and reference list.
- Corrected authorship of Sigstore to **Newman, Meyers, & Torres-Arias (ACM CCS 2022)**.
- Standardized Llama Guard publication year to **Inan et al. (2023, arXiv:2312.06674)** across text and bibliography.
- Flagged ToolHijacker (`arXiv:2407.12345`) in `paper/TODO_UNVERIFIED.md` as requiring preprint ID verification.

### Terminology & Claim Calibrations
- Reframed Section 2.2 from the speculative "Capability Paradox" to **Reasoning-Mode Vulnerability (Replication of MCPTox)**. Explicitly cited Wang et al.'s original +27.8 percentage point increase alongside our local Qwen3-8B +27.79 percentage point replication.
- In Abstract, added qualification: *"aiming to reduce manual operator reapproval burden (longitudinal replay designated future work)"* to ensure claims do not exceed active empirical measurements.
- Added headline Salami Drift Benchmark V3 transition recall (70.0%, $F_1=0.800$, McNemar $p=0.02246$) to the Abstract.

### Architecture & Pipeline Consistency
- Updated Section 5.2 to explicitly specify a **5-tier operational pipeline (Tiers 0, 1, 1.5, 2, 3)** matching the system diagrams.
- Generalized Tier 3 description from model-specific hardcoding to structured zero-temperature diff reasoning.
- Clarified Section 8.1 Note on Config H to explain that it evaluates the complete deterministic fast-path (Tiers 0, 1.5, 2 without LLM), distinguishing it from Config B (Tier 2 regex alone).

### Structural Refactoring & Audit Neutrality
- Streamlined Section 9.5.1 to focus on the Salami Drift threat model and authoritative V3 protocol.
- Moved historical V1 (static rule leakage) and V2 (mock label leakage invalidation) narrative to **Appendix B: Historical Benchmark Progression (V1 and V2 Iterations)** written in neutral academic prose.
- Reworded "independent audit" mentions to "internal methodological audit".
- Canonicalized Section 12 pinned repository commit to `93834f9` (with `381125b09dee2d05f23e170e32762a71f815305d` cited for deterministic test data provenance) and replaced repository URL with `[ANONYMIZED REPOSITORY URL]`.

---

## [Phase 0] - 2026-10-08 - Audit & Inventory Initialization

### Added
- Created `paper/AUDIT.md` providing an exhaustive inventory of all `[PENDING RE-RUN]` items, experimental configurations (A–H), model judge discrepancies, backing results files, and claim boundaries.
- Created `paper/TODO_UNVERIFIED.md` tracking all items requiring verification, external citations, or re-run execution.
- Established the baseline git commit hierarchy (`93834f9` as authoritative head; `381125b` as historical data export baseline).
