# Unverified Claims, Citations, and Pending Sweeps (`paper/TODO_UNVERIFIED.md`)

This document tracks every claim, parameter, citation, or experimental configuration in the draft that requires external confirmation, empirical execution, or bibliographic verification.

---

## 1. Bibliographic & Citation Verification Needed

1. **ToolHijacker Citation**:
   - Current citation: Liu et al., 2024, `arXiv:2407.12345` (*ToolHijacker: Stealing Tool Execution in LLM Agent through Black-box Poisoning*).
   - *Action*: Verify exact arXiv identifier, conference appearance, and author list.
2. **MCPTox Authorship**:
   - Current citation in text attributes to Zhang et al.
   - *Action*: Correct primary authorship to Zhiqiang Wang, Y. Li, J. Zhao, et al. (AAAI 2026 / arXiv:2508.14925).
3. **Sigstore Authorship**:
   - Current citation in text attributes to Newman et al.
   - *Action*: Update to Newman, Meyers, Torres-Arias (ACM CCS 2022).
4. **Llama Guard Year**:
   - Cited as 2024 in text, 2023 in References.
   - *Action*: Standardize to 2023 (arXiv:2312.06674) / 2024 published.

---

## 2. Experimental Sweeps Pending Re-Execution (Phase 5)

1. **Full Tier Ablation Suite (Configs C, D, E, F, G)**:
   - Config C (Hash + Static), Config D (Hash + Static + Diff), Config E (Hash + Static + Judge), Config F (Full Pipeline), Config G (No Schema Check).
2. **5-Fold Server-Grouped Cross-Validation ($N=370$)**:
   - Full 5-fold evaluation across 19 unique servers.
3. **Adversarial Red-Team Suites**:
   - Suite v1 ($N=30$, 10 categories) and Suite v2 ($N=28$, 14 categories).
4. **13 Real Pre-Existing Modifications**:
   - Full semantic guard execution on the 13 authentic contract modifications.
5. **Operator Alert-Burden Replay**:
   - Full replay across the 621 open-source release transitions.
6. **Local Model Comparison**:
   - Systematic evaluation across `Qwen3:8B`, `Gemma3:4B`, and `Qwen2.5:1.5B`.

---

## 3. Methodological and Terminology Calibrations

1. **Operator Burden Claim in Abstract**:
   - Temporarily remove until alert-burden replay is completed; note as future work.
2. **Reasoning-Mode Vulnerability ("Capability Paradox")**:
   - Frame as an empirical replication of MCPTox findings on local Qwen3-8B.
3. **Pipeline Tier Count**:
   - Clarify 5-tier architecture (Tiers 0, 1, 1.5, 2, 3) in text and diagrams.
4. **Deduplication of Config H / Config B**:
   - Merge or explicitly differentiate the deterministic fast-path configuration.
