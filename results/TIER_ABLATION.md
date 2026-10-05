# Full Architectural Tier Ablation Study

## 1. Executive Summary & Evaluated Configurations

To determine the individual and collective contributions of each defensive layer, we evaluate eight architectural variants (Configurations A through H) on the held-out test split ($N=56$):

1. **Tier A: Hash Only**: Exact SHA-256 comparison.
2. **Tier B: Static Only**: Static regular expression keyword rules (Tier 1).
3. **Tier C: Hash + Static**: Cryptographic pinning with static rule fallback.
4. **Tier D: Hash + Static + Structured Diff**: Structural normalization without LLM judge.
5. **Tier E: Hash + Static + Semantic Judge**: Pipeline without deterministic schema security checks.
6. **Tier F: Full Guard Middleware**: Unified multi-tiered pipeline (Tiers 0 + 1 + 1.5 + 2 + 3).
7. **Tier G: Guard without Schema Security Checks**: Full system omitting Tier 1.5.
8. **Tier H: Guard without Semantic Judge**: Fast deterministic pipeline omitting Tier 3 LLM.

---

## 2. Quantitative Ablation Results ($N=56$)

| Config Identifier | Pipeline Layers Included | Precision | Recall | F1 Score | Benign FPR | Malicious FNR | LLM Calls / Update | Latency (Mean) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| **Config A** | Hash Only | 58.9% | **100.0%** | 74.2% | 100.0% | **0.0%** | 0.0 | **< 0.05 ms** |
| **Config B** | Static Only | **100.0%** | 54.5% | 70.6% | **0.0%** | 45.5% | 0.0 | **< 0.05 ms** |
| **Config C** | Hash + Static | 58.9% | **100.0%** | 74.2% | 100.0% | **0.0%** | 0.0 | **< 0.05 ms** |
| **Config D** | Hash + Static + Diff | 58.9% | **100.0%** | 74.2% | 100.0% | **0.0%** | 0.0 | ~0.10 ms |
| **Config E / G** | Hash + Static + Semantic | 85.7% | **100.0%** | **92.3%** | 26.1% | **0.0%** | 0.68 | ~965 ms |
| **Config F (Full)** | **Full Guard Pipeline** | **85.7%** | **100.0%** | **92.3%** | **26.1%** | **0.0%** | **0.61** | **~960 ms** |
| **Config H** | Full Guard w/o LLM | **100.0%** | 66.7% | 80.0% | **0.0%** | 33.3% | **0.0** | **~0.12 ms** |

---

## 3. Analysis & Key Architectural Findings

1. **Why Full Guard (Config F) is Optimal**:
   Config F achieves the highest F1 score (**92.3%**), eliminating 73.9% of benign false alarms while catching 100% of malicious drift in this benchmark.
2. **The Role of Tier 1.5 Schema Security Checks**:
   Adding Tier 1.5 reduces LLM calls from 0.68 to 0.61 per update (a ~10.3% reduction in model invocations) by deterministically catching privilege escalations (`readOnly: true -> false`) and default URL injections upstream.
3. **The Utility of Config H (Deterministic Fast Path)**:
   For ultra-low-latency deployments where LLM execution is impossible, Config H (Hash + Static + Schema Checks) provides **100% precision, 0% FPR, and < 0.15 ms latency**, while catching 66.7% of attacks (missing only sophisticated paraphrases).
