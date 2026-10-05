# Methodological Reframing: Alert Burden vs. Semantic Drift

## 1. Executive Reframing Statement

In existing tool-integrity literature and industrial tooling (e.g., `snyk-agent-scan`, `mcp-scan`), exact cryptographic hash pinning (SHA-256) serves as a strict change-detection baseline. By mathematical definition, SHA-256 guarantees that any byte-level modification will produce a hash mismatch. Therefore, demonstrating that hash pinning flags 100% of non-identical tool definitions is not an empirical flaw of cryptographic hashing, but rather a direct consequence of its design.

The core research insight is that **Model Context Protocol tool contracts evolve in practice during normal software maintenance**, creating an operational **alert burden** under exact pinning. Our empirical corpus enables the first quantitative measurement of this burden and motivates the transition from *syntactic change detection* to *semantic drift evaluation*.

---

## 2. Empirical Quantification of the Alert Burden

From our multi-server corpus of 28 open-source MCP repositories across 621 consecutive release transitions and 4,961 tool comparisons, we establish the following empirical distribution of change events:

```
Total Release Transitions (N = 621)
  ├── Unchanged Releases (n = 590, 95.01%) ──────► Zero Pinning Alerts
  └── Modified Releases (n = 31, 4.99%) ──────────► 100% Trigger Pinning Review
        ├── Tool Additions / Removals Only (n = 23, 3.70%)
        └── Existing-Tool Contract Modifications (n = 8, 1.29%)
              ├── Description Modifications (n = 7, 1.13%)
              └── Input Schema Modifications (n = 2, 0.32%)
                  *(1 release contained both doc and schema updates)*
```

### 2.1 Detailed Corpus Metrics & Confidence Intervals (Wilson 95% CI)

| Category / Event Type | Numerator / Denominator | Rate (%) | 95% Wilson CI | Operational Meaning |
|---|---:|---:|---|---|
| **All Tool-Definition Changes** | 31 / 621 releases | **4.99%** | [3.51%, 7.04%] | Total release alert burden under exact hash pinning (~1 in 20 releases) |
| **Existing-Tool Contract Changes** | 8 / 621 releases | **1.29%** | [0.65%, 2.52%] | Releases altering behavior/descriptions of pre-existing active tools |
| **Description-Only Changes** | 7 / 621 releases | **1.13%** | [0.55%, 2.31%] | Natural language clarifications that do not alter execution code |
| **Input Schema Changes** | 2 / 621 releases | **0.32%** | [0.09%, 1.16%] | Structural parameter additions or constraint updates |
| **Individual Tool Definition Changes** | 123 / 4,961 comparisons | **2.48%** | [2.08%, 2.96%] | Churn rate at the individual tool contract level |

### 2.2 Breakdown of 123 Recorded Definition Modifications

| Modification Type | Count | Percentage | Operational Nature |
|---|---:|---:|---|
| `tool_addition` | 63 | 51.22% | New tool registered in server manifest |
| `tool_removal` | 47 | 38.21% | Deprecated tool removed from server manifest |
| `clarification` (docstring update) | 11 | 8.94% | Refinement of prompt guidance or usage examples |
| `new_feature` (optional schema update) | 2 | 1.63% | Backward-compatible optional parameters |
| **Total** | **123** | **100.0%** | |

---

## 3. Change Detection Burden vs. Semantic Contract Modification Burden

To ensure conceptual clarity, the research formalizes two distinct operational concepts:

### A. The Change Detection Burden (Exact Pinning)
- **Mechanism**: Binary equality check ($\text{SHA256}(D_{\text{new}}) \stackrel{?}{=} \text{SHA256}(D_{\text{old}})$).
- **Scope**: Flags all 31 modified releases (4.99% of total releases, 123 tool transitions).
- **Consequence**: Requires human operator intervention or manual re-approval for every documentation refinement, parameter typo fix, or capability extension.

### B. The Semantic Contract Modification Burden (Semantic Drift)
- **Mechanism**: Meaning-aware evaluation over structured deltas ($\text{Judge}(\Delta(D_{\text{old}}, D_{\text{new}}))$).
- **Scope**: Evaluates whether the contract change introduces unauthorized privileges, prompt injection directives, prerequisite hijacking, or data exfiltration.
- **Consequence**: Allows harmless documentation and non-breaking schema additions to proceed automatically, while selectively quarantining high-risk semantic deviations.

---

## 4. Revised Core Thesis

The scientific thesis of this work is therefore framed as follows:

> **Exact cryptographic pinning provides strong, low-cost integrity verification against silent tampering, but its binary nature cannot differentiate routine developer maintenance from security-relevant semantic drift. By integrating structured contract diffing and zero-temperature LLM reasoning, Semantic Drift Detection preserves the change-detection security boundary while automating the evaluation of benign software evolution.**
