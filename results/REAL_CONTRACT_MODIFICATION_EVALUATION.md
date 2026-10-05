# Real Existing-Tool Contract Modification Subset Evaluation

## 1. Executive Summary & Reviewer Motivation

In early evaluation phases, benign updates included all tool-definition events extracted from MCP git histories ($N=123$). However, an important reviewer observation was noted:
> **110 of the 123 transitions represent newly added or deleted tools rather than modifications to pre-existing tool contracts.**

If additions dominate the benign evaluation, performance on authentic contract refactoring might be masked.

This evaluation isolates the **13 historical instances where a pre-existing MCP tool definition was modified across release tags**, evaluating defense performance specifically on contract mutations.

---

## 2. Dataset Composition & Sub-Category Breakdown

| Category | Count ($n$) | Description & Historical Context |
|---|---:|---|
| **All Real Tool Updates** | 123 | Complete set of tool definition events across 621 release pairs |
| **Tool Additions / Deletions** | 110 | Introduction of brand new tools or deprecation removals |
| **Existing-Tool Contract Modifications** | **13** | **Pre-existing tools whose name was retained while docstring/schema changed** |
| ↳ *Description / Documentation Only* | 7 | Clarifying docstring text, usage examples, markdown formatting |
| ↳ *Schema / Parameter Modifications* | 2 | Property renaming, constraint adjustment, type narrowing |
| ↳ *Mixed (Schema + Description)* | 4 | Simultaneous docstring update and optional parameter additions |

*Statistical Note: Due to $n=13$ sample size, sub-category results are reported descriptively.*

---

## 3. Comparative False Positive Rates across Subsets

| Defense System | All Real Updates ($n=123$) | Existing-Tool Mods ($n=13$) | Description Only ($n=7$) | Schema Only ($n=2$) | Mixed Mods ($n=4$) |
|---|---:|---:|---:|---:|---:|
| **Cryptographic Hash Pinning (Tier 0)** | 100.0% (123/123) | 100.0% (13/13) | 100.0% (7/7) | 100.0% (2/2) | 100.0% (4/4) |
| **Static Keyword Rules (Tier 1)** | **0.0%** (0/123) | **0.0%** (0/13) | **0.0%** (0/7) | **0.0%** (0/2) | **0.0%** (0/4) |
| **Deterministic Schema Checks (Tier 1.5)** | **0.0%** (0/123) | **0.0%** (0/13) | **0.0%** (0/7) | **0.0%** (0/2) | **0.0%** (0/4) |
| **TF-IDF Cosine Embedding Baseline** | 71.5% (88/123) | 69.2% (9/13) | 57.1% (4/7) | 100.0% (2/2) | 75.0% (3/4) |
| **Full Guard Middleware (Tiers 0–3)** | **22.0%** (27/123) | **23.1%** (3/13) | **14.3%** (1/7) | **50.0%** (1/2) | **25.0%** (1/4) |

---

## 4. Qualitative Analysis of Modified Existing Tools

1. **Description-Only Changes ($n=7$)**:
   - 6 of 7 updates correctly classified as `BENIGN` and allowed.
   - 1 false positive occurred in `mcp-server-git` where the commit message described removing a vulnerable shell invocation path, which triggered elevated suspicion in the semantic judge.
2. **Schema Modifications ($n=2$)**:
   - 1 update in `mcp-server-sqlite` refactored argument keys to standard casing; classified as `SUSPICIOUS` due to large structural diff.
   - 1 update in `mcp-server-filesystem` expanded directory path validation; correctly identified as `BENIGN`.
3. **Conclusion**:
   When evaluating strictly against modified existing tool contracts ($n=13$), Guard reduces the false alarm burden by **76.9%** (from 13 false alarms under hash pinning down to 3 false alarms), confirming that the false positive reduction is not driven merely by tool additions.
