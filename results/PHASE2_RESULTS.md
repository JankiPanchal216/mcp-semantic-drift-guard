# Phase 2 — Real-World MCP Tool Update Measurement: Results & Analysis

## 1. Executive Summary

Phase 2 constructed a multi-server corpus of 28 open-source Model Context Protocol (MCP) servers and systematically analyzed tool definition evolution across **621 consecutive version transitions** and **4,961 tool comparisons**.

The central finding is that **legitimate open-source MCP servers actively evolve their tool definitions**, with **4.99% of release transitions** introducing tool definition changes. Specifically, description-only modifications (docstring refinements, prompt guidance updates) occur in **1.13% of all release transitions** ($7/621$), while tool additions and removals account for the majority of contract adjustments ($89.43\%$).

Because exact hash-based tool pinning (the Phase 1B baseline) treats any byte-level change in names, docstrings, or schemas as a security breach, **100% of these legitimate evolutionary changes trigger pinning alarms**, demonstrating a critical operational limitation in rigid pinning and providing empirical justification for a **Semantic Drift Judge (Phase 3)**.

---

## 2. Core Research Metrics

### 2.1 Corpus & Transition Metrics

| Metric | Measured Value | Description |
|---|---:|---|
| **Total Servers Studied** | 28 | Official and community open-source MCP servers |
| **Servers with Extracted Versions ($\ge 2$)** | 25 | Servers with multi-version historical evolution |
| **Total Tool Snapshots Extracted** | 594 | Fully indexed JSON snapshots across git tags |
| **Total Unique Tool Interfaces** | 285 | Distinct tool contracts across all servers |
| **Comparable Release Transitions** | 621 | Consecutive version pairs $(V_i, V_{i+1})$ |
| **Total Tool-Pair Comparisons** | 4,961 | Individual tool contract comparisons |
| **Total Tool Definition Changes** | 123 | Recorded instances of contract evolution |

---

### 2.2 Evolutionary Rates

| Rate Metric | Value | Formula / Basis |
|---|---:|---|
| **Definition-Change Rate** | **2.48%** | $123 \text{ changed tool transitions} / 4,961 \text{ total comparisons}$ |
| **Release-Change Rate** | **4.99%** | $31 \text{ releases with } \ge 1 \text{ change} / 621 \text{ comparable releases}$ |
| **Description-Change Rate** | **1.13%** | $7 \text{ releases with } \ge 1 \text{ doc change} / 621 \text{ comparable releases}$ |
| **Schema-Change Rate** | **0.32%** | $2 \text{ releases with schema changes} / 621 \text{ comparable releases}$ |

---

## 3. Breakdown of Tool Evolution by Category

| Change Category | Count | Percentage | Primary Impact on LLM / Agent System |
|---|---:|---:|---|
| `tool_addition` | 63 | 51.22% | Expands agent tool registry with new capabilities |
| `tool_removal` | 47 | 38.21% | Deprecates obsolete tools or consolidates APIs |
| `clarification` | 11 | 8.94% | Updates tool docstrings to improve LLM reasoning/adherence |
| `new_feature` | 2 | 1.63% | Adds backward-compatible optional schema parameters |
| `schema_change` | 0 | 0.00% | Parameter type/constraint adjustments |
| `behavior_change` | 0 | 0.00% | Breaking parameter modifications |
| `typo_or_formatting`| 0 | 0.00% | Cosmetic whitespace/punctuation normalization |
| `uncertain` | 0 | 0.00% | Ambiguous structural rewrites |
| **Total** | **123** | **100.0%** | |

---

## 4. Pinning False-Positive Baseline: Trigger Rate on Legitimate Updates

In Phase 1B, we established that exact SHA-256 tool pinning (the industry baseline implemented in `mcp-scan` / `snyk-agent-scan`) evaluates identity as:
$$\text{Status} = \begin{cases} \text{ALLOW}, & \text{SHA256}(\text{Tool}_{V_{i+1}}) = \text{SHA256}(\text{Tool}_{V_i}) \\ \text{ALERT / BLOCK}, & \text{otherwise} \end{cases}$$

Applying this exact pinning baseline across the 621 historical release transitions in our corpus produces the following trigger profile:

| Metric | Value | Interpretation |
|---|---:|---|
| **Total Hash-Triggered Releases** | 31 (4.99%) | Releases blocked or flagged for operator intervention |
| **Legitimate Updates Flagged** | 31 / 31 (100.0%) | All flagged updates represent benign open-source evolution |
| **Description-Only Triggers** | 7 (22.58% of triggers) | Pure docstring/guidance updates that break exact hash |
| **Estimated Benign Disruption Rate** | **1 in every 20 releases** | Maintenance burden imposed on human operators |

> [!IMPORTANT]
> **Key Insight**: Exact cryptographic tool pinning forces a binary tradeoff: either **freeze all tool updates** (preventing prompt improvements, bug fixes, and capability additions) or **rely on manual human review for 5% of all software releases**.

---

## 5. Phase 2 Research Checkpoint: Answering Core Research Questions

### Question 1: How many open-source MCP servers and versions were successfully studied?
- **28 candidate servers** were discovered and curated.
- **25 servers** had verified multi-release histories.
- **22 servers** had full static/runtime tool snapshot extractions.
- **594 version snapshots** were successfully extracted and indexed with full git commit provenance.

### Question 2: How frequently do MCP tool definitions change between versions?
- **4.99% of consecutive release transitions** contain at least one tool definition modification.
- At the individual tool level, **2.48% of comparable tool instances** undergo definition changes.

### Question 3: How frequently do tool descriptions change?
- **1.13% of release transitions** (7 releases) modify tool descriptions without altering underlying runtime code, directly causing cryptographic hash mismatch.

### Question 4: What types of legitimate changes occur most frequently?
- The majority of updates are **tool additions (51.2%)** and **tool removals/consolidations (38.2%)**, followed by **description clarifications (8.9%)** and **new optional schema parameters (1.6%)**.

### Question 5: How often would exact hash-based pinning flag a seemingly legitimate update?
- In 100% of the 31 modified releases (4.99% of total releases), exact hash-based pinning raised a false alarm on benign developer updates.

### Question 6: Are there enough real-world legitimate changes to justify a semantic drift detector?
- **YES.** Real-world MCP tools evolve at a consistent, measurable rate (~5% of releases). Because exact hashing indiscriminately flags benign documentation improvements and feature extensions, a **Semantic Drift Judge** that can automatically distinguish benign software evolution from malicious payload injection (such as the 41.8% ASR attacks discovered in Phase 1C) is empirically necessary.

---

## 6. Artifacts and Figures Generated

- **Corpus Metadata**: [`data/mcp_corpus.json`](file:///C:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/data/mcp_corpus.json)
- **Version Records**: [`data/mcp_versions.json`](file:///C:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/data/mcp_versions.json)
- **Tool Snapshots**: `data/tool_snapshots/<server_id>/<version>.json` (594 snapshots)
- **Tool Changes Dataset**: [`data/tool_changes.jsonl`](file:///C:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/data/tool_changes.jsonl) (123 records)
- **Labeling Guide**: [`results/PHASE2_LABELING_GUIDE.md`](file:///C:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/results/PHASE2_LABELING_GUIDE.md)
- **Corpus Report**: [`results/PHASE2_CORPUS_REPORT.md`](file:///C:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/results/PHASE2_CORPUS_REPORT.md)
- **Inter-rater Agreement**: [`results/phase2_interrater_agreement.json`](file:///C:/Users/Janki%20Panchal/Downloads/New%20folder/Desktop/Research/APP/results/phase2_interrater_agreement.json)
- **Academic Figures**:
  - `results/figures/change_types_distribution.png`
  - `results/figures/release_change_rates.png`
  - `results/figures/changes_by_server.png`
