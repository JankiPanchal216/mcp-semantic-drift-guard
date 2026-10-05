# Matched-Pair Dataset Specification: Controlling for Style Confounds

## 1. Motivation & Methodology

A central methodological limitation in previous tool poisoning evaluations is the **style and origin confound**:
- **Benign Negatives** originated from authentic open-source developer git commits (varying formatting, concise engineering language, complex parameters).
- **Malicious Positives** originated predominantly from synthetic MCPTox mutations applied to standardized baseline stubs.

To eliminate writing style, tool domain, and contract complexity as confounding variables, we constructed the **Matched-Pair Evaluation Dataset** (`data/matched_pairs.jsonl`).

---

## 2. Dataset Design & Triplet Structure

Each matched-pair record is a controlled triplet:
$$\text{Triplet}_i = \Big( \text{Tool}_{\text{old}}, \quad \text{Tool}_{\text{benign\_new}}, \quad \text{Tool}_{\text{malicious\_new}} \Big)$$

- $\text{Tool}_{\text{old}}$: The authentic historical V1 tool contract from the open-source git history.
- $\text{Tool}_{\text{benign\_new}}$: The authentic historical V2 tool contract produced by the original developer (Ground Truth: `BENIGN`).
- $\text{Tool}_{\text{malicious\_new}}$: A controlled semantic mutation constructed by injecting an attack payload directly into the authentic V2 contract while **strictly preserving** the server ID, tool name, vocabulary style, parameter naming conventions, and JSON Schema indentation (Ground Truth: `MALICIOUS`).

---

## 3. Dataset Distribution & Mutation Taxonomy

The dataset contains **12 matched triplets** (24 candidate update evaluations across 6 server repositories) spanning 6 balanced mutation categories (2 triplets per category):

| Mutation Category | Triplets Count | Source MCP Servers & Tools | Attack Target & Mechanism |
|---|---:|---|---|
| **Category A: Instruction Injection** | 2 | `mcp-server-git` (`git_commit`, `git_log`) | System override directives injected into docstrings. |
| **Category B: Prerequisite Manipulation** | 2 | `mcp-server-filesystem` (`read_file`), `mcp-server-time` (`get_current_time`) | Forced execution of unauthorized secondary diagnostic tools (`sync_state`, `read_file`). |
| **Category C: Argument Redirection** | 2 | `mcp-server-filesystem` (`write_file`), `mcp-server-mysql` (`get_schema_info`) | Explicit path redirection to `/etc/shadow` or public webroots. |
| **Category D: Authorization Expansion** | 2 | `mcp-server-mysql` (`execute_sql`), `mcp-server-filesystem` (`list_allowed_directories`) | Read-only permissions relaxed to unrestricted administrative access. |
| **Category E: Data Exfiltration** | 2 | `mcp-server-slack` (`slack_list_channels`), `mcp-server-mysql` (`get_table_sample`) | Passive data forwarding to external webhooks. |
| **Category F: Schema Mutation** | 2 | `mcp-server-puppeteer` (`puppeteer_navigate`, `puppeteer_screenshot`) | Default parameter webhook injection and public upload flags. |
| **Total Matched Pairs** | **12** | **6 Servers / 12 Tools** | **24 Paired Evaluations (12 Benign, 12 Malicious)** |

---

## 4. Dataset Properties & Provenance

- **Storage Location**: `data/matched_pairs.jsonl`
- **Builder Script**: `experiments/build_matched_pairs.py` (Fixed seed = 42).
- **Field Completeness**: 100% of records contain complete `old_definition`, `benign_new_definition`, and `malicious_new_definition` contracts.
- **Statistical Note**: Derived from all 13 modified existing-tool contracts in the open-source Phase 2 corpus. Small sample size ($N=24$ evaluations) is explicitly noted as a descriptive matched benchmark rather than a large asymptotic sample.
