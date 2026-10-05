# Phase 2 — Human Research Labeling Guide: MCP Tool Evolution

## 1. Overview & Research Objective

This guide defines the taxonomy and annotation criteria for categorizing changes in Model Context Protocol (MCP) tool definitions across consecutive software versions.

### ⚠️ Fundamental Research Distinction
These are **software evolution categories**, not malicious/benign security verdicts. In normal open-source repository history, developer updates are legitimate software maintenance. The goal of this taxonomy is to characterize *what dimensions of tool contracts evolve* in practice, establishing how often rigid cryptographic hashing (e.g., `mcp-scan` tool pinning) causes false positive disruption on normal engineering updates.

---

## 2. Taxonomy & Annotation Rubric

### 2.1 `typo_or_formatting`
- **Definition**: Cosmetic changes to description or schema documentation that do not alter semantic meaning or model interpretation.
- **Inclusion Criteria**:
  - Fixing spelling mistakes or grammatical errors.
  - Whitespace, casing, or Markdown punctuation formatting.
- **Exclusion Criteria**:
  - Any addition or removal of operational instructions or schema parameters.
- **Real Corpus Example**:
  - *Tool*: `mcp-server-git::git_status`
  - *Old*: `"Shows the working tree status."`
  - *New*: `"Shows the working tree status"` (trailing period normalization).

---

### 2.2 `clarification`
- **Definition**: The tool description is expanded, clarified, or made more precise to improve LLM comprehension without modifying schema parameters or runtime semantics.
- **Inclusion Criteria**:
  - Explaining parameter usage constraints in text.
  - Adding usage examples or caution notes in the docstring.
  - Rephrasing tool purpose for better agent prompt understanding.
- **Exclusion Criteria**:
  - Adding or removing JSON schema properties or changing type requirements.
- **Real Corpus Example**:
  - *Tool*: `mcp-server-git::git_commit` (`chg_0004`)
  - *From*: `0.3.1` $\rightarrow$ `0.4.0`
  - *Old Description*: `"Commits changes to the repository. You can specify a commit message and optionally stage all modified files."`
  - *New Description*: `"Records changes to the repository"`

---

### 2.3 `new_feature`
- **Definition**: A tool definition is expanded with new optional parameters, expanded enum options, or backward-compatible feature extensions.
- **Inclusion Criteria**:
  - New optional properties added to `inputSchema.properties`.
  - Added options to an `enum` list without breaking existing valid inputs.
- **Exclusion Criteria**:
  - Adding a *required* parameter that breaks backwards compatibility (see `behavior_change`).
- **Real Corpus Example**:
  - *Tool*: `mcp-server-fetch::fetch`
  - *From*: `0.1.0` $\rightarrow$ `0.2.0`
  - *Change*: Added optional parameter `raw: boolean` to allow retrieving raw HTML instead of Markdown converted text.

---

### 2.4 `behavior_change`
- **Definition**: The contract, parameter requirements, or operational behavior of the tool changes in a potentially breaking manner.
- **Inclusion Criteria**:
  - An existing parameter is removed.
  - An optional parameter becomes `required`.
  - Stricter parameter validation constraints (e.g. regex, minimum/maximum limits) are imposed.
- **Exclusion Criteria**:
  - Purely additive optional parameters (see `new_feature`).
- **Real Corpus Example**:
  - *Tool*: `mcp-server-filesystem::read_file`
  - *Change*: Making the path argument enforce sandbox boundary validation.

---

### 2.5 `schema_change`
- **Definition**: The structural types, parameter descriptions, or default values of the input schema are modified without altering fundamental tool behavior.
- **Inclusion Criteria**:
  - Changing parameter descriptions in schema properties.
  - Modifying parameter default values.
  - Reorganizing JSON Schema property annotations.
- **Exclusion Criteria**:
  - Adding brand new parameters (see `new_feature`).
- **Real Corpus Example**:
  - *Tool*: `mcp-server-sqlite::read_query`
  - *Change*: Updated description for the `query` parameter from `"SQL query to execute"` to `"The SELECT query to execute against the SQLite database"`.

---

### 2.6 `tool_addition`
- **Definition**: A new tool is introduced to the MCP server contract.
- **Inclusion Criteria**:
  - A tool name present in version $V_{i+1}$ that was not registered in version $V_i$.
- **Exclusion Criteria**:
  - Renamed tools (where old tool is deleted and replaced with identical functionality under a new name).
- **Real Corpus Example**:
  - *Tool*: `mcp-server-git::git_reset` (`chg_0006`)
  - *From*: `0.3.1` $\rightarrow$ `0.4.0`
  - *Action*: Newly introduced tool to reset HEAD to a specified commit.

---

### 2.7 `tool_removal`
- **Definition**: An existing tool is removed or deprecated from the MCP server contract.
- **Inclusion Criteria**:
  - A tool name present in version $V_i$ that is omitted in version $V_{i+1}$.
- **Exclusion Criteria**:
  - Temporary absence due to syntax error in source file.
- **Real Corpus Example**:
  - *Tool*: `mcp-server-git::git_file_history` (`chg_0011`)
  - *From*: `0.3.1` $\rightarrow$ `0.4.0`
  - *Action*: Removed in favor of unified `git_log` with path arguments.

---

### 2.8 `uncertain`
- **Definition**: Complex refactoring or simultaneous multiple edits where the primary intent cannot be reliably categorized into a single class.
- **Inclusion Criteria**:
  - Simultaneous total rewrite of description, parameters, and return semantics.

---

## 3. Annotation Workflow & Protocol

1. Extract normalized canonical JSON representations for version $V_i$ and $V_{i+1}$.
2. Run automated structural diff (`experiments/phase2_tool_diff.py`).
3. For modified tools, review the description and schema diffs.
4. Assign the appropriate category according to inclusion/exclusion criteria.
5. Record change record in `data/tool_changes.jsonl`.
