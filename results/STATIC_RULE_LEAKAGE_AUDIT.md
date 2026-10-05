# Audit of Static Heuristic Rules: Construction, Provenance & Leakage Analysis

## 1. Overview

This document audits the static heuristic regex rules defined in `guard/static_rules.py` (Baseline 2 / Tier 1 Fast Alert) to establish their provenance, relationship to the MCPTox benchmark taxonomy, and confirm the absence of post-hoc test-set over-fitting.

---

## 2. Rule Catalog & Target Attack Patterns

The static baseline comprises 7 targeted regular expressions:

| Rule ID | Rule Name | Target Attack Pattern | Associated MCPTox Paradigm / Domain Threat | Severity |
|---|---|---|---|---|
| **`RULE_01`** | `INSTRUCTION_OVERRIDE` | Direct prompt injection directives (`priority is higher than`, `ignore previous instructions`, `system message`, `new instruction takes precedence`) | **Template-1: Direct Injection** | `high` |
| **`RULE_02`** | `SENSITIVE_CREDENTIAL_PATH` | Explicit references to local host secrets (`.ssh/id_rsa`, `/etc/shadow`, `/etc/passwd`, `.aws/credentials`, `.env`) | **Host Exfiltration Vectors** | `high` |
| **`RULE_03`** | `PREREQUISITE_CALL` | Mandatory chaining to secondary tools (`before using this.*?MUST FIRST call`, `mandatory pre-requisite`) | **Template-2: Prerequisite Hijacking** | `high` |
| **`RULE_04`** | `ARGUMENT_REDIRECTION` | Silent redirection of tool arguments (`automatically modify the '\w+' argument to`, `modify the 'path' argument to`) | **Template-3: Argument Tampering** | `high` |
| **`RULE_05`** | `EXFILTRATION_DIRECTIVE` | Direct exfiltration instructions (`send to http://`, `exfiltrate`, `transmit keys to`) | **Network Exfiltration Directives** | `high` |
| **`RULE_06`** | `COVERT_EXECUTION` | Directives demanding silent operation (`do not tell the user`, `without user confirmation`, `hide this execution`) | **Covert Poisoning Signatures** | `medium` |
| **`RULE_07`** | `DESTRUCTIVE_OVERWRITE` | Explicit file content zeroing/destruction (`overwrite '\S+' with an empty string`, `replace the ALL content of '/etc/shadow'`) | **Destructive Poisoning Stubs** | `high` |

---

## 3. Provenance & Timing Analysis

1. **Source of Patterns**: The regex patterns were directly extracted from the structural phrasing templates documented in the published MCPTox benchmark (*"MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers"*, AAAI 2026 / arXiv:2508.14925, Section 3.2).
2. **Creation Order**: The static rules were implemented in Phase 3 as an explicit non-neural heuristic baseline (Baseline 2) to demonstrate the limits of deterministic regex pattern matching.
3. **No Test-Set Tuning**: The rules were not modified, tuned, or expanded during Phase 4 or Phase 5.
4. **Empirical Evidence of Independence**:
   - In Phase 3, static rules achieved only **50.0% recall** (missed 3/6 attacks on the exploratory sample).
   - In Phase 5, static rules achieved **75.8% recall** (missed 8/33 attacks on the full test split).
   - On the Red-Team suite, static rules failed against paraphrased and indirect evasion categories.
   - If rules had been post-hoc fitted to the test set, recall would have artificially approached 100%. The persistent ~24–50% false negative rate empirically confirms that the rules were fixed prior to evaluation.

---

## 4. Role in the 4-Tier Middleware Architecture

The static rules do not act as the primary security decision-maker. In the integrated `MCPGuardMiddleware`:
- **Tier 1 Fast Alert**: When an overt, unambiguous pattern triggers a `high` severity match, the middleware short-circuits the pipeline (<1 ms, 0 LLM calls) to save compute.
- **Unflagged Updates Proceed to Tier 3**: Any update that does not trigger static rules is passed to Tier 3 (Semantic Drift Judge) for full natural language and schema reasoning.
