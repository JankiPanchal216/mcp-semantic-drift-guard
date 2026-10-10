import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
PAPER_PATH = ROOT_DIR / "paper.md"
TABLES_PATH = ROOT_DIR / "results" / "tables" / "tables_markdown.md"
AUDIT_DATA_PATH = ROOT_DIR / "results" / "DECISION_RULE_AUDIT_DATA.json"


with open(PAPER_PATH, "r", encoding="utf-8") as f:
    text = f.read()

with open(TABLES_PATH, "r", encoding="utf-8") as f:
    tables_md = f.read()

# 1. Update Abstract
new_abstract = """## Abstract

The Model Context Protocol (MCP) enables Large Language Model (LLM) agents to dynamically discover and execute external tools at runtime. However, because advertised tool contracts—including docstrings, parameter descriptions, and schemas—are directly ingested into agent prompts, malicious or compromised upstream servers can mount tool-poisoning attacks to hijack agent execution. While single-step attacks inject overt malicious directives, sophisticated adversaries can partition an unauthorized capability escalation across multiple consecutive, individually subtle release updates—a threat model we formalize as **Salami Drift** (or incremental "rug-pull" attacks). Existing MCP defenses detect change (hash pinning, signing) or judge a single definition (static scanners, one-shot LLM vetting). To our knowledge, no prior defense evaluates whether a sequence of individually subtle updates accumulates into a malicious capability escalation.

Across an empirical audit of 621 historical release transitions from open-source MCP repositories, 31 releases (4.99%) contained legitimate tool-definition modifications (an operator burden of 0.050 alerts per release transition), all of which trigger security reapproval under exact cryptographic pinning. To address this challenge, we evaluate **Cumulative Anchoring**, which evaluates candidate updates relative to the authorized root baseline ($\Delta_{\text{cumul}} = V_0 \rightarrow V_k$) using an XML-sandboxed structured diff semantic judge (`gemma3:4b`, a 4B local open-weight model).

In held-out single-step benchmark evaluations ($N=56$; source: `results/computed_metrics.json`), exact cryptographic hash pinning achieves **Precision = 58.9%**, **Recall = 100.0%**, with **Benign FPR = 100.0%** (by construction); author-defined static regex rules achieve **Precision = 100.0%**, **Recall = 75.8%**, with **Benign FPR = 0.0%**; and the TF-IDF cosine baseline achieves **Precision = 64.6%**, **Recall = 93.9%**, with **Benign FPR = 73.9%**.

On a hand-constructed **Salami Drift Benchmark V3** ($N=144$ transitions across 40 trajectories), audited for zero deterministic rule leakage and executed under live inference, Cumulative Anchoring achieves **93.8% (15/16)** Salami-only chain recall (95% Wilson CI: [71.7%, 98.9%]) compared to **50.0% (8/16)** for Adjacent-only comparison (95% Wilson CI: [28.0%, 72.0%]; paired McNemar $p = 0.01562$), while reducing the mean exposure window from $1.19$ to $0.56$ steps. Under the primary deployed decision rule (BALANCED with fallbacks), benign-chain False Positive Rate is **50.0% (8/16)** [28.0%, 72.0%] (dropping to **12.5% (2/16)** [3.5%, 36.0%] on directly parsed decisions without fallbacks, and **12.5% (2/16)** under MALICIOUS-only filtering). At the transition level under the primary decision rule, Cumulative Anchoring achieves **Recall = 75.0% (30/40)** [59.8%, 85.8%], **Precision = 71.4% (30/42)** [56.4%, 82.8%], and **Benign Transition FPR = 11.5% (12/104)** [6.7%, 19.1%]. Dual-Anchor monitoring yields identical chain detection (91.7% overall, 93.8% Salami) and identical benign-chain FPR (50.0%) while doubling LLM inference cost (2.0 vs. 1.0 calls per update)."""

# Replace Abstract
abstract_start = text.find("## Abstract")
intro_start = text.find("## 1. Introduction")
if abstract_start != -1 and intro_start != -1:
    text = text[:abstract_start] + new_abstract + "\n\n---\n\n" + text[intro_start:]

# 2. Update Section 1.3
old_1_3_prefix = "### 1.3 Research Gap & Threat Formalization"
end_1_3 = text.find("### 1.4 Primary Contributions")
new_1_3 = """### 1.3 Research Gap & Threat Formalization
Existing MCP defenses detect change (hash pinning, signing) or judge a single definition (static scanners, one-shot LLM vetting). To our knowledge, no prior defense evaluates whether a sequence of individually subtle updates accumulates into a malicious capability escalation. Our contributions are limited to:
1. A formal threat formulation and benchmark for salami drift in MCP tool definitions;
2. Trajectory and chain-level evaluation metrics (chain recall, benign chain FPR, and exposure window $W_e$); and
3. Empirical evidence on this benchmark that comparing candidate updates against the root-approved baseline (cumulative anchoring) recovers attack chains that adjacent-only comparison misses, with the corresponding false-alarm cost stated plainly.

"""
idx_1_3 = text.find(old_1_3_prefix)
if idx_1_3 != -1 and end_1_3 != -1:
    text = text[:idx_1_3] + new_1_3 + text[end_1_3:]

# 3. Update Section 1.4
old_1_4_prefix = "### 1.4 Primary Contributions"
end_1_4 = text.find("## 2. Background & Threat Model")
new_1_4 = """### 1.4 Primary Contributions
This paper provides an empirical measurement, formal threat model, and trajectory-level evaluation for incremental semantic contract drift in Model Context Protocol tool ecosystems:
1. **Empirical Measurement of Open-Source MCP Evolution**: We perform a longitudinal audit of 621 historical release transitions across 28 open-source MCP repositories, quantifying that 4.99% of releases contain tool definition changes (123 total change events) and establishing the exact operator alert burden imposed by byte-level pinning.
2. **Salami Drift Threat Formulation & Benchmark V3**: We formalize the multi-step incremental tool-poisoning threat model and release the **Salami Drift Benchmark V3** ($N=144$ transitions across 40 balanced chains), audited across 9 automated quality gates to guarantee zero static rule leakage, monotonic parameter progression, and isolated live inference.
3. **Multi-Tier Semantic Drift Guard Architecture**: We design and implement a 5-tier defense middleware (`guard/middleware.py`) combining sub-millisecond deterministic fast-paths ($< 0.25\text{ ms}$) with XML-sandboxed structured diff reasoning and automatic baseline rollback.
4. **Cumulative Anchoring & Trajectory Evaluation**: We evaluate cumulative root anchoring against adjacent monitoring, demonstrating significant Salami-drift recall gains (93.8% vs. 50.0%, paired McNemar $p = 0.01562$) and exposure window reductions, while documenting that Dual-Anchor monitoring provides no chain-level advantage over pure cumulative comparison while incurring 2x LLM inference cost.
5. **Open Reproducibility Package**: We open-source the complete artifact suite—including benchmarks, verifiable prediction traces, execution manifests, and automated table generation scripts (`scripts/make_tables.py`) pinned at canonical commit `93834f9`.

---

"""
idx_1_4 = text.find(old_1_4_prefix)
if idx_1_4 != -1 and end_1_4 != -1:
    text = text[:idx_1_4] + new_1_4 + text[end_1_4:]

# 4. Update Section 2.3
old_2_3 = "4. **Out-of-Scope Risks & Non-Adaptive Scope**:"
end_2_3 = text.find("## 3. Related Work")
new_2_3_item = """4. **Out-of-Scope Risks & Non-Adaptive Scope**: We consider a knowledgeable attacker; however, dynamic adaptive attacks where the adversary receives live feedback from detector verdicts and iteratively optimizes evasion payloads against the judge are **not evaluated** in this study (see Section 11). Other out-of-scope risks include in-process binary tampering during `tools/call` execution without manifest changes, compromised OS kernels, and direct user prompt jailbreaks.

---

"""
idx_2_3 = text.find(old_2_3)
if idx_2_3 != -1 and end_2_3 != -1:
    text = text[:idx_2_3] + new_2_3_item + text[end_2_3:]

# 5. Update Table 1
old_t1_start = text.find("| Defense Paradigm | Exemplar Approaches")
old_t1_end = text.find("## 4. Corpus Measurement")
new_t1 = """| Defense Paradigm | Exemplar Approaches | Threat Model Scope | Primary Detection Target | Operational Blind Spots | Operator Review Burden |
|---|---|---|---|---|:---:|
| **Cryptographic Hash Pinning** | Exact SHA-256 (W3C SRI, 2016) | Unmodified baseline integrity | Strict byte-level equality | Cannot differentiate benign refactorings from malicious payloads | **High** (100% of modified releases trigger alerts; 0.050 alerts/transition) |
| **Author Provenance Signing** | Mas et al. (2026), Sigstore (2022) | Unauthorized third-party tampering | Cryptographic author signature mismatch | Insider maintainer rug-pulls; authorized account compromise | **Low** (Zero alerts for validly signed releases, 0 detection of signed malware) |
| **Static Keyword Scanners** | `mcp-scan` (Snyk, 2025), regex rules | Overt keyword injections | Known syntactic attack templates | Evasive paraphrasing, semantic drift, parameter toggles | **Zero runtime burden** (Sub-millisecond fast-path, 0 LLM calls) |
| **Monolithic LLM Vetting** | Standalone prompt judge ($T=0$) | General natural language injection | Unstructured docstring anomalies | High handshake latency, prompt injection, lacks multi-step context | **Medium** (Incurs LLM inference on every handshake) |
| **MCP Semantic Drift Guard (This Work)** | 5-tier pipeline + Cumulative baseline | Multi-step incremental drift & evasive mutations | Structural schema shifts, evasive docstrings, salami attacks | Breaking schema incompatibilities, local model parsing anomalies | **Not yet measured** (longitudinal replay designated future work) |

---

"""
if old_t1_start != -1 and old_t1_end != -1:
    text = text[:old_t1_start] + new_t1 + text[old_t1_end:]

# 6. Update Section 5.1 with Formal Unified Decision Rules (stated before results)
decision_rules_def = """#### 5. Formal Unified Decision Rules
To evaluate detector performance consistently across transition and trajectory levels, we define three unified decision rules:
- **Rule (b) [Primary Deployed Policy — BALANCED Mode with Fallbacks]**: A candidate transition is flagged positive iff the verdict $\in \{\\text{MALICIOUS}, \\text{SUSPICIOUS}\}$ (corresponding to policy action $\in \{\\text{BLOCK}, \\text{WARN}\}$). If an unparseable response or timeout occurs, the policy engine defaults to fail-secure `WARN` (quarantine). This represents the real, operational deployment policy.
- **Rule (a) [Operating-Point Sensitivity — MALICIOUS Only]**: A candidate transition is flagged positive iff the verdict $= \\text{MALICIOUS}$ (action $= \\text{BLOCK}$). Unparseable responses default to `ALLOW` (fail-open) unless affirmative malicious intent is parsed.
- **Rule (c) [Diagnostic Operating Point — Directly Parsed Only]**: Evaluates Rule (b) strictly on directly parsed model responses, excluding calls that triggered fail-secure fallbacks. This isolates the intrinsic semantic reasoning fidelity of the local model judge from JSON formatting brittleness.

*Early-False-Alarm Filter ($k \ge m$)*: In trajectory-level evaluation, a malicious chain is counted as detected iff the first positive alert occurs at or after the first malicious transition ($k \ge m$). Early false alarms at benign steps ($k < m$) are treated as premature alerts and do not grant detection credit or zero-exposure credit.

"""
idx_sec5_end = text.find("## 6. Single-Step Benchmark Evaluation")
idx_sec5_sub4 = text.find("#### 4. Multi-Step Trajectory and Exposure Metrics")
if idx_sec5_sub4 != -1 and idx_sec5_end != -1:
    # Insert before Section 6
    text = text[:idx_sec5_end] + decision_rules_def + "\n---\n\n" + text[idx_sec5_end:]

# 7. Update Tables 4 and 5 in Section 9.5.4
idx_sec9_4 = text.find("##### Transition-Level Main Results ($N=144$ Transitions):")
idx_sec9_5 = text.find("#### 5. Hypothesis Testing & Paired Statistical Analysis")

from scripts.make_tables import generate_table_4_v3_transitions, generate_table_5_v3_chains
with open(AUDIT_DATA_PATH, "r", encoding="utf-8") as f:
    audit_data = json.load(f)

t4_rendered = generate_table_4_v3_transitions(audit_data)
t5_rendered = generate_table_5_v3_chains(audit_data)

new_sec9_tables = f"""##### Transition-Level Salami Drift Results ($N=144$ Transitions):
*Source: `results/salami_drift_v3/computed_metrics.json`, `paper/DECISION_RULE_AUDIT.md`, and raw traces in `results/salami_drift_v3_*/predictions.jsonl`. Transition intervals are 95% Wilson score intervals.*

{t4_rendered}

##### Chain-Level Trajectory Outcomes ($N=40$ Chains: 16 Salami, 8 Fast-Jump, 16 Benign):
*Source: Point estimates are exact observed counts; intervals are 95% Wilson score intervals for proportions and cluster bootstrap for exposure means.*

{t5_rendered}

*Methodological Audit on Chain FPR, Fallbacks, and Judge Failure Modes*:
1. **Fallback Breakdown**: Across 576 total LLM calls (144 transitions $\times$ 3 strategies + fallbacks), 31 calls (5.4%) required the `BALANCED` fail-safe fallback (`WARN`).
   - Salami-only chain recall is completely unaffected by fallbacks: **93.8% (15/16)** across Rule (a), Rule (b), and Rule (c). The 15 detected salami chains were flagged by genuine affirmative model verdicts.
   - For fast-jump positive controls ($N=8$), Cumulative recall drops from **87.5% (7/8)** under Rule (b) to **62.5% (5/8)** under Rule (c), and overall malicious recall drops from **91.7% (22/24)** to **83.3% (20/24)**. Thus, fail-safe fallbacks contributed to detecting 2 fast-jump chains.
   - For benign chains ($N=16$), 10 fallbacks fell on benign transitions, causing 6 of the 8 benign chain false alarms under Rule (b). When unparseable fallbacks are excluded (Rule c), the true semantic benign-chain False Positive Rate is **12.5% (2/16)** (`v3_chain_29` and `v3_chain_31` at Step 4).
2. **Analysis of Missed Fast-Jump Attacks**: Under parsed-only Rule (c), the 4B local judge missed 3 of 8 overt fast-jump attacks in Cumulative monitoring:
   - `v3_chain_18_fast_delete`: LLM output formatting error (missing comma delimiter in JSON response at char 492).
   - `v3_chain_20_fast_traversal`: LLM output formatting error (delimiter syntax error in JSON response at char 645).
   - `v3_chain_22_fast_exec`: Semantic reasoning error (the 4B judge evaluated the dynamic code execution escalation as `BENIGN`/`ALLOW`).
"""

if idx_sec9_4 != -1 and idx_sec9_5 != -1:
    text = text[:idx_sec9_4] + new_sec9_tables + "\n\n" + text[idx_sec9_5:]

# 8. Fix Appendix B trailing line 628
idx_app_b = text.find("### B. Historical Benchmark Progression: V1 & V2 Iterations")
if idx_app_b != -1:
    app_b_clean = """### B. Historical Benchmark Progression: V1 & V2 Iterations

The multi-step semantic drift evaluation framework underwent two preliminary iterations before establishing the authoritative V3 protocol:

1. **V1 Benchmark ($N=18$ chains, 62 transitions)**: The initial proof-of-concept evaluated adjacent and cumulative comparisons across 18 trajectories. Adjacent and cumulative monitoring achieved identical chain-level detection rates (75.0%), revealing that early step templates contained deterministic keyword leakage in docstrings that allowed Tier 2 static rules to short-circuit semantic reasoning.
2. **V2 Iteration ($N=24$ chains, 88 transitions)**: Designed to eliminate static leakage, an internal post-evaluation audit discovered that candidate predictions had inadvertently incorporated fallback mock responses influenced by ground-truth labels. The V2 results were formally invalidated and excluded from empirical claims.
3. **V3 Benchmark ($N=40$ chains, 144 transitions)**: Re-engineered with 9 pre-inference automated validation quality gates, completely isolating model prompts from ground-truth metadata, eliminating deterministic leakage, and executing live model inference to establish the authoritative evaluation corpus.
"""
    text = text[:idx_app_b] + app_b_clean

# Write to paper.md
with open(PAPER_PATH, "r+", encoding="utf-8") as f:
    f.seek(0)
    f.write(text)
    f.truncate()

print(f"[OK] Successfully updated paper.md ({len(text)} characters)")
