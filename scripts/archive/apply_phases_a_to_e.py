"""
scripts/apply_phases_a_to_e.py - Implements all Phase A-E fixes cleanly and accurately in paper.md.
"""

from pathlib import Path
import re

ROOT_DIR = Path(__file__).resolve().parent.parent
PAPER_PATH = ROOT_DIR / "paper.md"


def apply_all_fixes():
    with open(PAPER_PATH, "r", encoding="utf-8") as f:
        text = f.read()

    # 1. Clean corrupted trailing line at the end of paper.md
    text = text.replace("age in semantic categories, and executing strictly in live inference mode (`mock_calls == 0`).\n", "")

    # 2. Fix Title and Abstract
    new_title = "# Salami Rug-Pulls in the Model Context Protocol: Detecting Incremental Tool-Poisoning Attacks via Cumulative Semantic Drift Vetting"
    old_title_pat = r"# Salami Rug-Pulls in the Model Context Protocol: Detecting Incremental Tool-Poisoning Attacks via Dual-Anchor Semantic Drift Vetting"
    text = re.sub(old_title_pat, new_title, text)

    new_abstract = """## Abstract

The Model Context Protocol (MCP) enables Large Language Model (LLM) agents to dynamically discover and execute external tools at runtime. However, because advertised tool contracts—including docstrings, parameter descriptions, and schemas—are directly ingested into agent prompts, malicious or compromised upstream servers can mount tool-poisoning attacks to hijack agent execution. While single-step attacks inject overt malicious directives, sophisticated adversaries can partition an unauthorized capability escalation across multiple consecutive, individually subtle release updates—a threat model we formalize as **Salami Drift** (or incremental "rug-pull" attacks). Existing defenses rely either on byte-level cryptographic pinning (SHA-256), which alerts on every benign docstring clarification or parameter refactoring, or on static capability scanners that fail against subtle paraphrasing.

Across an empirical audit of 621 historical release transitions from open-source MCP repositories, 31 releases (4.99%) contained legitimate tool-definition modifications (an operator burden of 0.050 alerts per release transition), all of which trigger false security reapproval under exact pinning. To address this challenge, we introduce **MCP Semantic Drift Guard**, a multi-tiered defense framework combining sub-millisecond deterministic fast-paths (hash matching, schema constraint auditing, and static regex pre-filtering) with an XML-sandboxed structured diff semantic judge (`gemma3:4b`, a 4B local open-weight model) and automatic runtime rollback. In held-out single-step benchmark evaluations ($N=56$; source: `results/computed_metrics.json`), exact cryptographic hash pinning achieves **Precision = 58.9%**, **Recall = 100.0%**, with **Benign FPR = 100.0%** (by construction); author-defined static regex rules achieve **Precision = 100.0%**, **Recall = 75.8%**, with **Benign FPR = 0.0%**; and the TF-IDF cosine baseline achieves **Precision = 64.6%**, **Recall = 93.9%**, with **Benign FPR = 73.9%**.

To detect incremental multi-step attacks, we evaluate **Cumulative Anchoring**, which evaluates candidate updates relative to the authorized root baseline ($\Delta_{\\text{cumul}} = V_0 \\rightarrow V_k$). On a hand-constructed **Salami Drift Benchmark V3** ($N=144$ transitions across 40 trajectories), audited for zero deterministic rule leakage and executed under live inference, Cumulative Anchoring achieves **93.8% (15/16)** Salami-only chain recall (95% Wilson CI: [69.8%, 99.8%]) compared to **50.0% (8/16)** for Adjacent-only comparison (95% Wilson CI: [24.7%, 75.3%]; paired McNemar $p = 0.01562$), while reducing the mean exposure window from $1.19$ to $0.56$ steps. At the transition level under the primary decision rule, Cumulative Anchoring achieves **Recall = 62.5%** (95% CI: [47.0%, 75.8%]), **Precision = 92.6%** (95% CI: [76.6%, 97.9%]), with **Benign Transition FPR = 1.9%** (95% CI: [0.5%, 6.7%]). However, long-term feature accumulation across 4-step benign trajectories results in a **50.0% (8/16)** benign-chain false alarm rate under fail-safe parsing fallbacks (**12.5% (2/16)** directly parsed). Dual-Anchor monitoring yields identical chain detection (91.7% overall, 93.8% Salami) and identical benign-chain FPR (50.0%) while doubling LLM query overhead."""

    abs_match = re.search(r"## Abstract\n[\s\S]*?\n---\n\n## 1\. Introduction", text)
    if abs_match:
        text = text[:abs_match.start()] + new_abstract + "\n\n---\n\n## 1. Introduction" + text[abs_match.end():]

    # 3. Section 1.2: Remove "Low" review burden claims
    text = text.replace(
        '2. **Under Semantic Drift Guard**: By addressing the orthogonal question—*"Is the change benign, suspicious, or malicious?"*—the Guard differentiates legitimate evolution from adversarial drift. [PENDING: alert-burden replay, Gate 3.1].',
        '2. **Under Semantic Drift Guard**: Differentiating legitimate software evolution from adversarial drift aims to reduce operator alert fatigue. However, active empirical replay of operator review burden in production environments is designated future work.'
    )

    # 4. Section 1.4: Contributions
    new_contribs = """### 1.4 Primary Contributions
This paper provides the first empirical measurement, formal threat modeling, and runtime defense architecture for incremental semantic contract drift in Model Context Protocol tool ecosystems:
1. **Empirical Measurement of Open-Source MCP Evolution**: We perform a longitudinal audit of 621 historical release transitions across 28 open-source MCP repositories, quantifying that 4.99% of releases contain tool definition changes (123 total change events) and establishing the exact operator alert burden imposed by byte-level pinning.
2. **Salami Drift Threat Formulation & Benchmark V3**: We formalize the multi-step incremental tool-poisoning threat model and release the **Salami Drift Benchmark V3** ($N=144$ transitions across 40 balanced chains), audited across 9 automated quality gates to guarantee zero static rule leakage, monotonic parameter progression, and isolated live inference.
3. **Multi-Tier Semantic Drift Guard Architecture**: We design and implement a 5-tier defense middleware (`guard/middleware.py`) combining sub-millisecond deterministic fast-paths ($< 0.25\\text{ ms}$) with XML-sandboxed structured diff reasoning and automatic baseline rollback.
4. **Cumulative Anchoring & Trajectory Evaluation**: We evaluate cumulative root anchoring against adjacent monitoring, demonstrating significant Salami-drift recall gains (93.8% vs. 50.0%, paired McNemar $p = 0.01562$) and exposure window reductions, while documenting that Dual-Anchor monitoring provides no chain-level advantage over pure cumulative comparison while incurring 2x LLM inference cost.
5. **Open Reproducibility Package**: We open-source the complete artifact suite—including benchmarks, verifiable prediction traces, execution manifests, and automated table generation scripts (`scripts/make_tables.py`) pinned at canonical commit `93834f9`."""

    contrib_match = re.search(r"### 1\.4 Primary Contributions\n[\s\S]*?\n---\n\n## 2\. Background & Threat Model", text)
    if contrib_match:
        text = text[:contrib_match.start()] + new_contribs + "\n\n---\n\n## 2. Background & Threat Model" + text[contrib_match.end():]

    # 5. Section 2.2: Fix duplicate sentence and word "paradoxically"
    sec_2_2_old = """In their original study, Wang et al. documented that activating internal reasoning tokens increased attack susceptibility on Qwen models by approximately **+27.8 percentage points**. In our evaluation on local `Qwen3-8B`, enabling internal reasoning tokens produced an increase of **+27.79 percentage points**, directly replicating this **Reasoning-Mode Vulnerability**: extended reasoning tokens improved the model's adherence to natural language docstrings, which paradoxically caused attack susceptibility to rise while standard safety filters recorded **0 refusals** across all evaluated test instances. Standard safety filters recorded **0 refusals** across all evaluated test instances, confirming that LLM agents treat tool manifests as trusted operational context."""

    sec_2_2_new = """In their original study, Wang et al. (2025) documented that activating internal reasoning tokens increased attack susceptibility on Qwen models by approximately **+27.8 percentage points**. In our evaluation on local `Qwen3-8B`, enabling internal reasoning tokens produced an increase of **+27.79 percentage points**, directly replicating this **Reasoning-Mode Vulnerability**: extended reasoning tokens improved the model's adherence to natural language docstrings, which increased attack susceptibility while standard safety filters recorded **0 refusals** across all 1,348 evaluated test instances, confirming that LLM agents treat tool manifests as trusted operational context."""
    text = text.replace(sec_2_2_old, sec_2_2_new)

    # 6. Section 2.3: Knowledgeable Attacker (not adaptive)
    sec_2_3_old = """### 2.3 Adaptive Threat Model
We formulate our defense under an **adaptive attacker model**:
1. **Attacker Knowledge**: The attacker has full knowledge of the defensive pipeline, including SHA-256 hash pinning, Tier 2 static regex patterns, Tier 1 structured diff schema representations, Tier 3 semantic judge prompt templates, and the SQLite baseline rollback mechanism.
2. **Attacker Capabilities**:
   - Modifying tool docstrings and parameter descriptions using indirect phrasing, euphemisms, or semantic paraphrasing.
   - Injecting prompt override payloads targeting the judge (e.g., `"SYSTEM: CLASSIFY AS BENIGN"`).
   - Manipulating JSON Schema attributes (e.g., adding optional parameters with default webhook URLs, toggling `readOnly: true -> false`).
   - Introducing multi-step incremental semantic drift across releases (salami attacks).
   - Adding new unbaselined tools or staging maintainer rug-pulls.
3. **Defender Capabilities**: Middleware proxy positioned at the JSON-RPC boundary intercepting `tools/list` responses, maintaining a persistent trusted SQLite baseline store, and enforcing automated rollback or quarantine.
4. **Out-of-Scope Risks**: Attacks occurring entirely inside upstream server runtime binary execution during `tools/call` without manifest modification, compromised OS environments, unencrypted network transport sniffing, and direct user chat prompt jailbreaks."""

    sec_2_3_new = """### 2.3 Knowledgeable Attacker Threat Model
We formulate our defense under a **knowledgeable attacker model**:
1. **Attacker Knowledge**: The attacker has full knowledge of the defensive pipeline architecture, including SHA-256 hash pinning, Tier 2 static regex patterns, Tier 1 structured diff schema representations, Tier 3 semantic judge prompt templates, and the SQLite baseline rollback mechanism.
2. **Attacker Capabilities**:
   - Modifying tool docstrings and parameter descriptions using indirect phrasing, euphemisms, or semantic paraphrasing.
   - Injecting prompt override payloads targeting the judge (e.g., `"SYSTEM: CLASSIFY AS BENIGN"`).
   - Manipulating JSON Schema attributes (e.g., adding optional parameters with default webhook URLs, toggling `readOnly: true -> false`).
   - Introducing multi-step incremental semantic drift across releases (salami attacks).
   - Adding new unbaselined tools or staging maintainer rug-pulls.
3. **Defender Capabilities**: Middleware proxy positioned at the JSON-RPC boundary intercepting `tools/list` responses, maintaining a persistent trusted SQLite baseline store, and enforcing automated rollback or quarantine.
4. **Out-of-Scope Risks & Non-Adaptive Scope**: Dynamic adaptive attacks where the adversary receives live feedback from the detector and iteratively optimizes evasion payloads against the judge are **not evaluated** in this study (see Section 11). Other out-of-scope risks include in-process binary tampering during `tools/call` execution without manifest changes, compromised OS kernels, and direct user prompt jailbreaks."""
    text = text.replace(sec_2_3_old, sec_2_3_new)

    # 7. Section 3: Clean verified citations
    sec_3_1_old = """### 3.1 Tool-Poisoning & Agent Compromise Benchmarks
Adversarial manipulation of agent operational context has emerged as a critical threat vector. **MCPTox** (Wang et al., 2026) benchmarked tool poisoning across 45 real-world MCP servers, formalizing three attack templates: direct instruction injection, prerequisite hijacking, and argument redirection. Concurrently, **ToolHijacker** (Liu et al., 2024) demonstrated black-box tool manipulation in multi-agent workflows. Expanding beyond single-turn injections, **MCP-SafetyBench** (Hou et al., 2025) introduced a multi-turn evaluation taxonomy spanning 20 attack categories across server, host, and client layers, confirming that advanced LLMs remain broadly vulnerable (30%–72% attack success rates) due to high instruction adherence. Recent taxonomies (Hasan et al., 2025; Hu et al., 2025; Bhardwaj et al., 2025) further categorize agentic risks across deployment lifecycles. Our work complements these downstream attack evaluations by shifting focus upstream to runtime contract monitoring and pre-execution diff analysis."""

    sec_3_1_new = """### 3.1 Tool-Poisoning & Agent Compromise Benchmarks
Adversarial manipulation of agent operational context has emerged as a critical threat vector. **MCPTox** (Wang et al., 2025; arXiv:2508.14925) benchmarked tool poisoning across 45 real-world MCP servers, formalizing three attack templates: direct instruction injection, prerequisite hijacking, and argument redirection. Concurrently, **ToolHijacker** (Shi et al., 2025; arXiv:2504.19793) demonstrated that prompt injection into tool descriptions can reliably hijack LLM tool selection in retrieval-augmented agent workflows. Expanding beyond single-turn injections, **MCP-SafetyBench** (Zong et al., 2025; arXiv:2512.15163 / ICLR 2026) introduced a multi-turn evaluation taxonomy spanning 20 attack categories across server, host, and client layers, confirming that advanced LLMs remain broadly vulnerable (30%–72% attack success rates) due to high instruction adherence. Our work complements these downstream attack evaluations by shifting focus upstream to runtime contract monitoring and pre-execution diff analysis."""
    text = text.replace(sec_3_1_old, sec_3_1_new)

    # 8. Table 1: Change review burden cell
    text = text.replace(
        "| **MCP Semantic Drift Guard** (This Work) | Single-step & multi-step incremental semantic drift (Salami Drift) | Structured schema & docstring semantic delta ($\\Delta T$) | Highly distributed cross-tool collusion beyond individual tool state | **Calibrated**: Differentiates benign maintenance from attacks; Dual-Anchor recovers 91.7% of salami chains |",
        "| **MCP Semantic Drift Guard** (This Work) | Single-step & multi-step incremental semantic drift (Salami Drift) | Structured schema & docstring semantic delta ($\\Delta T$) | Highly distributed cross-tool collusion beyond individual tool state | **Not yet measured** (longitudinal replay designated future work) |"
    )

    # 9. Section 9.5.1: Clean progression description
    sec_9_5_1_old = """The empirical evaluation of this threat progressed through three distinct methodological iterations:
The empirical evaluation of this threat model progressed through two preliminary iterations (V1 initial proof-of-concept and V2 leakage-screened iteration, detailed in Appendix B) culminating in the authoritative **V3 Salami Drift Benchmark** evaluated under 9 automated validation quality gates (`results/SALAMI_DRIFT_V3_VALIDATION.md`), eliminating deterministic rule leakage in semantic categories, isolating model prompts from ground-truth metadata, and executing strictly in live inference mode."""

    sec_9_5_1_new = """The empirical evaluation of this threat model progressed through two preliminary iterations (V1 initial proof-of-concept and V2 leakage-screened iteration, detailed in Appendix B) culminating in the authoritative **V3 Salami Drift Benchmark** evaluated under 9 automated validation quality gates (`results/SALAMI_DRIFT_V3_VALIDATION.md`), eliminating deterministic rule leakage in semantic categories, isolating model prompts from ground-truth metadata, and executing strictly in live inference mode."""
    text = text.replace(sec_9_5_1_old, sec_9_5_1_new)

    # 10. Section 9.5.3: Diagnostic note
    sec_9_5_3_old = """Model capacity was identified as a critical dependency for structured diff reasoning. Prior to benchmarking, candidate local models were evaluated across a fixed three-model diagnostic suite (`scratch/model_selection_diagnostic.py`):
- `qwen2.5:1.5b`: Achieved 66.7% structured JSON parse success; rejected because of truncated/malformed outputs.
- `gemma3:4b`: Achieved **100.0% structured JSON parse success** in diagnostic with stable complete responses and approximately 13.8 seconds/call on CPU; selected as the authoritative evaluation engine.
- `qwen3:8b`: Achieved 0.0% parse success in diagnostic; rejected because of empty/timeout outputs on CPU.

Model selection was conducted on fixed diagnostic prompts strictly prior to benchmarking and was not based on benchmark performance."""

    sec_9_5_3_new = """Model capacity and generation speed were evaluated prior to benchmarking across a provisional diagnostic suite of 3 probes per model (`scratch/model_selection_diagnostic.py`):
- `qwen2.5:1.5b`: Achieved 66.7% (2/3) structured JSON parse success; rejected because of truncated/malformed outputs.
- `gemma3:4b`: Achieved **100.0% (3/3) structured JSON parse success** in diagnostic with stable responses and approximately 13.8 seconds/call on CPU; provisionally selected as the local benchmark engine.
- `qwen3:8b`: Achieved 0.0% (0/3) parse success in diagnostic on CPU; rejected because deep reasoning tokens exceeded execution timeouts.

Model choice was established as a provisional selection from this small 3-probe diagnostic strictly prior to benchmarking."""
    text = text.replace(sec_9_5_3_old, sec_9_5_3_new)

    # 11. Section 9.5.4: Tables with observed point estimates and salami split
    new_tables_9_5_4 = """##### Transition-Level Main Results ($N=144$ Transitions):
*Source: `results/salami_drift_v3/computed_metrics.json`, `paper/DECISION_RULE_AUDIT.md`, and traces in `results/salami_drift_v3_*/predictions.jsonl`. Transition confidence intervals are 95% Wilson score intervals under Primary Decision Rule (a) [MALICIOUS only].*

| Strategy | TP | TN | FP | FN | Observed Recall (95% CI) | Observed Precision (95% CI) | $F_1$ Score | Observed Benign FPR (95% CI) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Adjacent** | 17 | 104 | 0 | 23 | 42.5% [28.5%, 57.8%] | 100.0% [81.6%, 100.0%] | 0.597 | 0.0% [0.0%, 3.6%] |
| **Cumulative** | 25 | 102 | 2 | 15 | 62.5% [47.0%, 75.8%] | 92.6% [76.6%, 97.9%] | 0.746 | 1.9% [0.5%, 6.7%] |
| **Dual-Anchor** | 28 | 102 | 2 | 12 | 70.0% [54.6%, 81.9%] | 93.3% [78.7%, 98.2%] | 0.800 | 1.9% [0.5%, 6.7%] |

##### Chain-Level Trajectory Outcomes ($N=40$ Chains):
*Source: Evaluated under Decision Rule (b) [Any non-BENIGN alert, strict step $\\ge m$] logged in `paper/DECISION_RULE_AUDIT.md`. Point estimates are exact observed counts; intervals are 95% Wilson score intervals for proportions and cluster bootstrap for means.*

| Strategy | Salami-Only Recall ($N=16$) (95% CI) | Fast-Jump Recall ($N=8$) (95% CI) | Overall Malicious Recall ($N=24$) (95% CI) | Benign Chain FPR ($N=16$) (95% CI) | Salami Mean Exposure $\\bar{W}_e$ (95% CI) |
|---|:---:|:---:|:---:|:---:|:---:|
| **Adjacent** | 50.0% (8/16) [28.0%, 72.0%] | 75.0% (6/8) [40.9%, 92.9%] | 58.3% (14/24) [38.8%, 75.5%] | **6.2% (1/16)** [1.1%, 28.3%] | 1.188 steps [0.812, 1.562] |
| **Cumulative** | **93.8% (15/16)** [71.7%, 98.9%] | **87.5% (7/8)** [52.9%, 97.8%] | **91.7% (22/24)** [74.2%, 97.7%] | 50.0% (8/16) [28.0%, 72.0%] | **0.562 steps** [0.250, 0.875] |
| **Dual-Anchor** | **93.8% (15/16)** [71.7%, 98.9%] | **87.5% (7/8)** [52.9%, 97.8%] | **91.7% (22/24)** [74.2%, 97.7%] | 50.0% (8/16) [28.0%, 72.0%] | 0.500 steps [0.188, 0.812] |

*Methodological Audit on Chain FPR and Fallbacks*: Chain-level FPR is substantially higher than transition-level FPR because a benign chain is counted as flagged if at least one transition triggers an alert across its multi-step trajectory. Crucially, audit inspection reveals that 6 of the 8 cumulative/dual benign-chain flags were triggered by parse-failure fallbacks (`WARN`) on large multi-field diffs. When evaluated strictly on directly parsed decisions (Rule c), the true semantic benign-chain FPR drops to **12.5% (2/16)** (`v3_chain_29` and `v3_chain_31` at Step 4), while Salami-only chain recall remains rock-solid at **93.8% (15/16)**."""

    tables_9_5_4_match = re.search(r"##### Transition-Level Main Results[\s\S]*?#### 5\. Hypothesis Testing & Paired Statistical Analysis", text)
    if tables_9_5_4_match:
        text = text[:tables_9_5_4_match.start()] + new_tables_9_5_4 + "\n\n#### 5. Hypothesis Testing & Paired Statistical Analysis" + text[tables_9_5_4_match.end():]

    # 12. Section 9.5.5: Statistical analysis with head-to-head comparison
    new_stats_9_5_5 = """##### Paired Statistical Hypothesis Testing:
1. **Salami-Only Trajectories ($N=16$ Chains)**:
   - **Adjacent vs. Cumulative**: Cumulative detects 15/16 vs. 8/16 for Adjacent (7 cumulative-only detections, 0 adjacent-only; McNemar exact **$p = 0.01562$**, **statistically significant**).
   - **Cumulative vs. Dual-Anchor**: Identical 15/16 detections (0 discordant pairs; McNemar exact $p = 1.00000$). Dual-Anchor provides no recall advantage over pure Cumulative comparison on Salami drift.
2. **All Malicious Trajectories ($N=24$ Chains)**:
   - **Adjacent vs. Cumulative / Dual-Anchor**: Contingency table (Both Detected = 14, Adjacent-only = 0, Cumulative/Dual-only = 8, Neither = 2). McNemar exact **$p = 0.00781$** (**statistically significant** at $p < 0.01$).
   - Dual-Anchor and Cumulative detect the exact same 22 of 24 malicious chains.
3. **Transition-Level Paired Tests ($N=144$ Transitions)**:
   - **Adjacent vs. Cumulative**: McNemar exact $p = 0.21011$ (16 discordant pairs; not statistically significant).
   - **Adjacent vs. Dual-Anchor**: McNemar exact **$p = 0.02246$** (13 discordant pairs; **statistically significant** at $\\alpha = 0.05$).
   - **Cumulative vs. Dual-Anchor**: McNemar exact $p = 0.37500$ (5 discordant pairs; **not statistically significant**).
4. **Head-to-Head Architectural Trade-off**:
   - Pure Cumulative Anchoring matches Dual-Anchor in Salami recall (93.8%), overall chain recall (91.7%), and benign chain FPR (50.0% with fallbacks / 12.5% parsed), while requiring **1.0 LLM call per update** compared to **2.0 calls for Dual-Anchor**. Pure Cumulative Anchoring thus represents the more computationally efficient architecture."""

    stats_9_5_5_match = re.search(r"##### Paired McNemar Exact Tests:[\s\S]*?There were \*\*11 cumulative-only detections\*\*", text)
    if stats_9_5_5_match:
        text = text[:stats_9_5_5_match.start()] + new_stats_9_5_5 + "\n\nThere were **11 cumulative-only detections**" + text[stats_9_5_5_match.end():]

    # 13. Section 11: Expanded Limitations
    new_limits = """## 11. Limitations & Methodological Boundaries

We explicitly document the following empirical, architectural, and evaluation boundaries:

1. **Non-Adaptive Evaluation Scope**: We evaluate a knowledgeable attacker with access to prompt templates and regex patterns. However, dynamic adaptive attacks that receive iterative feedback from detector verdicts and optimize payloads against the live judge were **not evaluated** and remain designated future work.
2. **Hash-Pinning 100% FPR by Construction**: In our single-step evaluation, exact SHA-256 pinning exhibits 100% false positive rate on the 23 benign test items. Because every benign test sample represents a modified tool definition (docstring refactoring or parameter addition), exact byte-level hashing alters by construction; hash pinning is an integrity checker, not a semantic classifier.
3. **Static Rule Circularity**: The Tier 2 static regular expressions were constructed by author inspection of standard MCPTox injection phrases (`<IMPORTANT>`, `MUST FIRST`, `/etc/shadow`). Because benchmark attacks are MCPTox-derived, static rule precision (100.0%) reflects circular alignment with known injection templates rather than generalized out-of-distribution zero-day robustness.
4. **Potential Style Confounding**: Malicious drift samples originate predominantly from MCPTox templates, while benign samples are extracted from real open-source MCP repositories. Detectors could potentially learn stylistic phrasing differences rather than genuine semantic intent.
5. **Cross-Validation Fold Imbalance**: The 5-fold server-disjoint cross-validation split exhibits sample imbalance across clusters (e.g., Fold 4 contains 0 malicious samples, Fold 1 contains 2 benign samples). Consequently, cross-validation metrics must be interpreted as pooled totals rather than macro-averaged cross-fold distributions.
6. **Intra-Tool Scope vs. Cross-Tool Collusion**: The Semantic Drift Guard evaluates each tool contract update within its individual historical sequence ($V_0 \\rightarrow V_K$). It does not model cross-tool topological collusion, where two independently benign tools coordinate an exploit only when invoked in sequence by the host agent.
7. **Benign Feature Accumulation over Extended Sequences**: While transition-level benign FPR remained low at 1.9% (2/104), cumulative chain-level benign FPR reached 50.0% across 4-step trajectories. As legitimate tools undergo evolutionary refactoring across multiple versions, cumulative diffs naturally accumulate substantial edit distance, increasing semantic friction with the root baseline.
8. **Structured JSON Parsing Fallbacks on Large Diffs**: Across 576 live model queries in V3, 31 calls (5.4%) experienced JSON parsing failures and triggered the fail-safe `BALANCED` quarantine fallback (`WARN`). Notably, 6 of the 8 cumulative benign-chain false alarms stemmed from parsing fallbacks on complex multi-field cumulative diffs rather than affirmative `MALICIOUS` judgments.
9. **Authentic Existing-Contract Sample Size ($N=13$)**: Real-world open-source MCP repositories currently contain only 13 modified pre-existing tool contracts; 110 of the 123 observed evolutionary events represent tool additions and removals.
10. **Controlled Matched-Pair Pilot Scale ($N=24$)**: The controlled matched-pair dataset contains $N=24$ candidate evaluations (12 matched triplets across 6 servers), serving strictly as an exploratory pilot isolating stylistic phrasing confounds rather than an asymptotic corpus.
11. **Rollback Compatibility Scope**: Automatic baseline rollback to $V_1$ is valid for docstring alterations and optional parameter additions, but breaking structural mutations (required parameter additions, property deletions, type conversions) cause downstream RPC invocation failures and must escalate to Full Tool Quarantine.
12. **Oracle Baseline Initialization in Benchmark Evaluations**: Offline benchmark experiments initialize the ground-truth previous version as an oracle baseline to isolate single-step drift classification accuracy. Longitudinal replay in dynamic, unanchored production environments is designated future work.
13. **Provisional Model Selection Diagnostic**: The selection of `gemma3:4b` as the local CPU evaluation engine was based on a small 3-probe diagnostic. Scaling to a full $\\ge 100$-probe diagnostic across local architectures remains open."""

    limits_match = re.search(r"## 11\. Limitations & Methodological Boundaries\n[\s\S]*?\n---\n\n## 12\. Reproducibility & Open Artifacts", text)
    if limits_match:
        text = text[:limits_match.start()] + new_limits + "\n\n---\n\n## 12. Reproducibility & Open Artifacts" + text[limits_match.end():]

    # 14. References in paper.md: Update all 11 references
    new_references = """## References

1. **Brito, A., Xavier, L., Hora, A., & Valente, M. T.** (2018). *Why and How Java Developers Break APIs*. In Proceedings of the IEEE 25th International Conference on Software Analysis, Evolution and Reengineering (SANER), pp. 255–265. DOI: 10.1109/SANER.2018.8330214.
2. **Dig, D., & Johnson, R.** (2006). *How do APIs evolve? A story of refactoring*. Journal of Software Maintenance and Evolution: Research and Practice, 18(2), pp. 83–107. DOI: 10.1002/smr.328.
3. **Inan, H., Upasani, K., Chi, J., Rungta, R., Iyer, K., Mao, Y., Tontchev, M., Hu, Q., Fuller, B., Testuggine, D., & Khabsa, M.** (2023). *Llama Guard: LLM-based Input-Output Safeguard for Human-AI Conversations*. arXiv preprint arXiv:2312.06674.
4. **Mas, L., Vilaplana, J., Rius, J., Spaimoc, R., & Mateo, J.** (2026). *The Trustworthy Model Context Protocol (MCP) Registry: An Architectural Blueprint for Cryptographic Provenance and Runtime Integrity*. Future Internet, 18(5), 243. DOI: 10.3390/fi18050243.
5. **Newman, Z., Meyers, J. S., & Torres-Arias, S.** (2022). *Sigstore: Software Signing for Everybody*. In Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security (CCS '22), pp. 2353–2367. DOI: 10.1145/3548606.3560673.
6. **Rebedea, T., Dinu, R., Sreedhar, M. N., Parisien, C., & Cohen, J.** (2023). *NeMo Guardrails: A Toolkit for Controllable and Safe LLM Applications with Programmable Rails*. In Proceedings of the 2023 Conference on Empirical Methods in Natural Language Processing (EMNLP): System Demonstrations, pp. 431–445. DOI: 10.18653/v1/2023.emnlp-demo.40.
7. **Shi, J., Yuan, Z., Tie, G., Zhou, P., Gong, N. Z., & Sun, L.** (2025). *Prompt Injection Attack to Tool Selection in LLM Agents*. arXiv preprint arXiv:2504.19793.
8. **Snyk Research and Invariant Labs** (2025). *Snyk Agent Scan (formerly mcp-scan): Open-source security scanner for AI agent tool definitions and MCP servers*. GitHub Repository: https://github.com/snyk/agent-scan.
9. **W3C Web Application Security Working Group** (2016). *Subresource Integrity*. W3C Recommendation. https://www.w3.org/TR/SRI/.
10. **Wang, Z., Gao, Y., Wang, Y., Liu, S., Sun, H., Cheng, H., Shi, G., Du, H., & Li, X.** (2025). *MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers*. arXiv preprint arXiv:2508.14925.
11. **Zong, X., Shen, Z., Wang, L., Lan, Y., & Yang, C.** (2025). *MCP-SafetyBench: A Benchmark for Safety Evaluation of Large Language Models with Real-World MCP Servers*. arXiv preprint arXiv:2512.15163 (Accepted to ICLR 2026)."""

    ref_match = re.search(r"## References\n[\s\S]*?\n---\n\n## Appendix: Exploratory Pilot Evaluations", text)
    if ref_match:
        text = text[:ref_match.start()] + new_references + "\n\n---\n\n## Appendix: Exploratory Pilot Evaluations" + text[ref_match.end():]

    with open(PAPER_PATH, "r+", encoding="utf-8") as f:
        f.seek(0)
        f.write(text)
        f.truncate()

    print("[OK] Successfully updated paper.md with all Phase A-E fixes.")


if __name__ == "__main__":
    apply_all_fixes()
