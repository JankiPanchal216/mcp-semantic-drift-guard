from pathlib import Path

p = Path("paper.md")
with open(p, "r", encoding="utf-8") as f:
    text = f.read()

# Replace Abstract
old_abs_start = text.find("## Abstract\n")
old_abs_end = text.find("\n---\n\n## 1. Introduction")

new_abs = """## Abstract

The Model Context Protocol (MCP) enables Large Language Model (LLM) agents to dynamically discover and execute external tools at runtime. However, because advertised tool contracts—including docstrings, parameter descriptions, and schemas—are directly ingested into agent prompts, malicious or compromised upstream servers can mount tool-poisoning attacks to hijack agent execution. While single-step attacks inject overt malicious directives, sophisticated adversaries can partition an unauthorized capability escalation across multiple consecutive, individually subtle release updates—a threat model we formalize as **Salami Drift** (or incremental "rug-pull" attacks). Existing defenses rely either on byte-level cryptographic pinning (SHA-256), which alerts on every benign docstring clarification or parameter refactoring, or on static capability scanners that fail against subtle paraphrasing.

Across an empirical audit of 621 historical release transitions from open-source MCP repositories, 31 releases (4.99%) contained legitimate tool-definition modifications (an operator burden of 0.050 alerts per release transition), all of which trigger false security reapproval under exact pinning. To address this challenge, we introduce **MCP Semantic Drift Guard**, a multi-tiered defense framework combining sub-millisecond deterministic fast-paths (hash matching, schema constraint auditing, and static regex pre-filtering) with an XML-sandboxed structured diff semantic judge and automatic runtime rollback. In held-out single-step benchmark evaluations ($N=56$; source: `results/computed_metrics.json`), exact cryptographic hash pinning achieves **Precision = 58.9%**, **Recall = 100.0%**, with **Benign FPR = 100.0%**; author-defined static regex rules achieve **Precision = 100.0%**, **Recall = 75.8%**, with **Benign FPR = 0.0%**; and the TF-IDF cosine baseline achieves **Precision = 64.6%**, **Recall = 93.9%**, with **Benign FPR = 73.9%**.

To detect incremental multi-step attacks, we propose **Dual-Anchor Monitoring**, which evaluates candidate updates simultaneously against both immediate predecessor versions ($\Delta_{\\text{adj}}$) and authorized root baselines ($\Delta_{\\text{cumul}}$). On the authoritative **Salami Drift Benchmark V3** ($N=144$ transitions across 40 trajectories), audited for zero deterministic rule leakage and executed under live inference, Dual-Anchor monitoring significantly improves transition recall from **42.5%** (Adjacent-only) to **70.0%** ($F_1 = 0.800$, paired McNemar exact $p = 0.02246$), and increases malicious trajectory detection from **58.3%** to **91.7%** (paired McNemar exact $p = 0.00781$), reducing the mean exposure window from $0.88$ to $0.38$ steps while isolating the operational trade-offs of long-term benign feature accumulation. These results demonstrate that meaning-aware semantic drift detection effectively neutralizes incremental tool-poisoning attacks without imposing intractable operator reapproval overhead."""

if old_abs_start != -1 and old_abs_end != -1:
    text = text[:old_abs_start] + new_abs + text[old_abs_end:]
    with open(p, "r+", encoding="utf-8") as f:
        f.seek(0)
        f.write(text)
        f.truncate()
    print("Successfully updated Abstract in paper.md")
else:
    print("Could not find Abstract boundaries")
