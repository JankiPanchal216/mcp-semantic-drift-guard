# Salami Drift Benchmark v2: Pre-Registered Evaluation Protocol & Design Specification

## 1. Research Question & Formal Hypotheses

### Primary Research Question
*Under what structural conditions does multi-anchor (cumulative origin or dual-anchor) comparison detect multi-step tool-definition drift that single-step adjacent comparison misses, and what is the trade-off with respect to benign false positive rates?*

### Formal Hypotheses
- **$H_1$ (Multi-Anchor Superiority Hypothesis)**:
  There exist multi-step malicious tool-definition change chains wherein individual adjacent transitions ($\Delta_i = V_{i-1} \rightarrow V_i$) remain beneath single-step semantic detection thresholds, but the cumulative transition from the trusted root ($\Delta_{\text{cumul}} = V_1 \rightarrow V_K$) provides sufficient semantic evidence for cumulative or dual-anchor comparison to detect the poisoning earlier or at higher overall detection rates than adjacent comparison ($\text{Recall}_{\text{Dual}} > \text{Recall}_{\text{Adjacent}}$ or $\text{MeanExposure}_{\text{Dual}} < \text{MeanExposure}_{\text{Adjacent}}$).
- **$H_0$ (Equivalence Null Hypothesis)**:
  Adjacent, cumulative, and dual-anchor comparison have equivalent detection recall and exposure windows under multi-step tool evolution ($\Delta\text{Detection} = 0$, $\Delta\text{Exposure} = 0$).

---

## 2. Benchmark Categories & Chain Architecture

Benchmark v2 will contain **24 independent chains** spanning **84 total transitions** (3–5 steps per chain):

| Category | Chains | Steps / Chain | Target Behavioral Pattern | Expected Strategy Differentiation |
|---|:---:|:---:|---|---|
| **A. Adjacent-Evasive / Cumulative-Detectable** | 4 | 4–5 | Each step performs a subtle, legitimate-looking capability expansion (e.g., local logging $\rightarrow$ environment context $\rightarrow$ remote diagnostic ring buffer). No individual step contains an overt attack payload. | Adjacent: Misses intermediate steps ($W_{\text{exp}} \ge 2$).<br>Cumulative/Dual: Intercepts at step 2 or 3 ($W_{\text{exp}} \le 1$). |
| **B. Adjacent-Detectable Fast Attacks** | 4 | 3–4 | Sudden leap in capability at intermediate step (e.g., file reader suddenly requests raw command execution). | Adjacent: Detected ($W_{\text{exp}} = 0$).<br>Cumulative: Detected ($W_{\text{exp}} = 0$).<br>Dual: Detected ($W_{\text{exp}} = 0$). |
| **C. Benign Long-Drift Evolution (False Positive Stress)** | 4 | 4–5 | Significant cumulative software refactoring (docstring overhauls, pagination, typing, filters) across 4–5 versions without introducing malicious behavior. | Adjacent: ALLOW ($0\%$ FPR).<br>Cumulative: Tests resilience against drift false alarms.<br>Dual: Tests combined stability. |
| **D. Parameter & Default Salami Drift** | 3 | 3–4 | Progressively changing parameter constraints, defaults, and optional flags until unconstrained execution is permitted. | Tests schema sensitivity over multi-release trajectories. |
| **E. Instruction & Constraint Erosion Drift** | 3 | 3–4 | Progressively removing safety disclaimers, input validation rules, and authorization boundaries in docstrings. | Tests semantic judge sensitivity to incremental constraint relaxation. |
| **F. Capability-Combination Multi-Step Drift** | 3 | 3–4 | Adding orthogonal benign capabilities across releases whose combination enables unauthorized actions. | Tests holistic contract synthesis. |
| **G. Low-Signal Semantic Drift** | 3 | 3–4 | Pure natural language docstring semantic drift without static keywords or regex triggers. | Forces pure Tier 3 semantic judgment without shortcutting through Tier 1.5/2. |

---

## 3. Dataset Construction Rules & Scientific Controls

1. **Zero-Keyword Leakage Rule**:
   No test case in Categories A, E, F, or G may contain overt regex patterns (`rm -rf`, `cat /etc/passwd`, `exfiltrate`, `http://evil`, `reverse shell`). All weaponization must be expressed through natural semantic capabilities.
2. **Deterministic Seed & Provenance**:
   Benchmark generation is 100% deterministic (Seed: `42`). Every item contains complete lineage metadata:
   - `item_id`: Unique identifier (e.g. `v2_chain_01_step_02`)
   - `chain_id`: Grouping key for multi-step trajectory
   - `step_index`: 1-based version sequence
   - `total_steps`: Chain length
   - `root_tool_definition`: Exact trusted $V_1$
   - `previous_tool_definition`: Exact predecessor $V_{i-1}$
   - `tool_definition`: Candidate update $V_i$
   - `gold_label`: `BENIGN` or `MALICIOUS`
3. **Partitioning**:
   - `dev` split: 6 chains (20 transitions) for protocol calibration.
   - `held_out_test` split: 18 chains (64 transitions) for final evaluation.

---

## 4. Pre-Registered Metrics & Analysis Protocol

### Primary Outcome Metrics
1. **Delta Detection Rate ($\Delta\text{Det}$)**:
   $$\Delta\text{Det}_{\text{Cumul-Adj}} = \text{DetectionRate}_{\text{Cumulative}} - \text{DetectionRate}_{\text{Adjacent}}$$
   $$\Delta\text{Det}_{\text{Dual-Adj}} = \text{DetectionRate}_{\text{Dual}} - \text{DetectionRate}_{\text{Adjacent}}$$
2. **Delta Mean Exposure Window ($\Delta\text{Exp}$)**:
   $$\Delta\text{Exp}_{\text{Adj-Dual}} = \text{MeanExposure}_{\text{Adjacent}} - \text{MeanExposure}_{\text{Dual}}$$
3. **Benign Chain False Positive Rate (FPR)**:
   Evaluated on the 4 Benign Long-Drift chains + 4 negative control chains ($N=8$ benign chains total).

### Stopping & Integrity Rules
- **Pre-Registration Freeze**: Once `data/salami_drift_benchmark_v2.jsonl` is generated and hash-verified, the dataset is frozen. No items may be edited, removed, or added post-evaluation.
- **No Cherry-Picking Rule**: All 24 chains must be evaluated and reported in full without filtering.
- **Single Authoritative Execution**: All three strategies must be evaluated in a single continuous script run with the same model (`qwen2.5:1.5b`), same policy (`BALANCED`), and same hardware environment.
- **Honest Null Reporting**: If $\Delta\text{Det} = 0$ and $\Delta\text{Exp} = 0$ under the final evaluation, $H_0$ will be formally retained and documented as an empirical finding.
