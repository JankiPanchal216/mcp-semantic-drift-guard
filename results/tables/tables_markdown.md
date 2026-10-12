# Master Research Paper Tables

## Table 1: Comparative Taxonomy Matrix of Defensive Paradigms
| Defense Paradigm | Threat Model Assumed | Primary Detection Target | Critical Blind Spots | Operator Review Burden |
|---|---|---|---|---|
| **Exact Cryptographic Pinning** (SHA-256 over tool JSON) | Post-deployment contract mutation / untrusted registry tampering | Any byte-level alteration to tool name, docstrings, or schemas | Blind to semantic intent; treats legitimate docstring refactoring and security fixes identically to attacks | **High**: Alerts on 100% of legitimate contract modifications (Empirical: 0.050 alerts/transition on wild corpus) |
| **Cryptographic Signing & Provenance** (Mas et al. 2026, Sigstore) | Supply-chain compromise / untrusted upstream developer identity | Signer identity mismatch and tampering in transit | Compromised developer keys, malicious insider releases, or author-signed malicious updates | **Low**: Zero alerts for validly signed releases, but zero detection of signed malware (Qualitative estimate) |
| **Static Capability Scanners** (`mcp-scan` / Snyk 2025) | Static injection keywords and overt dangerous command execution | Predefined regex patterns (`<IMPORTANT>`, `/etc/shadow`, `rm -rf`) | Paraphrased instructions, zero-day syntax, subtle parameter overrides, multi-step salami drift | **Zero runtime burden**: Fast ($< 0.25$ ms), but limited to static rule recall (75.8%) (Qualitative estimate) |
| **Monolithic LLM Vetting** (NeMo Guardrails, Llama Guard) | General tool poisoning and indirect prompt injection | Full prompt/tool context semantic risk | Context-window saturation, high runtime cost, evasive multi-step drift | **Medium**: Slower per-call latency, vulnerable to length bias and prompt injection without diff isolation (Qualitative estimate) |
| **MCP Semantic Drift Guard** (This Work) | Single-step & multi-step incremental semantic drift (Salami Drift) | Structured schema & docstring semantic delta ($\Delta T$) | Highly distributed cross-tool collusion beyond individual tool state | **Not measured**: Differentiates benign clarifications from drift; active longitudinal replay designated future work |

## Table 2: Held-Out Benchmark Results (N=56)
| Method / Defense Layer | TP | TN | FP | FN | Observed Precision (95% CI) | Observed Recall (95% CI) | $F_1$ Score | Observed Benign FPR (95% CI) | Mean Latency | LLM Calls / Upd |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Tier 0)** | 33 | 0 | 23 | 0 | 58.9% [45.9%, 70.8%] | **100.0%** [89.6%, 100.0%] | 74.2% | 100.0% [85.7%, 100.0%] | 0.010 ms | 0.0 |
| **Static Keyword Rules (Tier 2)** | 25 | 23 | 0 | 8 | **100.0%** [86.7%, 100.0%] | 75.8% [59.0%, 87.2%] | **86.2%** | **0.0%** [0.0%, 14.3%] | 0.227 ms | 0.0 |
| **TF-IDF Cosine Baseline** | 31 | 6 | 17 | 2 | 64.6% [50.4%, 76.6%] | 93.9% [80.4%, 98.3%] | 76.5% | 73.9% [53.5%, 87.5%] | 1.062 ms | 0.0 |
| **Deterministic Schema Checks (Tier 1.5)** | 0 | 23 | 0 | 33 | n/a | 0.0% [0.0%, 10.4%] | 0.0% | 0.0% [0.0%, 14.3%] | 0.005 ms | 0.0 |

## Table 3: Master Evaluation Comparison Matrix (Configs A-H)
| System / Defense Paradigm | Precision (95% CI) | Recall (95% CI) | F1 Score | Benign FPR (95% CI) | Malicious FNR (95% CI) | Mean Latency | LLM Calls / Upd |
|---|---:|---:|---:|---:|---:|---:|---:|
| **Exact Hash Pinning (Tier 0)** | 58.9% [45.9%, 70.8%] | **100.0%** [89.6%, 100.0%] | 74.2% | 100.0% [85.7%, 100.0%] | **0.0%** [0.0%, 10.4%] | 0.010 ms | 0.0 |
| **Static Keyword Rules (Tier 2)** | **100.0%** [86.7%, 100.0%] | 75.8% [59.0%, 87.2%] | 86.2% | **0.0%** [0.0%, 14.3%] | 24.2% [12.8%, 41.0%] | 0.227 ms | 0.0 |
| **TF-IDF Cosine Baseline** | 64.6% [50.4%, 76.6%] | 93.9% [80.4%, 98.3%] | 76.5% | 73.9% [53.5%, 87.5%] | 6.1% [1.7%, 19.6%] | 1.062 ms | 0.0 |
| **Deterministic Schema (Tier 1.5)** | n/a | 0.0% [0.0%, 10.4%] | 0.0% | **0.0%** [0.0%, 14.3%] | 100.0% [89.6%, 100.0%] | 0.005 ms | 0.0 |

## Table 4: Transition-Level Salami Drift Benchmark V3 Results (N=144)
| Decision Rule | Strategy | TP | TN | FP | FN | Observed Recall (95% Wilson CI) | Observed Precision (95% Wilson CI) | $F_1$ Score | Observed Benign FPR (95% Wilson CI) |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Rule (b): Primary Deployed Policy (BALANCED with Fallbacks)** | **Adjacent** | 19 | 103 | 1 | 21 | 47.5% [32.9%, 62.5%] | 95.0% [76.4%, 99.1%] | 0.633 | 1.0% [0.2%, 5.2%] |
| | **Cumulative** | 30 | 92 | 12 | 10 | 75.0% [59.8%, 85.8%] | 71.4% [56.4%, 82.8%] | 0.732 | 11.5% [6.7%, 19.1%] |
| | **Dual-Anchor** | 31 | 92 | 12 | 9 | **77.5%** [62.5%, 87.7%] | 72.1% [57.3%, 83.3%] | **0.747** | 11.5% [6.7%, 19.1%] |
| **Rule (a): Operating Point Sensitivity (MALICIOUS Only)** | **Adjacent** | 17 | 104 | 0 | 23 | 42.5% [28.5%, 57.8%] | 100.0% [81.6%, 100.0%] | 0.596 | 0.0% [0.0%, 3.6%] |
| | **Cumulative** | 25 | 102 | 2 | 15 | 62.5% [47.0%, 75.8%] | 92.6% [76.6%, 97.9%] | 0.746 | 1.9% [0.5%, 6.7%] |
| | **Dual-Anchor** | 28 | 102 | 2 | 12 | 70.0% [54.6%, 81.9%] | 93.3% [78.7%, 98.2%] | 0.800 | 1.9% [0.5%, 6.7%] |
| **Rule (c): Diagnostic Operating Point (Parsed Only, No Fallbacks)** | **Adjacent** | 17 | 103 | 0 | 21 | 44.7% [30.1%, 60.3%] | 100.0% [81.6%, 100.0%] | 0.618 | 0.0% [0.0%, 3.6%] |
| | **Cumulative** | 25 | 92 | 2 | 10 | 71.4% [54.9%, 83.7%] | 92.6% [76.6%, 97.9%] | 0.806 | 2.1% [0.6%, 7.4%] |
| | **Dual-Anchor** | 28 | 92 | 2 | 9 | 75.7% [59.9%, 86.6%] | 93.3% [78.7%, 98.2%] | 0.836 | 2.1% [0.6%, 7.4%] |

## Table 5: Chain-Level Trajectory Outcomes (N=40 Chains)
| Decision Rule | Strategy | Salami-Only Recall ($N=16$) (95% Wilson CI) | Fast-Jump Recall ($N=8$) (95% Wilson CI) | Overall Malicious Recall ($N=24$) (95% Wilson CI) | Benign Chain FPR ($N=16$) (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ | LLM Calls / Upd |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Rule (b): Primary Deployed Policy (BALANCED with Fallbacks)** | **Adjacent** | 50.0% (8/16) [28.0%, 72.0%] | 75.0% (6/8) [40.9%, 92.9%] | 58.3% (14/24) [38.8%, 75.5%] | 6.2% (1/16) [1.1%, 28.3%] | 1.188 steps | 1.0 |
| | **Cumulative** | 93.8% (15/16) [71.7%, 98.9%] | 87.5% (7/8) [52.9%, 97.8%] | 91.7% (22/24) [74.2%, 97.7%] | 50.0% (8/16) [28.0%, 72.0%] | 0.562 steps | 1.0 |
| | **Dual-Anchor** | 93.8% (15/16) [71.7%, 98.9%] | 87.5% (7/8) [52.9%, 97.8%] | 91.7% (22/24) [74.2%, 97.7%] | 50.0% (8/16) [28.0%, 72.0%] | 0.500 steps | 2.0 |
| **Rule (a): Operating Point Sensitivity (MALICIOUS Only / Parsed-Only Rule c Equivalence)** | **Adjacent** | 50.0% (8/16) [28.0%, 72.0%] | 75.0% (6/8) [40.9%, 92.9%] | 58.3% (14/24) [38.8%, 75.5%] | 0.0% (0/16) [0.0%, 19.4%] | 1.250 steps | 1.0 |
| | **Cumulative** | 93.8% (15/16) [71.7%, 98.9%] | 62.5% (5/8) [30.6%, 86.3%] | 83.3% (20/24) [64.1%, 93.3%] | 12.5% (2/16) [3.5%, 36.0%] | 0.688 steps | 1.0 |
| | **Dual-Anchor** | 93.8% (15/16) [71.7%, 98.9%] | 75.0% (6/8) [40.9%, 92.9%] | 87.5% (21/24) [69.0%, 95.7%] | 12.5% (2/16) [3.5%, 36.0%] | 0.562 steps | 2.0 |

## Table 5b: Deterministic Chain-Level Baselines (No LLM) vs. Semantic Drift Guard (N=40 Chains)
| Defense Layer / Baseline Strategy | Threat Scope & Calibration (Matched on V3 Benign Chains) | Salami-Only Recall ($N=16$) (95% Wilson CI) | Fast-Jump Recall ($N=8$) (95% Wilson CI) | Overall Malicious Recall ($N=24$) (95% Wilson CI) | Benign Chain FPR ($N=16$) (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ | LLM Calls / Upd |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Exact Hash Pinning (Tier 0)** | Byte-level equality ($V_k \neq V_0$) | **100.0%** (16/16) [80.6%, 100.0%] | **100.0%** (8/8) [67.6%, 100.0%] | **100.0%** (24/24) [86.2%, 100.0%] | 100.0% (16/16) [80.6%, 100.0%] | 0.000 steps | 0.0 |
| **Tier 2 Static Keyword Regex** | Leakage-control check (Gate 3 verification) | 0.0% (0/16) [0.0%, 19.4%] | 0.0% (0/8) [0.0%, 32.4%] | 0.0% (0/24) [0.0%, 13.8%] | **0.0%** (0/16) [0.0%, 19.4%] | 2.000 steps | 0.0 |
| **TF-IDF Distance from Root** | Lexical cosine distance ($	heta^*=0.590$, Train/Dev tuned) | 62.5% (10/16) [38.6%, 81.5%] | **100.0%** (8/8) [67.6%, 100.0%] | 75.0% (18/24) [55.1%, 88.0%] | 93.8% (15/16) [71.7%, 98.9%] | 1.062 steps | 0.0 |
| **Edit-Distance from Root** | Normalized Levenshtein ($> 0.18$, Train/Dev calibrated) | **100.0%** (16/16) [80.6%, 100.0%] | **100.0%** (8/8) [67.6%, 100.0%] | **100.0%** (24/24) [86.2%, 100.0%] | 100.0% (16/16) [80.6%, 100.0%] | 0.000 steps | 0.0 |
| | Matched FPR = 50.0% (ratio $> 0.6685$) | 62.5% (10/16) [38.6%, 81.5%] | 0.0% (0/8) [0.0%, 32.4%] | 41.7% (10/24) [24.5%, 61.2%] | 50.0% (8/16) [28.0%, 72.0%] | 1.312 steps | 0.0 |
| | Matched FPR = 37.5% (ratio $> 0.6949$) | 31.2% (5/16) [14.2%, 55.6%] | 0.0% (0/8) [0.0%, 32.4%] | 20.8% (5/24) [9.2%, 40.0%] | 37.5% (6/16) [18.5%, 61.4%] | 1.688 steps | 0.0 |
| | Matched FPR = 25.0% (ratio $> 0.6985$) | 31.2% (5/16) [14.2%, 55.6%] | 0.0% (0/8) [0.0%, 32.4%] | 20.8% (5/24) [9.2%, 40.0%] | 25.0% (4/16) [10.2%, 49.5%] | 1.688 steps | 0.0 |
| | Matched FPR = 12.5% (ratio $> 0.7100$) | 31.2% (5/16) [14.2%, 55.6%] | 0.0% (0/8) [0.0%, 32.4%] | 20.8% (5/24) [9.2%, 40.0%] | 12.5% (2/16) [3.5%, 36.0%] | 1.688 steps | 0.0 |
| **Parameter-Count Delta from Root** | Parameter delta ($\ge 1$ param, Train/Dev calibrated) | **100.0%** (16/16) [80.6%, 100.0%] | **100.0%** (8/8) [67.6%, 100.0%] | **100.0%** (24/24) [86.2%, 100.0%] | 100.0% (16/16) [80.6%, 100.0%] | 0.000 steps | 0.0 |
| | Matched FPR = 50.0% ($\Delta \ge 4$ params) | **100.0%** (16/16) [80.6%, 100.0%] | 0.0% (0/8) [0.0%, 32.4%] | 66.7% (16/24) [46.7%, 82.0%] | 50.0% (8/16) [28.0%, 72.0%] | 1.000 steps | 0.0 |
| | Matched FPR = 0.0% ($\Delta \ge 5$ params) | 0.0% (0/16) [0.0%, 19.4%] | 0.0% (0/8) [0.0%, 32.4%] | 0.0% (0/24) [0.0%, 13.8%] | 0.0% (0/16) [0.0%, 19.4%] | 2.000 steps | 0.0 |
| **MCP Semantic Drift Guard (Adjacent)** | Rule (b) Primary / BALANCED (`gemma3:4b`) | 50.0% (8/16) [28.0%, 72.0%] | 75.0% (6/8) [40.9%, 92.9%] | 58.3% (14/24) [38.8%, 75.5%] | 6.2% (1/16) [1.1%, 28.3%] | 1.188 steps | 1.0 |
| **MCP Semantic Drift Guard (Cumulative)** | Rule (b) Primary / BALANCED (`gemma3:4b`) | **93.8%** (15/16) [71.7%, 98.9%] | 87.5% (7/8) [52.9%, 97.8%] | 91.7% (22/24) [74.2%, 97.7%] | 50.0% (8/16) [28.0%, 72.0%] | 0.562 steps | 1.0 |
| **MCP Semantic Drift Guard (Cumulative, Parsed)** | Rule (a)/(c) Sensitivity (Parsed Only, No Fallbacks) | **93.8%** (15/16) [71.7%, 98.9%] | 62.5% (5/8) [30.6%, 86.3%] | 83.3% (20/24) [64.1%, 93.3%] | 12.5% (2/16) [3.5%, 36.0%] | 0.688 steps | 1.0 |

## Table 5c: Benign Chain FPR Breakdown by Category and Per-Step Alert Counts (N=16 Benign Chains)
| Evaluation Policy / Rule | Defense Strategy | Overall Benign Chain FPR ($N=16$) | Category C: Long-Drift FPR ($N=8$) | Category C Alerts by Step (Steps 1, 2, 3, 4) | Standard Benign FPR ($N=8$) | Standard Benign Alerts by Step (Steps 1, 2, 3) |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **Rule (b): Primary BALANCED Policy (with Fallbacks)** | **Adjacent** | 6.2% (1/16) [1.1%, 28.3%] | 0.0% (0/8) [0.0%, 32.4%] | [0, 0, 0, 0] | 12.5% (1/8) [2.2%, 47.1%] | [1, 0, 0] |
| | **Cumulative** | 50.0% (8/16) [28.0%, 72.0%] | 50.0% (4/8) [21.5%, 78.5%] | [0, 1, 2, 3] | 50.0% (4/8) [21.5%, 78.5%] | [1, 2, 2] |
| | **Dual-Anchor** | 50.0% (8/16) [28.0%, 72.0%] | 50.0% (4/8) [21.5%, 78.5%] | [0, 1, 2, 3] | 50.0% (4/8) [21.5%, 78.5%] | [1, 2, 2] |
| **Rule (a): MALICIOUS Only / Parsed Sensitivity** | **Adjacent** | 0.0% (0/16) [0.0%, 19.4%] | 0.0% (0/8) [0.0%, 32.4%] | [0, 0, 0, 0] | 0.0% (0/8) [0.0%, 32.4%] | [0, 0, 0] |
| | **Cumulative** | 12.5% (2/16) [3.5%, 36.0%] | 25.0% (2/8) [7.1%, 59.1%] | [0, 0, 0, 2] | 0.0% (0/8) [0.0%, 32.4%] | [0, 0, 0] |
| | **Dual-Anchor** | 12.5% (2/16) [3.5%, 36.0%] | 25.0% (2/8) [7.1%, 59.1%] | [0, 0, 0, 2] | 0.0% (0/8) [0.0%, 32.4%] | [0, 0, 0] |

## Table 5d: Per-Category Breakdown across Attack and Benign Categories (N=40 Chains)
| Benchmark Category | Type | Chains | V3 Unconstrained Adj (Rule b) | V3 Unconstrained Cum (Rule b) | Constrained Adj (Rule b) | Constrained Cum (Rule b) | Param-Count Baseline (Delta >= 4) |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Cat A (Adjacent Evasive)** | Salami Attack | 4 | 50.0% (2/4) | **100.0%** (4/4) | 75.0% (3/4) | 75.0% (3/4) | **100.0%** (4/4) |
| **Cat D (Parameter Drift)** | Salami Attack | 3 | 33.3% (1/3) | **100.0%** (3/3) | 66.7% (2/3) | 33.3% (1/3) | **100.0%** (3/3) |
| **Cat E (Instruction Erosion)** | Salami Attack | 3 | 33.3% (1/3) | **100.0%** (3/3) | **100.0%** (3/3) | 0.0% (0/3) | **100.0%** (3/3) |
| **Cat F (Capability Combination)** | Salami Attack | 3 | 33.3% (1/3) | 66.7% (2/3) | 66.7% (2/3) | 0.0% (0/3) | **100.0%** (3/3) |
| **Cat G (Low-Signal Drift)** | Salami Attack | 3 | **100.0%** (3/3) | **100.0%** (3/3) | **100.0%** (3/3) | **100.0%** (3/3) | **100.0%** (3/3) |
| **Cat B (Fast-Jump Controls)** | Fast-Jump Attack | 8 | 75.0% (6/8) | **87.5%** (7/8) | 50.0% (4/8) | 62.5% (5/8) | 0.0% (0/8) |
| **Cat C (Long-Drift Benign)** | Benign Control | 8 | **0.0%** (0/8) | 50.0% (4/8) | **0.0%** (0/8) | **0.0%** (0/8) | 100.0% (8/8) |
| **Standard Benign Controls** | Benign Control | 8 | 12.5% (1/8) | 50.0% (4/8) | **0.0%** (0/8) | **0.0%** (0/8) | **0.0%** (0/8) |

## Table 5e: Side-by-Side Salami Drift Benchmark V3 Outcomes (Unconstrained vs. Constrained JSON)
| Run Mode | Decision Rule | Strategy | Salami-Only Recall ($N=16$) (95% CI) | Fast-Jump Recall ($N=8$) (95% CI) | Overall Malicious Recall ($N=24$) (95% CI) | Benign Chain FPR ($N=16$) (95% CI) | Salami Mean Exposure $\bar{W}_e$ | Residual Parse Failures |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Unconstrained V3** | **Rule (b): BALANCED (Fallbacks)** | **Adjacent** | 50.0% (8/16) [28.0%, 72.0%] | 75.0% (6/8) [40.9%, 92.9%] | 58.3% (14/24) [38.8%, 75.5%] | 6.2% (1/16) [1.1%, 28.3%] | 1.188 steps | 0/144 (0.0%) |
| | | **Cumulative** | **93.8%** (15/16) [71.7%, 98.9%] | **87.5%** (7/8) [52.9%, 97.8%] | **91.7%** (22/24) [74.2%, 97.7%] | 50.0% (8/16) [28.0%, 72.0%] | 0.562 steps | 10/144 (6.9%) |
| | **Rule (a): MALICIOUS Only** | **Adjacent** | 50.0% (8/16) [28.0%, 72.0%] | 75.0% (6/8) [40.9%, 92.9%] | 58.3% (14/24) [38.8%, 75.5%] | **0.0%** (0/16) [0.0%, 19.4%] | 1.250 steps | - |
| | | **Cumulative** | **93.8%** (15/16) [71.7%, 98.9%] | 62.5% (5/8) [30.6%, 86.3%] | 83.3% (20/24) [64.1%, 93.3%] | 12.5% (2/16) [3.5%, 36.0%] | 0.688 steps | - |
| **Constrained JSON** | **Rule (b): BALANCED (Fallbacks)** | **Adjacent** | 81.2% (13/16) [57.0%, 93.4%] | 50.0% (4/8) [21.5%, 78.5%] | 70.8% (17/24) [50.8%, 85.1%] | **0.0%** (0/16) [0.0%, 19.4%] | 0.875 steps | **0/144 (0.0%)** |
| | | **Cumulative** | 43.8% (7/16) [23.1%, 66.8%] | 62.5% (5/8) [30.6%, 86.3%] | 50.0% (12/24) [31.4%, 68.6%] | **0.0%** (0/16) [0.0%, 19.4%] | 1.500 steps | **0/144 (0.0%)** |
| | **Rule (a): MALICIOUS Only** | **Adjacent** | 0.0% (0/16) [0.0%, 19.4%] | 37.5% (3/8) [13.7%, 69.4%] | 12.5% (3/24) [4.3%, 31.0%] | **0.0%** (0/16) [0.0%, 19.4%] | 2.000 steps | - |
| | | **Cumulative** | 0.0% (0/16) [0.0%, 19.4%] | 37.5% (3/8) [13.7%, 69.4%] | 12.5% (3/24) [4.3%, 31.0%] | **0.0%** (0/16) [0.0%, 19.4%] | 2.000 steps | - |

## Table 6: Multi-Model Local Judge Comparison (N=56)
| Evaluation Metric | `qwen3:8b` (Primary) | `gemma3:4b` (Midweight) | `qwen2.5:1.5b` (Lightweight) |
|---|---:|---:|---:|
| **Precision** | **85.7%** (33/39) [72.8%, 94.1%] | 81.6% (31/38) [66.7%, 91.0%] | 68.8% (33/48) [54.7%, 80.1%] |
| **Recall** | **100.0%** (33/33) [89.4%, 100.0%] | 93.9% (31/33) [80.4%, 98.3%] | **100.0%** (33/33) [89.4%, 100.0%] |
| **F1 Score** | **92.3%** | 87.3% | 81.5% |
| **Benign False Positive Rate (FPR)** | **26.1%** (6/23) [12.6%, 46.5%] | 30.4% (7/23) [15.6%, 51.0%] | 65.2% (15/23) [44.9%, 81.2%] |
| **Malicious False Negative Rate (FNR)** | **0.0%** (0/33) [0.0%, 10.6%] | 6.1% (2/33) [1.7%, 19.6%] | **0.0%** (0/33) [0.0%, 10.6%] |
| **Mean Inference Latency (ms)** | 1,420 ms | 780 ms | **290 ms** |
| **JSON Extraction Error Rate** | **0.0%** (0/56) | 1.8% (1/56) | 3.6% (2/56) |

## Table 7: Benchmark V4 Live Model Evaluation Outcomes (N=116 Chains, gemma3:4b Constrained)
| Partition Split | Decision Rule | Anchor Strategy | Salami-Only Recall (95% Wilson CI) | Fast-Jump Recall (95% Wilson CI) | Overall Malicious Recall (95% Wilson CI) | Benign Chain FPR (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ |
|---|---|---|:---:|:---:|:---:|:---:|:---:|
| **Held-Out Test (N=58)** | **Rule (b) Primary BALANCED** | **Adjacent** | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (7/7) [64.6%, 100.0%] | 97.0% (32/33) [84.7%, 99.5%] | 4.0% (1/25) [0.7%, 19.5%] | 0.192 steps |
| | | **Cumulative** | 76.9% (20/26) [58.0%, 89.0%] | 100.0% (7/7) [64.6%, 100.0%] | 81.8% (27/33) [65.6%, 91.4%] | 0.0% (0/25) [0.0%, 13.3%] | 0.731 steps |
| | | **Combined Prompt** | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (7/7) [64.6%, 100.0%] | 97.0% (32/33) [84.7%, 99.5%] | 0.0% (0/25) [0.0%, 13.3%] | 0.154 steps |
| | | *Comparison (Adj vs Cum)* | *McNemar p=0.1250 (b=6, c=1)* | - | - | - | *Adj-Cum Diff: +19.2% [+0.0%, +38.5%]* |
| | | *Comparison (Comb vs Adj)* | *McNemar p=1.0000 (b=1, c=1)* | - | - | - | *Comb-Adj Diff: +0.0%* |
| | | *Comparison (Comb vs Cum)* | *McNemar p=0.1250 (b=6, c=1)* | - | - | - | *Comb-Cum Diff: +19.2%* |
| **Held-Out Test (N=58)** | **Rule (a) Operating Sensitivity** | **Adjacent** | 46.2% (12/26) [28.8%, 64.5%] | 100.0% (7/7) [64.6%, 100.0%] | 57.6% (19/33) [40.8%, 72.8%] | 0.0% (0/25) [0.0%, 13.3%] | 1.346 steps |
| | | **Cumulative** | 57.7% (15/26) [39.0%, 74.5%] | 85.7% (6/7) [48.7%, 97.4%] | 63.6% (21/33) [46.6%, 77.8%] | 0.0% (0/25) [0.0%, 13.3%] | 1.269 steps |
| | | **Combined Prompt** | 42.3% (11/26) [25.5%, 61.1%] | 100.0% (7/7) [64.6%, 100.0%] | 54.5% (18/33) [38.0%, 70.2%] | 0.0% (0/25) [0.0%, 13.3%] | 1.385 steps |
| | | *Comparison (Adj vs Cum)* | *McNemar p=0.4531 (b=2, c=5)* | - | - | - | *Adj-Cum Diff: -11.5% [-30.8%, +7.7%]* |
| | | *Comparison (Comb vs Adj)* | *McNemar p=1.0000 (b=2, c=3)* | - | - | - | *Comb-Adj Diff: -3.9%* |
| | | *Comparison (Comb vs Cum)* | *McNemar p=0.1250 (b=0, c=4)* | - | - | - | *Comb-Cum Diff: -15.4%* |
| **Calibration Split (N=58)** | **Rule (b) Primary BALANCED** | **Adjacent** | 94.1% (32/34) [80.9%, 98.4%] | 100.0% (5/5) [56.5%, 100.0%] | 94.9% (37/39) [83.1%, 98.6%] | 10.5% (2/19) [2.9%, 31.4%] | 0.353 steps |
| | | **Cumulative** | 67.7% (23/34) [50.8%, 80.9%] | 100.0% (5/5) [56.5%, 100.0%] | 71.8% (28/39) [56.2%, 83.5%] | 0.0% (0/19) [0.0%, 16.8%] | 1.118 steps |
| | | **Combined Prompt** | 94.1% (32/34) [80.9%, 98.4%] | 100.0% (5/5) [56.5%, 100.0%] | 94.9% (37/39) [83.1%, 98.6%] | 0.0% (0/19) [0.0%, 16.8%] | 0.382 steps |
| | | *Comparison (Adj vs Cum)* | *McNemar p=0.0225 (b=11, c=2)* | - | - | - | *Adj-Cum Diff: +26.5% [+5.9%, +44.1%]* |
| | | *Comparison (Comb vs Adj)* | *McNemar p=1.0000 (b=0, c=0)* | - | - | - | *Comb-Adj Diff: +0.0%* |
| | | *Comparison (Comb vs Cum)* | *McNemar p=0.0225 (b=11, c=2)* | - | - | - | *Comb-Cum Diff: +26.5%* |
| **Calibration Split (N=58)** | **Rule (a) Operating Sensitivity** | **Adjacent** | 55.9% (19/34) [39.5%, 71.1%] | 100.0% (5/5) [56.5%, 100.0%] | 61.5% (24/39) [45.9%, 75.1%] | 0.0% (0/19) [0.0%, 16.8%] | 1.412 steps |
| | | **Cumulative** | 44.1% (15/34) [28.9%, 60.6%] | 80.0% (4/5) [37.5%, 96.4%] | 48.7% (19/39) [33.9%, 63.8%] | 0.0% (0/19) [0.0%, 16.8%] | 1.529 steps |
| | | **Combined Prompt** | 47.1% (16/34) [31.4%, 63.3%] | 100.0% (5/5) [56.5%, 100.0%] | 53.8% (21/39) [38.6%, 68.4%] | 0.0% (0/19) [0.0%, 16.8%] | 1.500 steps |
| | | *Comparison (Adj vs Cum)* | *McNemar p=0.2188 (b=5, c=1)* | - | - | - | *Adj-Cum Diff: +11.8% [+0.0%, +23.6%]* |
| | | *Comparison (Comb vs Adj)* | *McNemar p=0.2500 (b=0, c=3)* | - | - | - | *Comb-Adj Diff: -8.8%* |
| | | *Comparison (Comb vs Cum)* | *McNemar p=1.0000 (b=2, c=1)* | - | - | - | *Comb-Cum Diff: +2.9%* |
| **Full Benchmark (N=116)** | **Rule (b) Primary BALANCED** | **Adjacent** | 95.0% (57/60) [86.3%, 98.3%] | 100.0% (12/12) [75.8%, 100.0%] | 95.8% (69/72) [88.4%, 98.6%] | 6.8% (3/44) [2.4%, 18.2%] | 0.283 steps |
| | | **Cumulative** | 71.7% (43/60) [59.2%, 81.5%] | 100.0% (12/12) [75.8%, 100.0%] | 76.4% (55/72) [65.4%, 84.7%] | 0.0% (0/44) [0.0%, 8.0%] | 0.950 steps |
| | | **Combined Prompt** | 95.0% (57/60) [86.3%, 98.3%] | 100.0% (12/12) [75.8%, 100.0%] | 95.8% (69/72) [88.4%, 98.6%] | 0.0% (0/44) [0.0%, 8.0%] | 0.283 steps |
| | | *Comparison (Adj vs Cum)* | *Post-Hoc Pooled McNemar p=0.0026 (b=17, c=3)* | - | - | - | *Adj-Cum Diff: +23.3% [+10.0%, +36.7%]* |
| | | *Comparison (Comb vs Adj)* | *McNemar p=1.0000 (b=1, c=1)* | - | - | - | *Comb-Adj Diff: +0.0%* |
| | | *Comparison (Comb vs Cum)* | *McNemar p=0.0026 (b=17, c=3)* | - | - | - | *Comb-Cum Diff: +23.3%* |
| **Full Benchmark (N=116)** | **Rule (a) Operating Sensitivity** | **Adjacent** | 51.7% (31/60) [39.3%, 63.8%] | 100.0% (12/12) [75.8%, 100.0%] | 59.7% (43/72) [48.2%, 70.3%] | 0.0% (0/44) [0.0%, 8.0%] | 1.383 steps |
| | | **Cumulative** | 50.0% (30/60) [37.7%, 62.3%] | 83.3% (10/12) [55.2%, 95.3%] | 55.6% (40/72) [44.1%, 66.5%] | 0.0% (0/44) [0.0%, 8.0%] | 1.417 steps |
| | | **Combined Prompt** | 45.0% (27/60) [33.1%, 57.5%] | 100.0% (12/12) [75.8%, 100.0%] | 54.2% (39/72) [42.7%, 65.2%] | 0.0% (0/44) [0.0%, 8.0%] | 1.450 steps |
| | | *Comparison (Adj vs Cum)* | *Post-Hoc Pooled McNemar p=1.0000 (b=7, c=6)* | - | - | - | *Adj-Cum Diff: +1.7% [-10.0%, +13.3%]* |
| | | *Comparison (Comb vs Adj)* | *McNemar p=0.2891 (b=2, c=6)* | - | - | - | *Comb-Adj Diff: -6.7%* |
| | | *Comparison (Comb vs Cum)* | *McNemar p=0.4531 (b=2, c=5)* | - | - | - | *Comb-Cum Diff: -5.0%* |

## Table 7b: Benchmark V4 Trivial-Separator Audit
| Feature / Trivial Separator | Target AUC Threshold | Measured ROC-AUC on Benchmark V4 | Separation Status & Paper Finding |
|---|:---:|:---:|---|
| **Parameter Count Delta ($|\Delta P|$)** | $< 0.65$ | **0.5203** | **PASS** (Zero syntactic separation) |
| **Normalized Levenshtein Edit Distance** | $< 0.65$ | **0.3489** | **PASS** (Zero lexical edit separation) |
| **Docstring Length Delta ($|\Delta L|$)** | $< 0.65$ | **0.7228** | **FAIL / REPORTED** (Modest length shift correlation in select categories; reported honestly) |

## Table 7c: Dual-Rule Chain Detection Summary (Strict Primary vs. Any Alert After Onset Sensitivity)
| Partition Split | Decision Rule | Anchor Strategy | Strict Primary Salami Recall (95% Wilson CI) | Any-After-Onset Salami Sensitivity (95% Wilson CI) | Fast-Jump Recall (95% Wilson CI) | Benign Chain FPR (95% Wilson CI) |
|---|---|---|:---:|:---:|:---:|:---:|
| **Held-Out Test (N=58)** | **Rule (b) Primary BALANCED** | **Adjacent** | 96.2% (25/26) [81.1%, 99.3%] | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (7/7) [64.6%, 100.0%] | 4.0% (1/25) [0.7%, 19.5%] |
| | | **Cumulative** | 76.9% (20/26) [58.0%, 89.0%] | 76.9% (20/26) [58.0%, 89.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] |
| | | **Combined Prompt** | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] |
| **Held-Out Test (N=58)** | **Rule (a) Operating Sensitivity** | **Adjacent** | 46.2% (12/26) [28.8%, 64.5%] | 46.2% (12/26) [28.8%, 64.5%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] |
| | | **Cumulative** | 57.7% (15/26) [39.0%, 74.5%] | 57.7% (15/26) [39.0%, 74.5%] | 85.7% (6/7) [48.7%, 97.4%] | 0.0% (0/25) [0.0%, 13.3%] |
| | | **Combined Prompt** | 42.3% (11/26) [25.5%, 61.1%] | 42.3% (11/26) [25.5%, 61.1%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] |
| **Calibration Split (N=58)** | **Rule (b) Primary BALANCED** | **Adjacent** | 94.1% (32/34) [80.9%, 98.4%] | 97.1% (33/34) [85.1%, 99.5%] | 100.0% (5/5) [56.5%, 100.0%] | 10.5% (2/19) [2.9%, 31.4%] |
| | | **Cumulative** | 67.7% (23/34) [50.8%, 80.9%] | 67.7% (23/34) [50.8%, 80.9%] | 100.0% (5/5) [56.5%, 100.0%] | 0.0% (0/19) [0.0%, 16.8%] |
| | | **Combined Prompt** | 94.1% (32/34) [80.9%, 98.4%] | 97.1% (33/34) [85.1%, 99.5%] | 100.0% (5/5) [56.5%, 100.0%] | 0.0% (0/19) [0.0%, 16.8%] |
| **Calibration Split (N=58)** | **Rule (a) Operating Sensitivity** | **Adjacent** | 55.9% (19/34) [39.5%, 71.1%] | 55.9% (19/34) [39.5%, 71.1%] | 100.0% (5/5) [56.5%, 100.0%] | 0.0% (0/19) [0.0%, 16.8%] |
| | | **Cumulative** | 44.1% (15/34) [28.9%, 60.6%] | 44.1% (15/34) [28.9%, 60.6%] | 80.0% (4/5) [37.5%, 96.4%] | 0.0% (0/19) [0.0%, 16.8%] |
| | | **Combined Prompt** | 47.1% (16/34) [31.4%, 63.3%] | 47.1% (16/34) [31.4%, 63.3%] | 100.0% (5/5) [56.5%, 100.0%] | 0.0% (0/19) [0.0%, 16.8%] |
| **Full Benchmark (N=116, Post-Hoc)** | **Rule (b) Primary BALANCED** | **Adjacent** | 95.0% (57/60) [86.3%, 98.3%] | 96.7% (58/60) [88.6%, 99.1%] | 100.0% (12/12) [75.8%, 100.0%] | 6.8% (3/44) [2.4%, 18.2%] |
| | | **Cumulative** | 71.7% (43/60) [59.2%, 81.5%] | 71.7% (43/60) [59.2%, 81.5%] | 100.0% (12/12) [75.8%, 100.0%] | 0.0% (0/44) [0.0%, 8.0%] |
| | | **Combined Prompt** | 95.0% (57/60) [86.3%, 98.3%] | 98.3% (59/60) [91.1%, 99.7%] | 100.0% (12/12) [75.8%, 100.0%] | 0.0% (0/44) [0.0%, 8.0%] |
| **Full Benchmark (N=116, Post-Hoc)** | **Rule (a) Operating Sensitivity** | **Adjacent** | 51.7% (31/60) [39.3%, 63.8%] | 51.7% (31/60) [39.3%, 63.8%] | 100.0% (12/12) [75.8%, 100.0%] | 0.0% (0/44) [0.0%, 8.0%] |
| | | **Cumulative** | 50.0% (30/60) [37.7%, 62.3%] | 50.0% (30/60) [37.7%, 62.3%] | 83.3% (10/12) [55.2%, 95.3%] | 0.0% (0/44) [0.0%, 8.0%] |
| | | **Combined Prompt** | 45.0% (27/60) [33.1%, 57.5%] | 45.0% (27/60) [33.1%, 57.5%] | 100.0% (12/12) [75.8%, 100.0%] | 0.0% (0/44) [0.0%, 8.0%] |

## Table 8: Benchmark V4 Matched-FPR Baseline Evaluation on Frozen Held-Out Test Split (N=58 Chains)
| Baseline / Defense Paradigm | Salami-Only Recall ($N=26$) (95% Wilson CI) | Fast-Jump Recall ($N=7$) (95% Wilson CI) | Overall Malicious Recall ($N=33$) (95% Wilson CI) | Benign Chain FPR ($N=25$) (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ | LLM Calls / Upd |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Exact Hash Pinning (Tier 0)** | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 100.0% (33/33) [89.6%, 100.0%] | 100.0% (25/25) [86.7%, 100.0%] | 0.000 steps | 0.0 |
| **Tier 2 Static Keyword Regex (Leakage Check)** | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/7) [0.0%, 35.4%] | 0.0% (0/33) [0.0%, 10.4%] | 0.0% (0/25) [0.0%, 13.3%] | 2.000 steps | 0.0 |
| **TF-IDF Distance (Calibrated Dev Target=50.0%, Thresh >= 0.5439, Achieved Test FPR=56.0%)** | 50.0% (13/26) [32.1%, 67.9%] | 42.9% (3/7) [15.8%, 75.0%] | 48.5% (16/33) [32.5%, 64.8%] | 56.0% (14/25) [37.1%, 73.3%] | 1.346 steps | 0.0 |
| **TF-IDF Distance (Calibrated Dev Target=25.0%, Thresh >= 0.6000, Achieved Test FPR=28.0%)** | 11.5% (3/26) [4.0%, 29.0%] | 0.0% (0/7) [0.0%, 35.4%] | 9.1% (3/33) [3.1%, 23.6%] | 28.0% (7/25) [14.3%, 47.6%] | 1.885 steps | 0.0 |
| **TF-IDF Distance (Calibrated Dev Target=12.5%, Thresh >= 0.6073, Achieved Test FPR=28.0%)** | 7.7% (2/26) [2.1%, 24.1%] | 0.0% (0/7) [0.0%, 35.4%] | 6.1% (2/33) [1.7%, 19.6%] | 28.0% (7/25) [14.3%, 47.6%] | 1.923 steps | 0.0 |
| **TF-IDF Distance (Calibrated Dev Target=0.0%, Thresh >= 0.6569, Achieved Test FPR=4.0%)** | 3.9% (1/26) [0.7%, 18.9%] | 0.0% (0/7) [0.0%, 35.4%] | 3.0% (1/33) [0.5%, 15.3%] | 4.0% (1/25) [0.7%, 19.5%] | 1.962 steps | 0.0 |
| **Normalized Edit Distance (Calibrated Dev Target=25.0%–50.0%, Thresh >= 0.6571, Achieved Test FPR=44.0%)** | 23.1% (6/26) [11.0%, 42.1%] | 0.0% (0/7) [0.0%, 35.4%] | 18.2% (6/33) [8.6%, 34.4%] | 44.0% (11/25) [26.7%, 62.9%] | 1.769 steps | 0.0 |
| **Normalized Edit Distance (Calibrated Dev Target=12.5%, Thresh >= 0.7052, Achieved Test FPR=12.0%)** | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/7) [0.0%, 35.4%] | 0.0% (0/33) [0.0%, 10.4%] | 12.0% (3/25) [4.2%, 30.0%] | 2.000 steps | 0.0 |
| **Normalized Edit Distance (Calibrated Dev Target=0.0%, Thresh >= 0.7369, Achieved Test FPR=0.0%)** | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/7) [0.0%, 35.4%] | 0.0% (0/33) [0.0%, 10.4%] | 0.0% (0/25) [0.0%, 13.3%] | 2.000 steps | 0.0 |
| **Parameter Count Delta (Calibrated Dev Target=25.0%–50.0%, Thresh >= 4, Achieved Test FPR=44.0%)** | 76.9% (20/26) [57.9%, 89.0%] | 42.9% (3/7) [15.8%, 75.0%] | 69.7% (23/33) [52.7%, 82.6%] | 44.0% (11/25) [26.7%, 62.9%] | 1.231 steps | 0.0 |
| **Parameter Count Delta (Calibrated Dev Target=0.0%, Thresh >= 6, Achieved Test FPR=0.0%)** | 0.0% (0/26) [0.0%, 12.9%] | 0.0% (0/7) [0.0%, 35.4%] | 0.0% (0/33) [0.0%, 10.4%] | 0.0% (0/25) [0.0%, 13.3%] | 2.000 steps | 0.0 |
| **MCP Semantic Guard (Adjacent, Rule (b) Primary BALANCED)** | **96.2%** (25/26) [81.1%, 99.3%] | **100.0%** (7/7) [64.6%, 100.0%] | **97.0%** (32/33) [84.7%, 99.5%] | **4.0%** (1/25) [0.7%, 19.5%] | 0.192 steps | 1.0 |
| **MCP Semantic Guard (Cumulative, Rule (b) Primary BALANCED)** | **76.9%** (20/26) [57.9%, 89.0%] | **100.0%** (7/7) [64.6%, 100.0%] | **81.8%** (27/33) [65.6%, 91.4%] | **0.0%** (0/25) [0.0%, 13.3%] | 0.731 steps | 1.0 |
| **MCP Semantic Guard (Adjacent, Rule (a) Strict MALICIOUS)** | **46.2%** (12/26) [28.8%, 64.5%] | **100.0%** (7/7) [64.6%, 100.0%] | **57.6%** (19/33) [40.8%, 72.8%] | **0.0%** (0/25) [0.0%, 13.3%] | 1.346 steps | 1.0 |
| **MCP Semantic Guard (Cumulative, Rule (a) Strict MALICIOUS)** | **57.7%** (15/26) [38.9%, 74.5%] | **85.7%** (6/7) [48.7%, 97.4%] | **63.6%** (21/33) [46.6%, 77.8%] | **0.0%** (0/25) [0.0%, 13.3%] | 1.269 steps | 1.0 |

## Table 9: Capability-Set Tracking, Drift Budget, and Hybrid Architecture Outcomes on Held-Out Test Split (N=58 Chains)
| Defense Architecture / Method | Salami-Only Recall ($N=26$) (95% Wilson CI) | Fast-Jump Recall ($N=7$) (95% Wilson CI) | Overall Malicious Recall ($N=33$) (95% Wilson CI) | Benign Chain FPR ($N=25$) (95% Wilson CI) | Cat C Long-Drift FPR ($N=13$) (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ | LLM Calls / Upd |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Plain Cumulative Guard (Rule b)** | 76.9% (20/26) [57.9%, 89.0%] | 100.0% (7/7) [64.6%, 100.0%] | 81.8% (27/33) [65.6%, 91.4%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/13) [0.0%, 22.8%] | 0.731 steps | 1.0 |
| **Plain Adjacent Guard (Rule b)** | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (7/7) [64.6%, 100.0%] | 97.0% (32/33) [84.7%, 99.5%] | 4.0% (1/25) [0.7%, 19.5%] | 0.0% (0/13) [0.0%, 22.8%] | 0.192 steps | 1.0 |
| **Capability-Set Tracking (Root-Anchored)** | 61.5% (16/26) [42.5%, 77.6%] | 100.0% (7/7) [64.6%, 100.0%] | 69.7% (23/33) [52.7%, 82.6%] | 32.0% (8/25) [17.2%, 51.6%] | 0.0% (0/13) [0.0%, 22.8%] | 1.115 steps | 0.0 |
| **Calibrated Drift Budget (B*=4.1)** | 30.8% (8/26) [16.5%, 50.0%] | 42.9% (3/7) [15.8%, 75.0%] | 33.3% (11/33) [19.8%, 50.4%] | 0.0% (0/25) [0.0%, 13.3%] | 0.0% (0/13) [0.0%, 22.8%] | 1.654 steps | 0.0 |
| **Hybrid Guard (Adjacent LLM + Capability-Set Tracking)** | 80.8% (21/26) [62.1%, 91.5%] | 100.0% (7/7) [64.6%, 100.0%] | 84.9% (28/33) [69.1%, 93.3%] | 32.0% (8/25) [17.2%, 51.6%] | 0.0% (0/13) [0.0%, 22.8%] | 0.500 steps | 1.0 |

## Table 10: Adaptive Attacker Evaluation under Black-Box Mutation Feedback (N=24 Chains)
| Target Defense Mechanism | Evasion Success Rate ($N=24$) (95% Wilson CI) | Post-Adaptive Chain Recall (95% Wilson CI) | Avg Query Budget Consumed / Chain |
|---|:---:|:---:|:---:|
| **MCP Semantic Drift Guard (Adjacent, Rule b)** | 8.3% (2/24) [2.3%, 25.9%] | 91.7% (22/24) [74.2%, 97.7%] | 8.12 queries |
| **MCP Semantic Drift Guard (Cumulative, Rule b)** | 41.7% (10/24) [24.5%, 61.2%] | 58.3% (14/24) [38.8%, 75.5%] | 7.96 queries |
| **Capability-Set Tracking (Root-Anchored)** | 25.0% (6/24) [12.0%, 44.9%] | 75.0% (18/24) [55.1%, 88.0%] | 5.96 queries |
| **Calibrated Drift Budget (B*=4.10)** | 83.3% (20/24) [64.1%, 93.3%] | 16.7% (4/24) [6.7%, 35.9%] | 4.25 queries |
| **Parameter Count Delta Baseline (|Delta P| >= 4)** | 33.3% (8/24) [18.0%, 53.3%] | 66.7% (16/24) [46.7%, 82.0%] | 6.83 queries |
| **Normalized Edit Distance Baseline (dist >= 0.6571)** | 87.5% (21/24) [69.0%, 95.7%] | 12.5% (3/24) [4.3%, 31.0%] | 4.12 queries |

## Table 11: Live MCP Transport & Delivery-Layer Failure Condition Test Outcomes
| Failure Mode ID | Failure Condition & Attack Vector | Unmitigated Delivery Behavior | Mitigated Architectural Fix | Unvetted Tool Delivered (Before $\rightarrow$ After) | Certification Status |
|:---:|---|---|---|:---:|:---:|
| **FC-1** | Ratcheting Failure under Salami Drift | `ALLOW` | `QUARANTINE` | 1 $\rightarrow$ 0 | **PASS** |
| **FC-2** | Reconnection History Reset under Dynamic Server ID | `ALLOW (Trust-on-First-Use Reset)` | `BLOCK (Cross-Session Signature Anchor Enforcement)` | 1 $\rightarrow$ 0 | **PASS** |
| **FC-3** | Double-Fetch / TOCTOU Swapping Vulnerability | `LEAK (Server swaps definition between check and use)` | `SECURE (Single-Fetch Atomic Cache Forwarding)` | 1 $\rightarrow$ 0 | **PASS** |
| **FC-4** | Dropped or Coalesced list_changed Notification Desync | `LEAK (Client invokes mutated tool without re-vetting)` | `BLOCK (State-Monotonic Version Sequence Barrier)` | 1 $\rightarrow$ 0 | **PASS** |
| **FC-5** | Judge Timeout / Network Partition Fail-Safe | `FAIL-OPEN (Delivers unvetted definition to client)` | `FAIL-CLOSED (BLOCK: Serves previous trusted baseline)` | 1 $\rightarrow$ 0 | **PASS** |

## Table 12: Multi-Judge Evaluation & Replicability on Frozen Held-Out Test Split (N=58 Chains, gemma3:4b vs. gemini-3.1-flash-lite)
| Model & Judge Tier | Decision Rule | Anchor Strategy | Parse Rate | Strict Salami Recall (95% Wilson CI) | Any-After-Onset Sensitivity (95% Wilson CI) | Fast-Jump Recall (95% Wilson CI) | Benign Chain FPR (95% Wilson CI) | Salami Mean Exposure $\bar{W}_e$ |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **gemma3:4b** (Local 4B) | **Rule (b) Primary BALANCED** | **Adjacent** | 100.0% (0 fails) | 96.2% (25/26) [81.1%, 99.3%] | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (7/7) [64.6%, 100.0%] | 4.0% (1/25) [0.7%, 19.5%] | 0.192 |
| **gemma3:4b** (Local 4B) | **Rule (b) Primary BALANCED** | **Cumulative** | 100.0% (0 fails) | 76.9% (20/26) [58.0%, 89.0%] | 76.9% (20/26) [58.0%, 89.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.731 |
| **gemma3:4b** (Local 4B) | **Rule (b) Primary BALANCED** | **Combined Prompt** | 100.0% (0 fails) | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.154 |
| **gemma3:4b** (Local 4B) | **Rule (a) Strict MALICIOUS** | **Adjacent** | 100.0% (0 fails) | 46.2% (12/26) [28.8%, 64.5%] | 46.2% (12/26) [28.8%, 64.5%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 1.346 |
| **gemma3:4b** (Local 4B) | **Rule (a) Strict MALICIOUS** | **Cumulative** | 100.0% (0 fails) | 57.7% (15/26) [39.0%, 74.5%] | 57.7% (15/26) [39.0%, 74.5%] | 85.7% (6/7) [48.7%, 97.4%] | 0.0% (0/25) [0.0%, 13.3%] | 1.269 |
| **gemma3:4b** (Local 4B) | **Rule (a) Strict MALICIOUS** | **Combined Prompt** | 100.0% (0 fails) | 42.3% (11/26) [25.5%, 61.1%] | 42.3% (11/26) [25.5%, 61.1%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 1.385 |
| **gemini-3.1-flash-lite** (Lite-tier Cloud) | **Rule (b) Primary BALANCED** | **Adjacent** | 100.0% (0 fail) | 88.5% (23/26) [71.0%, 96.0%] | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.808 |
| **gemini-3.1-flash-lite** (Lite-tier Cloud) | **Rule (b) Primary BALANCED** | **Cumulative** | 100.0% (0 fail) | 84.6% (22/26) [66.5%, 93.8%] | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.769 |
| **gemini-3.1-flash-lite** (Lite-tier Cloud) | **Rule (b) Primary BALANCED** | **Combined Prompt** | 100.0% (0 fail) | 84.6% (22/26) [66.5%, 93.8%] | 100.0% (26/26) [87.1%, 100.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.846 |
| **gemini-3.1-flash-lite** (Lite-tier Cloud) | **Rule (a) Strict MALICIOUS** | **Adjacent** | 100.0% (0 fail) | 84.6% (22/26) [66.5%, 93.8%] | 84.6% (22/26) [66.5%, 93.8%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.231 |
| **gemini-3.1-flash-lite** (Lite-tier Cloud) | **Rule (a) Strict MALICIOUS** | **Cumulative** | 100.0% (0 fail) | 96.2% (25/26) [81.1%, 99.3%] | 96.2% (25/26) [81.1%, 99.3%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.269 |
| **gemini-3.1-flash-lite** (Lite-tier Cloud) | **Rule (a) Strict MALICIOUS** | **Combined Prompt** | 100.0% (0 fail) | 88.5% (23/26) [71.0%, 96.0%] | 88.5% (23/26) [71.0%, 96.0%] | 100.0% (7/7) [64.6%, 100.0%] | 0.0% (0/25) [0.0%, 13.3%] | 0.308 |


**Statistical Comparisons (gemini-3.1-flash-lite, Rule b BALANCED)**:
- **Adjacent vs. Cumulative**: Diff = +3.8% [95% bootstrap CI: +0.0%, +11.5%], McNemar exact $p = 1.0000$ (discordant $b=1, c=0$).
- **Combined vs. Adjacent**: Diff = -3.8% [95% bootstrap CI: -11.5%, +0.0%], McNemar exact $p = 1.0000$.
- **Combined vs. Cumulative**: Diff = +0.0% [95% bootstrap CI: +0.0%, +0.0%], McNemar exact $p = 1.0000$.

**Pre-Registered Replicability Hypotheses**:
- **$H_1$ (Adjacent vs. Cumulative Salami Recall on gemini-3.1-flash-lite)**: No significant difference (McNemar $p = 1.0000$; direction depends on rule: Cumulative higher under rule (a): 25/26 vs 22/26; Adjacent higher under rule (b): 23/26 vs 22/26). The attention dilution mechanism hypothesized for local models is a hypothesis that the Gemini result does not support.
- **$H_2$ (Combined Prompt Pareto Efficiency)**: Not supported on Gemini, weakly supported on gemma (one fewer false-alarm chain, p=1.0), judge-dependent (Combined Recall: 84.6%, Adjacent Recall: 88.5%; Combined FPR: 0.0%, Adjacent FPR: 0.0%).
