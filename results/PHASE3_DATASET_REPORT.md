# Phase 3 — Semantic Drift Judge Dataset Report

## 1. Executive Summary

The Phase 3 Semantic Drift Dataset is specifically designed to benchmark methods for differentiating legitimate software updates from malicious tool poisoning in Model Context Protocol (MCP) tool contracts.

The dataset integrates:
1. **Real-world Negatives**: Authentic before/after tool evolution pairs collected from open-source MCP repositories in Phase 2.
2. **MCPTox Positives**: Poisoned tool contracts spanning 3 distinct attack paradigms and 5 mutation categories derived from the official MCPTox benchmark.
3. **Hard Negatives**: Benign updates containing strict imperative language, security warnings, authentication constraints, or path restrictions to test against naive keyword over-triggering.

---

## 2. Dataset Overview & Split Statistics

| Dataset Split | Total Examples | Benign Examples | Malicious Examples | Proportion |
|---|---:|---:|---:|---:|
| **Train Set (`drift_train.jsonl`)** | 259 | 114 | 145 | 70.0% |
| **Dev Set (`drift_dev.jsonl`)** | 55 | 28 | 27 | 14.9% |
| **Test Set (`drift_test.jsonl`)** | 56 | 28 | 28 | 15.1% |
| **Full Master Dataset** | **370** | **170** | **200** | **100.0%** |

---

## 3. Data Sources Distribution

| Data Source | Count | Proportion | Expected Label |
|---|---:|---:|---|
| **Real Open-Source Updates (Phase 2)** | 123 | 33.2% | `BENIGN` |
| **MCPTox Poisoned Tool Injections** | 200 | 54.1% | `MALICIOUS` |
| **Hard Negative Security Constraints** | 47 | 12.7% | `BENIGN` |
| **Total** | **370** | **100.0%** | |

---

## 4. Poisoned Attack Distributions (Malicious Positive Set)

### 4.1 MCPTox Attack Paradigms
| Paradigm | Count | Description |
|---|---:|---|
| **Prerequisite Attack** | 200 | Forces mandatory pre-execution of unauthorized tools |
| **Direct Injection** | 0 | Directly embeds prompt injection payloads into docstrings |
| **Argument Tampering** | 0 | Commands the model to silently alter user parameters to sensitive targets |

### 4.2 Mutation Categories
| Mutation Category | Count | Mechanism |
|---|---:|---|
| `appended_malicious_instruction` | 120 | Appends attack sentence to clean docstring |
| `rewritten_malicious_description` | 0 | Completely replaces tool description with poisoned text |
| `prerequisite_manipulation` | 80 | Injects prerequisite dependency command |
| `argument_manipulation` | 0 | Injects redirection / tampering instructions |
| `subtle_semantic_paraphrase` | 0 | Uses natural security-auditing justifications for malicious intent |

### 4.3 Security Risk Categories
| Risk Category | Count | Percentage |
|---|---:|---:|
| **Credential Leakage** | 200 | 100.0% |

---

## 5. Leakage Prevention Strategy

To ensure valid generalization, splitting is performed using **Cluster-Based Partitioning (`cluster_id`)**:
- All mutations and transitions for a given `server_id + tool_name` are kept entirely within a single split (Train, Dev, or Test).
- No underlying tool definition appearing in the Test set was exposed during training or development policy selection.
- Random seed `42` is recorded for 100% deterministic reproducibility.

---

## 6. Dataset Limitations

1. **Benchmark Grounding**: Positive attacks originate from the published MCPTox benchmark; future phases will evaluate adaptive, evading adversaries.
2. **Language Coverage**: Real updates primarily cover TypeScript and Python MCP implementations.
3. **Imbalance**: Dataset maintains balanced representation between legitimate software evolution (123 real updates + 35 hard negatives = 158 benign) and poisoned attacks (200 instances).
