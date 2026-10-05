# Reproducibility Specification: Reviewer Upgrade Package

This document provides exhaustive reproducible specifications for all code, models, datasets, prompts, rules, and evaluations used in this research.

---

## 1. Environment & Software Dependencies

- **Operating System**: Microsoft Windows 11 Enterprise (x86_64)
- **Python Version**: Python 3.12.3 / 3.11.x
- **Inference Runtime**: Ollama (llama.cpp engine, HTTP API on `localhost:11434`)
- **Key Python Packages**:
  - `scikit-learn` >= 1.4.0 (TF-IDF Vectorization & Cosine Metrics)
  - `numpy` >= 1.26.0 (Binomial interval & statistical calculations)
  - `sqlite3` (Built-in standard library for persistent state store)
  - `urllib.request` (Standard library HTTP client with socket timeout)

---

## 2. Model Specifications & Quantization

| Role | Model Identifier | Architecture | Parameters | Quantization | Context Window | Checksum / Digest |
|---|---|---|---|---|---|---|
| **Primary Semantic Judge** | `qwen3:8b` | Qwen3-Instruct | 8.2 Billion | `Q4_K_M` (GGUF) | 40,960 tokens | `500a1f067a9f...` |
| **Ablation Model (Small)** | `qwen2.5:1.5b` | Qwen2.5-Instruct | 1.5 Billion | `Q4_K_M` (GGUF) | 32,768 tokens | `65ec06548149...` |
| **Ablation Model (Medium)** | `gemma3:4b` | Gemma3-IT | 4.3 Billion | `Q4_K_M` (GGUF) | 131,072 tokens | `a2af6cc3eb7f...` |

### Generation Hyperparameters
- `temperature`: `0.0`
- `seed`: `42`
- `num_predict`: `256`
- `stop_tokens`: `["<think>", "</think>"]` (for thinking disabled mode)

---

## 3. Dataset Provenance & Split Methodology

### 3.1 Real MCP Server Corpus ($N=621$ Transitions)
- Extracted from 12 active official/community MCP repositories on GitHub (`modelcontextprotocol/servers`, `git`, `filesystem`, `sqlite`, `github`, `puppeteer`, `memory`, `mysql`, `slack`, etc.).
- 123 total tool-definition change events: 110 additions/removals, 13 modified tool definitions (7 description, 2 schema, 4 mixed).
- 13 of 621 release transitions (2.09%) contained modifications to pre-existing tool contracts.

### 3.2 Main Benchmark Dataset ($N=370$)
- Partitioned using **Server Cluster Grouping** to prevent cross-server template leakage:
  - **Train**: $N=259$ (135 Malicious, 124 Benign) across 19 server clusters
  - **Dev**: $N=55$ (32 Malicious, 23 Benign)
  - **Held-Out Test**: $N=56$ (33 Malicious, 23 Benign)

### 3.3 Controlled Matched-Pair Pilot ($N=24$)
- Generated in `experiments/build_matched_pairs.py` $\rightarrow$ `data/matched_pairs.jsonl`.
- 12 real benign historical updates paired with 12 controlled malicious mutations preserving exact server, tool name, argument structure, and stylistic phrasing.

### 3.4 Adversarial Pilot Evaluation (Red-Team v2, $N=28$)
- Generated in `experiments/build_redteam_v2.py` $\rightarrow$ `data/redteam_v2.jsonl`.
- 28 targeted evasion vectors spanning 14 attack categories ($n=2$ per category).

---

## 4. Exact Evaluation Commands

### Run Full Experimental Evaluation Suite:
```powershell
python -u experiments/run_reviewer_evaluations.py
```

### Run Unit & Integration Test Suite (38 Tests):
```powershell
python -m unittest discover tests
```

### Run TF-IDF Cosine-Similarity Lexical Baseline Calibration:
```powershell
python -u experiments/baseline_embedding.py
```

### Run Local MCP JSON-RPC Integration Test:
```powershell
python -u experiments/phase5_live_mcp_proxy.py
```
