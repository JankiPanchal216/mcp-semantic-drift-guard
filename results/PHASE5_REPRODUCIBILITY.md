# Phase 5 Reproducibility Report

## 1. Environment & Hardware Specifications
- **Python**: 3.12 / 3.11
- **LLM Engine**: Ollama serving `qwen3:8b` (Quantization Q4_K_M)
- **Decoding Configuration**: Temperature $T = 0.0$, Seed $= 42$
- **Dependencies**: `matplotlib`, `numpy`, `sqlite3`

## 2. Execution Commands
```bash
# 1. Run Unit Test Suite (28 tests)
python -m unittest discover tests

# 2. Run Live MCP Proxy Socket Interception Test
python experiments/phase5_live_mcp_proxy.py

# 3. Run Red-Team Adversarial Suite Inspection
python experiments/phase5_red_team_suite.py

# 4. Run Full Phase 5 Evaluation Benchmark
python experiments/phase5_evaluate_full.py
```
