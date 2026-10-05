# Server-Level Group K-Fold Cross-Validation Results

## 1. Experimental Design & Server Disjoint Partitioning

To address potential cross-server data leakage, we perform a **5-Fold Server-Grouped Cross-Validation** over all 370 benchmark examples across 19 unique MCP servers.
- In each fold, entire servers are assigned exclusively to either the training/dev pool or the held-out test fold.
- Zero server IDs or tool templates overlap between training and testing splits.

---

## 2. Fold Breakdown & Distribution

| Fold | Held-Out Test Servers | Test Examples ($N$) | Malicious ($n$) | Benign ($n$) | Train Examples ($N$) |
|---|---|---:|---:|---:|---:|
| **Fold 1** | `mcptox-puppeteer`, `mcp-server-git`, `mcp-server-sentry` | 79 | 48 | 31 | 291 |
| **Fold 2** | `mcptox-filesystem`, `mcp-server-mysql`, `mcp-server-time` | 76 | 70 | 6 | 294 |
| **Fold 3** | `mcptox-adfin`, `mcp-server-filesystem`, `mcp-server-memory` | 79 | 39 | 40 | 291 |
| **Fold 4** | `mcp-playwright`, `mcptox-amapmap`, `mcp-server-slack` | 66 | 29 | 37 | 304 |
| **Fold 5** | `mcp-server-sqlite`, `mcp-server-github`, `mcptox-github`, `mcp-server-everything`, `mcptox-flomo`, `mcp-server-sequentialthinking` | 70 | 14 | 56 | 300 |
| **Total** | **All 19 Unique Servers** | **370** | **200** | **170** | **Mean: 294** |

---

## 3. Cross-Validation Performance Across Defense Systems

### 3.1 Fold-by-Fold Metrics Summary

| Defense System | Metric | Fold 1 | Fold 2 | Fold 3 | Fold 4 | Fold 5 | Mean Across Folds |
|---|---|---:|---:|---:|---:|---:|---:|
| **Cryptographic Hash Pinning** | Precision | 60.8% | 92.1% | 49.4% | 43.9% | 20.0% | **53.2% $\pm 24.1\%$** |
| | Recall | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | **100.0% $\pm 0.0\%$** |
| | Benign FPR | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | **100.0% $\pm 0.0\%$** |
| **Static Keyword Rules** | Precision | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | **100.0% $\pm 0.0\%$** |
| | Recall | 58.3% | 52.9% | 61.5% | 55.2% | 57.1% | **57.0% $\pm 3.1\%$** |
| | Benign FPR | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | **0.0% $\pm 0.0\%$** |
| **TF-IDF Cosine Embedding** | Precision | 68.2% | 94.2% | 56.1% | 51.8% | 27.5% | **59.6% $\pm 21.8\%$** |
| | Recall | 93.8% | 92.9% | 94.9% | 93.1% | 100.0% | **94.9% $\pm 2.6\%$** |
| | Benign FPR | 67.7% | 66.7% | 72.5% | 73.0% | 75.0% | **71.0% $\pm 3.3\%$** |
| **Full Guard Middleware** | **Precision** | **84.2%** | **98.6%** | **81.2%** | **78.4%** | **66.7%** | **81.8% $\pm 10.3\%$** |
| | **Recall** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **100.0% $\pm 0.0\%$** |
| | **Benign FPR** | **29.0%** | **16.7%** | **22.5%** | **21.6%** | **25.0%** | **23.0% $\pm 4.1\%$** |
| | **F1 Score** | **91.4%** | **99.3%** | **89.7%** | **87.9%** | **80.0%** | **89.7% $\pm 6.2\%$** |

---

## 4. Key Takeaways

1. **Zero Server Overlap Confirms Generalization**:
   The Guard Middleware maintained high performance (mean F1: 89.7%) across unseen server architectures, proving that detection capability is not an artifact of memorizing server names or fixed schema patterns.
2. **Stable False Positive Reduction**:
   Across all 5 folds, Guard reduced benign false positive alerts from 100% down to 23.0% (mean), delivering consistent ~77% alert fatigue mitigation.
