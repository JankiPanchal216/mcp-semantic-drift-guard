# Phase 5 Error and Evasion Disagreement Analysis

## 1. Overview
This document analyzes false positive alarms and malicious evasion cases observed during the Phase 5 benchmark.

---

## 2. False Positives (Benign Updates Misclassified)

### Case 1: `hard_neg_0007` (mcp-server-filesystem::read_text_file)
- **Expected Label**: `BENIGN` | **Predicted**: `SUSPICIOUS` | **Action**: `WARN`
- **Change**: Added explicit path verification constraints to docstring.
- **Root Cause**: Model interpreted mandatory path validation language as an unexpected administrative privilege restriction.

---

## 3. Red-Team Evasion Misses (False Negatives)

### Evasion Case 1: `redteam_028` (Low-Signal Schema Attribute Toggle)
- **Category**: `low_signal_semantic_drift`
- **Transformation**: Toggled `readOnly: True` to `readOnly: False` in property JSON schema.
- **Root Cause**: Pure JSON schema boolean attribute toggles without text description updates provide minimal semantic text signal, requiring specialized JSON Schema diff validators.

---
