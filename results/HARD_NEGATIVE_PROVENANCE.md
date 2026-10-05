# Provenance and Construction Audit: Hard Negative Evaluation Examples

## 1. Overview

This document provides a transparent audit of the provenance, generation procedure, and validation criteria for the **47 hard negative examples** included in the Phase 3 dataset (`data/drift_train.jsonl`, `data/drift_dev.jsonl`, `data/drift_test.jsonl`).

---

## 2. Hard Negative Dataset Purpose & Motivation

Naive heuristic keyword filters or shallow classifiers frequently misclassify legitimate security-related documentation (e.g., instructions demanding parameter validation, token authorization, or strict file path restrictions) as malicious attacks. The hard negative set was constructed to ensure that benign tool updates containing imperative keywords (`must`, `require`, `validate`, `restrict`, `permission`, `credential`, `path`) do not trigger false positive alarms.

---

## 3. Provenance & Generation Procedure

The 47 hard negative examples were generated **programmatically** in `experiments/phase3_build_dataset.py` (lines 217–300) prior to model evaluation using a deterministic seed (`RANDOM_SEED = 42`).

### 3.1 Two-Stage Extraction Pipeline

1. **Stage 1: Real-Update Filtering from Phase 2 Corpus (12 examples)**
   - **Source**: Authentic developer changes recorded in `data/tool_changes.jsonl`.
   - **Procedure**: Scanned the candidate `new_definition.description` field for imperative and security-related tokens using the regular expression:
     ```python
     imp_keywords = [
         'must', 'require', 'token', 'auth', 'restrict', 'verify', 'do not',
         'never', 'validate', 'permission', 'credential', 'path', 'secure', 'root',
         'only', 'staging', 'read-only', 'sandbox', 'limit', 'strict', 'caution', 'warning',
         'ensure', 'check', 'valid', 'file', 'directory', 'key', 'access', 'safe'
     ]
     ```
   - **Verification**: Retained the authentic historical `old_definition` and `new_definition` with ground-truth label `BENIGN`.

2. **Stage 2: Authentic Snapshot Mining with Baseline Stubs (35 examples)**
   - **Source**: Authentic tool contract snapshots indexed across 25 open-source repositories in `data/tool_snapshots/`.
   - **Procedure**: Extracted real tools containing constraint descriptions (>20 characters).
   - **Baseline Construction**: Generated standard baseline description `Performs <tool_name>` as `old_definition` and populated the authentic developer docstring as `new_definition`.
   - **Verification**: All 35 tools represent genuine open-source implementations (e.g. `mcp-server-filesystem`, `mcp-server-git`, `mcp-server-fetch`, `mcp-server-docker`).

---

## 4. Distribution Across Splits & Cluster Leakage Check

The 47 hard negative records were distributed across the cluster-isolated dataset partitions:

| Split | Hard Negatives Count | Example ID Range | Cluster Isolation Status |
|---|---:|---|---|
| **Train Split** | 33 | `hard_neg_0001` – `hard_neg_0033` | 0 overlap with Dev or Test clusters |
| **Dev Split** | 6 | `hard_neg_0034` – `hard_neg_0039` | 0 overlap with Train or Test clusters |
| **Test Split** | 8 | `hard_neg_0040` – `hard_neg_0047` | 0 overlap with Train or Dev clusters |
| **Total** | **47** | | |

---

## 5. Audit Findings & Integrity Statement

1. **Pre-Construction**: The hard negative dataset was generated programmatically in batch during Phase 3 dataset construction and frozen prior to running judge evaluations.
2. **Independence from Test Sets**: No test-set evaluation results were used to iteratively modify or filter hard negative examples.
3. **No Synthetic Injection**: Hard negative descriptions originate from authentic open-source MCP repositories rather than manually fabricated attack strings.
4. **Reproducibility**: Rerunning `python experiments/phase3_build_dataset.py` reproduces the exact 47 hard negative records with identical SHA-256 hashes.
