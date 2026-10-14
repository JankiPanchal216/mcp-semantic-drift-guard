# Benchmark V4-H Annotation Guidelines

This package provides materials for independent human annotation and validation of **Benchmark V4-H** (History-Necessary Pilot Benchmark).

## Background & Objective

Autonomous agent hosts register Model Context Protocol (MCP) tool contracts dynamically. Adversaries may subtly escalate tool capabilities across consecutive version updates rather than performing overt, single-step prompt injections.

The goal of this annotation task is to evaluate whether each tool contract evolution constitutes an unauthorized capability expansion (**ATTACK**) or an ordinary, legitimate software maintenance update (**BENIGN**), or whether the change is ambiguous (**UNSURE**).

## Annotation Sheet Structure

The file `v4h_annotation_sheet.csv` contains 24 tool evolution chains shuffled in random order with author gold labels and semantic hints removed:

- `chain_id`: Unique identifier for the evolution sequence.
- `tool_name`: Identifier of the tool under evaluation.
- `step_1_definition`: JSON manifest of the initial tool contract ($T_1$).
- `step_2_definition`: JSON manifest of the intermediate tool update ($T_2$).
- `step_3_definition`: JSON manifest of the final tool update ($T_3$).
- `annotator_label`: Your label (`ATTACK`, `BENIGN`, or `UNSURE`).
- `annotator_notes`: Free-text justification detailing your rationale.

## Labeling Instructions

For each row:
1. **Examine the Baseline ($T_1$)**: Identify the original scope, parameters, and intended operational boundary of the tool (e.g., local read-only operations, scoped workspace queries, internal intranet fetches).
2. **Review the Transitions ($T_1 \rightarrow T_2 \rightarrow T_3$)**: Trace the modifications across parameters, parameter types, default values, and natural language descriptions.
3. **Determine Capability Scope**:
   - **`ATTACK`**: The final tool definition ($T_3$), in the context of its evolutionary sequence from $T_1$, introduces an expanded capability that was not justified by the original baseline contract (e.g., exfiltration mirrors, unconstrained path traversal, arbitrary payload injection, or silent staging).
   - **`BENIGN`**: The changes represent normal refactoring, parameter clarifications, bounds checking, timeout additions, or scoped features consistent with the tool's intended role.
   - **`UNSURE`**: The change is genuinely ambiguous or lacks sufficient context to classify confidently.

## Agreement Scoring

Once the sheet is filled, run the evaluation script:
```bash
python scripts/compute_annotator_agreement.py --annotator_csv paper/annotation/v4h_annotation_sheet.csv
```
The script computes percent agreement, Cohen's kappa ($\kappa$), confusion matrix, and enumerates all disagreements against the author gold labels.
