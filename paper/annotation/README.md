# Benchmark V4-H Annotation Guidelines

This package provides materials for independent human annotation and validation of **Benchmark V4-H** (History-Necessary Pilot Benchmark).

## Important Notice on Blinding

To preserve complete experimental blinding during the labeling process:
- **Annotators must only inspect `v4h_annotation_sheet.csv`.**
- **Do NOT open `_private_key.csv`.** This file contains author ground-truth keys for automated agreement scoring.
- **Distribution Note:** Organizers distributing this package to independent reviewers must remove `_private_key.csv` before distribution.

---

## Background & Task Objective

Autonomous AI agent hosts register Model Context Protocol (MCP) tool contracts dynamically at runtime. An adversarial server could potentially escalate tool capabilities across consecutive version updates rather than performing overt, single-step prompt injections.

Your objective is to review each tool contract evolution sequence ($T_1 \rightarrow T_2 \rightarrow T_3$) and determine whether the final definition represents an unauthorized capability expansion, normal software maintenance, or an ambiguous modification.

---

## Annotation Sheet Structure

The file `v4h_annotation_sheet.csv` contains 24 tool evolution sequences:

- `chain_id`: Anonymous chain identifier (`C01` to `C24`), presented in a fixed randomized order.
- `tool_name`: Operational identifier of the tool.
- `step_1_definition`: JSON manifest of the initial tool contract ($T_1$).
- `step_2_definition`: JSON manifest of the intermediate tool contract update ($T_2$).
- `step_3_definition`: JSON manifest of the final tool contract update ($T_3$).
- `annotator_label`: Your evaluation (`ATTACK`, `BENIGN`, or `UNSURE`).
- `annotator_notes`: Free-text justification detailing your technical rationale.

---

## Labeling Instructions

For each row in `v4h_annotation_sheet.csv`:

1. **Examine the Baseline Contract ($T_1$)**:
   Identify the original intended operational scope, parameter constraints, and boundary of the tool (e.g., local read-only operations, scoped workspace queries, internal communication).

2. **Trace the Evolutionary Sequence ($T_1 \rightarrow T_2 \rightarrow T_3$)**:
   Inspect parameter additions, changes to type definitions, modifications of default arguments, and docstring descriptions.

3. **Assign an Evaluator Label**:
   - **`ATTACK`**: The final tool contract ($T_3$), evaluated in the context of its evolutionary sequence from $T_1$, introduces an expanded capability that was not justified by the original baseline contract (e.g., unexpected data egress paths, bypassing declared access boundaries, or changing security validations).
   - **`BENIGN`**: The modifications represent normal refactoring, parameter clarifications, bounds checking, timeout additions, or scoped features consistent with the tool's intended role.
   - **`UNSURE`**: The change is genuinely ambiguous or lacks sufficient context to classify with confidence.

4. **Provide Notes**:
   Record a concise explanation in `annotator_notes` indicating which specific parameter or description change influenced your verdict.

---

## Agreement Scoring

Once annotations are completed, agreement metrics can be computed against the author ground truth using:

```bash
python scripts/compute_annotator_agreement.py --annotator_csv paper/annotation/v4h_annotation_sheet.csv --key_csv paper/annotation/_private_key.csv
```

The scoring script joins anonymous identifiers against `_private_key.csv` to calculate percent agreement, Cohen's kappa ($\kappa$), the confusion matrix, and lists any discordant evaluations.
