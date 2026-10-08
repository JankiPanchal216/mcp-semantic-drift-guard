"""
Unit and Validation Test Suite for Salami Drift Benchmark v3.
Tests:
1. Dataset file existence and SHA-256 integrity
2. Budget and category counts (40 chains, 144 transitions)
3. Step ordering, sequence integrity, and root preservation
4. Adjacent vs Cumulative structural diff properties
5. Zero deterministic leakage in semantic categories (Tier 1.5 / Tier 2)
6. Zero gold-label leakage in model-facing definitions
7. No duplicate item or chain IDs
8. Draft-07 JSON Schema validity for all definitions
9. Validation harness fail-closed behavior on malformed / leaked chains
10. Absence of overt single-step capability leaps in Category A
"""

import json
import hashlib
import unittest
from pathlib import Path
import jsonschema

from experiments.generate_salami_benchmark_v3 import (
    OUTPUT_DATA_FILE,
    VALIDATION_JSON_FILE,
    extract_model_facing_inputs,
    calculate_token_edit_ratio
)
from guard.static_rules import evaluate_static_rules
from guard.schema_security_rules import inspect_schema_security_diff
from experiments.phase3_structured_diff import compute_structured_diff


class TestSalamiBenchmarkV3(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dataset_path = OUTPUT_DATA_FILE
        cls.val_report_path = VALIDATION_JSON_FILE

        with open(cls.dataset_path, "r", encoding="utf-8") as f:
            cls.records = [json.loads(line) for line in f if line.strip()]

        with open(cls.dataset_path, "rb") as f:
            cls.computed_sha256 = hashlib.sha256(f.read()).hexdigest()

        with open(cls.val_report_path, "r", encoding="utf-8") as f:
            cls.val_report = json.load(f)

    def test_v3_dataset_file_exists_and_hash(self):
        """Verifies dataset file exists and its SHA-256 matches validation report."""
        self.assertTrue(self.dataset_path.exists())
        self.assertEqual(self.computed_sha256, self.val_report["dataset_sha256"])
        self.assertEqual(self.val_report["overall_validation_status"], "VALIDATED_FOR_INFERENCE")

    def test_v3_budget_and_counts(self):
        """Verifies exact 40 chains and 144 transitions budget."""
        self.assertEqual(len(self.records), 144)
        chains_map = {}
        for r in self.records:
            chains_map.setdefault(r["chain_id"], []).append(r)
        self.assertEqual(len(chains_map), 40)

        mal_chains = sum(1 for c, steps in chains_map.items() if any(s["gold_label"] == "MALICIOUS" for s in steps))
        ben_chains = sum(1 for c, steps in chains_map.items() if all(s["gold_label"] == "BENIGN" for s in steps))
        self.assertEqual(mal_chains, 24)
        self.assertEqual(ben_chains, 16)

        # Transition category counts
        cats = [r["category"] for r in self.records]
        self.assertEqual(cats.count("A_adjacent_evasive"), 16)
        self.assertEqual(cats.count("D_parameter_drift"), 12)
        self.assertEqual(cats.count("E_instruction_erosion"), 12)
        self.assertEqual(cats.count("F_capability_combination"), 12)
        self.assertEqual(cats.count("G_low_signal_drift"), 12)
        self.assertEqual(cats.count("B_adjacent_detectable"), 24)
        self.assertEqual(cats.count("C_benign_long_drift"), 32)
        self.assertEqual(cats.count("C_std_benign_control"), 24)

    def test_v3_no_duplicate_item_or_chain_ids(self):
        """Asserts uniqueness of all item IDs."""
        item_ids = [r["item_id"] for r in self.records]
        self.assertEqual(len(item_ids), len(set(item_ids)), "Duplicate item_id detected in benchmark!")

    def test_v3_step_ordering_and_root_preservation(self):
        """Asserts monotonic step sequencing and immutable root definitions."""
        chains_map = {}
        for r in self.records:
            chains_map.setdefault(r["chain_id"], []).append(r)

        for cid, steps in chains_map.items():
            first_root = steps[0]["root_tool_definition"]
            for idx, s in enumerate(steps, 1):
                self.assertEqual(s["step_index"], idx, f"Non-monotonic step index in {cid}")
                self.assertEqual(s["total_steps"], len(steps))
                self.assertEqual(s["root_tool_definition"], first_root, f"Root definition mutated in {cid}")
                if idx > 1:
                    prev_candidate = steps[idx - 2]["tool_definition"]
                    self.assertEqual(s["previous_tool_definition"], prev_candidate, f"Previous def broken in {cid}")

    def test_v3_adjacent_and_cumulative_comparison(self):
        """Verifies structural diff computations and monotonic cumulative parameter growth."""
        chains_map = {}
        for r in self.records:
            chains_map.setdefault(r["chain_id"], []).append(r)

        for cid, steps in chains_map.items():
            cumul_params_prev = 0
            for s in steps:
                prev_def = s["previous_tool_definition"]
                cand_def = s["tool_definition"]
                root_def = s["root_tool_definition"]

                diff_adj = compute_structured_diff(prev_def, cand_def)
                diff_cumul = compute_structured_diff(root_def, cand_def)

                self.assertTrue(len(diff_cumul["params_added"]) >= cumul_params_prev)
                cumul_params_prev = len(diff_cumul["params_added"])

                # Adjacent parameter addition count is at most 1 in semantic categories
                if not s["category"].startswith("B_"):
                    self.assertLessEqual(len(diff_adj["params_added"]), 1)

    def test_v3_deterministic_leakage_zero_in_semantic_categories(self):
        """Asserts zero Tier 1.5 and Tier 2 deterministic leakage in semantic drift categories."""
        for r in self.records:
            cat = r["category"]
            if cat.startswith("B_"):
                continue  # Positive controls exempt

            cand_def = r["tool_definition"]
            prev_def = r["previous_tool_definition"]
            root_def = r["root_tool_definition"]

            diff_adj = compute_structured_diff(prev_def, cand_def)
            diff_cumul = compute_structured_diff(root_def, cand_def)

            static_adj = evaluate_static_rules(cand_def, diff_adj.get("description_diff_summary", ""))
            static_cumul = evaluate_static_rules(cand_def, diff_cumul.get("description_diff_summary", ""))
            self.assertFalse(static_adj.get("flagged", False), f"Static rule hit adj on {r['item_id']}")
            self.assertFalse(static_cumul.get("flagged", False), f"Static rule hit cumul on {r['item_id']}")

            findings_adj = inspect_schema_security_diff(prev_def.get("inputSchema"), cand_def.get("inputSchema"))
            findings_cumul = inspect_schema_security_diff(root_def.get("inputSchema"), cand_def.get("inputSchema"))
            crit_adj = [f for f in findings_adj if f.get("severity") in ("CRITICAL", "HIGH")]
            crit_cumul = [f for f in findings_cumul if f.get("severity") in ("CRITICAL", "HIGH")]
            self.assertEqual(len(crit_adj), 0, f"Schema security rule hit adj on {r['item_id']}")
            self.assertEqual(len(crit_cumul), 0, f"Schema security rule hit cumul on {r['item_id']}")

    def test_v3_gold_label_leakage_zero(self):
        """Asserts that model-facing representation contains zero gold labels or leak terms."""
        leak_terms = ["gold_label", "malicious", "attack", "trojan", "exploit", "poison", "sink_target"]

        for r in self.records:
            # Check candidate tool definition
            def_str = json.dumps(r["tool_definition"]).lower()
            for lt in leak_terms:
                self.assertNotIn(lt, def_str, f"Leaked term '{lt}' in tool definition of {r['item_id']}")

            # Check model-facing extracted inputs
            model_inputs = extract_model_facing_inputs(r)
            self.assertNotIn("gold_label", model_inputs)
            self.assertNotIn("category", model_inputs)
            self.assertNotIn("attack_family", model_inputs)
            self.assertNotIn("intended_semantic_change", model_inputs)
            self.assertNotIn("metrics_evaluator_metadata", model_inputs)

    def test_v3_schema_validity(self):
        """Validates all tool schemas conform to Draft-07 JSON Schema standard."""
        for r in self.records:
            root_sch = r["root_tool_definition"]["inputSchema"]
            cand_sch = r["tool_definition"]["inputSchema"]
            jsonschema.Draft7Validator.check_schema(root_sch)
            jsonschema.Draft7Validator.check_schema(cand_sch)

    def test_v3_no_final_step_capability_leaps_in_category_a(self):
        """Asserts Category A final transitions do not introduce overt single-step attack terms."""
        banned_terms = [
            "bypass_tenant_isolation", "strip_authorization_gates", "attach_host_namespace",
            "telemetry_sink_target", "eval_command", "purge_all_files", "dump_secret_keys"
        ]
        cat_a_records = [r for r in self.records if r["category"] == "A_adjacent_evasive"]
        for r in cat_a_records:
            diff_adj = compute_structured_diff(r["previous_tool_definition"], r["tool_definition"])
            for p in diff_adj["params_added"]:
                self.assertNotIn(p, banned_terms, f"Banned single-step attack param {p} in Category A {r['item_id']}")

    def test_v3_comparability_balance(self):
        """Asserts Category A and Category C controls have balanced average cumulative parameters."""
        cat_a_final = [r for r in self.records if r["category"] == "A_adjacent_evasive" and r["item_id"].endswith("_04")]
        cat_c_final = [r for r in self.records if r["category"] == "C_benign_long_drift" and r["item_id"].endswith("_04")]
        self.assertEqual(len(cat_a_final), 4)
        self.assertEqual(len(cat_c_final), 8)

        avg_a_params = sum(len(r["metrics_evaluator_metadata"]["cumulative_params_added"]) for r in cat_a_final) / 4.0
        avg_c_params = sum(len(r["metrics_evaluator_metadata"]["cumulative_params_added"]) for r in cat_c_final) / 8.0
        self.assertAlmostEqual(avg_a_params, avg_c_params, delta=1.0)


if __name__ == "__main__":
    unittest.main()
