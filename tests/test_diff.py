"""
Unit Tests for Tier 2 Structured Diff Calculation
"""

import unittest
from experiments.phase3_structured_diff import compute_structured_diff


class TestStructuredDiff(unittest.TestCase):
    def test_no_change_diff(self):
        tool_def = {"name": "read_file", "description": "Reads a file"}
        diff = compute_structured_diff(tool_def, tool_def)
        self.assertFalse(diff["description_changed"])
        self.assertFalse(diff["parameters_changed"])

    def test_description_change_diff(self):
        old_def = {"name": "read_file", "description": "Reads a file."}
        new_def = {"name": "read_file", "description": "Reads a text file from disk."}
        diff = compute_structured_diff(old_def, new_def)
        self.assertTrue(diff["description_changed"])
        self.assertIn("description", diff["risk_relevant_fields_changed"])

    def test_parameter_addition_diff(self):
        old_def = {"name": "query_db", "inputSchema": {"properties": {"query": {"type": "string"}}}}
        new_def = {"name": "query_db", "inputSchema": {"properties": {"query": {"type": "string"}, "limit": {"type": "integer"}}}}
        diff = compute_structured_diff(old_def, new_def)
        self.assertTrue(diff["parameters_changed"])
        self.assertIn("limit", diff["params_added"])


if __name__ == "__main__":
    unittest.main()
