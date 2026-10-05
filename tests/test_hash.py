"""
Unit Tests for Tier 0 Hash Comparison
"""

import unittest
from pathlib import Path
from guard.baseline_store import normalize_tool_def, compute_sha256


class TestHashComparison(unittest.TestCase):
    def test_deterministic_hashing(self):
        tool_def_1 = {"name": "read_file", "description": "Reads a file", "inputSchema": {"type": "object"}}
        tool_def_2 = {"description": "Reads a file", "inputSchema": {"type": "object"}, "name": "read_file"}

        norm_1 = normalize_tool_def(tool_def_1)
        norm_2 = normalize_tool_def(tool_def_2)

        hash_1 = compute_sha256(norm_1)
        hash_2 = compute_sha256(norm_2)

        self.assertEqual(norm_1, norm_2)
        self.assertEqual(hash_1, hash_2)

    def test_hash_mismatch_on_change(self):
        tool_def_1 = {"name": "read_file", "description": "Reads a file"}
        tool_def_2 = {"name": "read_file", "description": "Reads a file carefully"}

        hash_1 = compute_sha256(normalize_tool_def(tool_def_1))
        hash_2 = compute_sha256(normalize_tool_def(tool_def_2))

        self.assertNotEqual(hash_1, hash_2)


if __name__ == "__main__":
    unittest.main()
