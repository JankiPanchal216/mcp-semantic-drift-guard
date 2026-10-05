"""
Unit Tests for SQLite Baseline Store Persistence & History
"""

import unittest
import tempfile
from pathlib import Path
from guard.baseline_store import BaselineStore


class TestBaselineStore(unittest.TestCase):
    def setUp(self):
        self.tmp_db = Path(tempfile.mktemp(suffix=".db"))
        self.store = BaselineStore(self.tmp_db)

    def tearDown(self):
        if self.tmp_db.exists():
            try:
                self.tmp_db.unlink()
            except Exception:
                pass

    def test_initial_store_and_retrieve(self):
        tool_def = {"name": "read_file", "description": "Initial version"}
        store_hash = self.store.update_trusted_baseline("test_server", "read_file", tool_def)
        
        retrieved_def, retrieved_hash = self.store.get_trusted_definition("test_server", "read_file")
        self.assertEqual(retrieved_hash, store_hash)
        self.assertEqual(retrieved_def["description"], "Initial version")

    def test_baseline_update_history(self):
        tool_v1 = {"name": "read_file", "description": "Version 1"}
        tool_v2 = {"name": "read_file", "description": "Version 2"}

        self.store.update_trusted_baseline("test_server", "read_file", tool_v1)
        v2_hash = self.store.update_trusted_baseline("test_server", "read_file", tool_v2)

        retrieved_def, retrieved_hash = self.store.get_trusted_definition("test_server", "read_file")
        self.assertEqual(retrieved_hash, v2_hash)
        self.assertEqual(retrieved_def["description"], "Version 2")


if __name__ == "__main__":
    unittest.main()
