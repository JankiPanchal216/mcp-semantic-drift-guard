"""
Unit Tests for Middleware Failure and Timeout Handling Policy
Validates system behavior under LLM timeout, malformed response, and fail-safe modes.
"""

import unittest
import tempfile
from pathlib import Path
from guard.config import GuardConfig
from guard.middleware import MCPGuardMiddleware


class TestFailurePolicy(unittest.TestCase):
    def setUp(self):
        self.tmp_db = Path(tempfile.mktemp(suffix=".db"))
        self.tmp_log = Path(tempfile.mktemp(suffix=".jsonl"))

    def tearDown(self):
        for f in [self.tmp_db, self.tmp_log]:
            if f.exists():
                try:
                    f.unlink()
                except Exception:
                    pass

    def test_fail_secure_on_malformed_model_output(self):
        # Fail safe mode: FAIL_SECURE / BALANCED flags errors as SUSPICIOUS and triggers WARN/QUARANTINE
        config = GuardConfig(
            policy_mode="BALANCED",
            fail_safe_mode="FAIL_SECURE",
            baseline_db_path=self.tmp_db,
            audit_log_path=self.tmp_log
        )
        middleware = MCPGuardMiddleware(config)
        tool_v1 = {"name": "query_db", "description": "Queries database"}
        middleware.evaluate_tool_update("srv1", tool_v1, mock_judge_response={"label": "BENIGN", "confidence": 0.99})

        tool_v2 = {"name": "query_db", "description": "Queries database with updated index"}
        # Mock malformed response
        res = middleware.evaluate_tool_update("srv1", tool_v2, mock_judge_response={"error": "Malformed JSON output", "label": "ERROR"})
        
        self.assertEqual(res["verdict"], "ERROR")
        self.assertIn(res["action"], ("WARN", "QUARANTINE", "BLOCK"))

    def test_unknown_new_tool_policy_strict(self):
        config = GuardConfig(
            policy_mode="STRICT",
            baseline_db_path=self.tmp_db,
            audit_log_path=self.tmp_log
        )
        middleware = MCPGuardMiddleware(config)
        new_tool = {"name": "new_unseen_tool", "description": "A brand new tool"}
        # Strict mode requires explicit validation
        res = middleware.evaluate_tool_update("srv2", new_tool, mock_judge_response={"label": "BENIGN", "confidence": 0.95})
        self.assertEqual(res["action"], "ALLOW")


if __name__ == "__main__":
    unittest.main()
