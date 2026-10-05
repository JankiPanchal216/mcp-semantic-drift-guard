"""
Test Rule 10: LLM Timeouts, Connection Errors, and Parse Failures
Must be recorded as predicted_label='ERROR', parse_error=True, and NEVER silently mapped to BENIGN.
"""

import unittest
from unittest.mock import patch
from pathlib import Path

from guard.semantic_judge import evaluate_semantic_judge_example, call_ollama_judge
from guard.middleware import MCPGuardMiddleware
from guard.config import GuardConfig


class TestErrorHandlingRule10(unittest.TestCase):

    def setUp(self):
        self.sample_example = {
            "example_id": "test_err_001",
            "server_id": "mcp-test-server",
            "tool_name": "test_tool",
            "expected_label": "BENIGN",
            "old_definition": {"name": "test_tool", "description": "Old docstring"},
            "new_definition": {"name": "test_tool", "description": "New docstring with update"},
            "structured_diff": {"description_diff_summary": "Docstring changed"}
        }

    @patch("guard.semantic_judge.urllib.request.urlopen")
    def test_ollama_connection_error_produces_error_label(self, mock_urlopen):
        # Simulate connection failure (e.g., Ollama not running)
        mock_urlopen.side_effect = Exception("Connection refused to Ollama")

        res = evaluate_semantic_judge_example(self.sample_example, mode="diff")
        self.assertEqual(res["prediction"], "ERROR", "Failed connection must yield prediction='ERROR'")
        self.assertTrue(res["parse_error"], "Failed connection must set parse_error=True")
        self.assertFalse(res["is_tn"], "Error must never be recorded as a True Negative (TN)")
        self.assertFalse(res["is_fn"], "Error must never be recorded as a False Negative (FN)")
        self.assertFalse(res["is_tp"], "Error must never be recorded as a True Positive (TP)")
        self.assertFalse(res["is_fp"], "Error must never be recorded as a False Positive (FP)")

    @patch("guard.semantic_judge.urllib.request.urlopen")
    def test_malformed_json_produces_error_not_benign(self, mock_urlopen):
        # Simulate garbage LLM response that cannot be parsed as JSON
        class MockResponse:
            def read(self):
                return b'{"message": {"content": "I am an LLM and I refuse to output JSON today."}}'
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass

        mock_urlopen.return_value = MockResponse()

        res = evaluate_semantic_judge_example(self.sample_example, mode="diff")
        self.assertEqual(res["prediction"], "ERROR", "Unparseable output must yield prediction='ERROR'")
        self.assertTrue(res["parse_error"], "Unparseable output must set parse_error=True")

    def test_middleware_records_error_verdict_when_judge_fails(self):
        cfg = GuardConfig(policy_mode="BALANCED")
        middleware = MCPGuardMiddleware(cfg)

        # Pre-populate baseline
        middleware.baseline_store.update_trusted_baseline(
            "mcp-test-server", "test_tool", self.sample_example["old_definition"], reason="TEST"
        )

        # Evaluate with an explicit error judge response
        eval_res = middleware.evaluate_tool_update(
            server_id="mcp-test-server",
            new_tool_def=self.sample_example["new_definition"],
            mock_judge_response={"error": "Simulated judge timeout", "label": "ERROR"}
        )

        self.assertEqual(eval_res["verdict"], "ERROR", "Middleware must record verdict='ERROR' on judge failure")
        self.assertNotEqual(eval_res["action"], "ALLOW", "Middleware must not silently ALLOW on judge error")


if __name__ == "__main__":
    unittest.main()
