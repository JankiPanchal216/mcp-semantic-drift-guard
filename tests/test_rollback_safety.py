"""
Unit Tests for Rollback Safety and Schema Incompatibility Handling
Tests client-server call compatibility when rollback to V1 is executed
in the presence of breaking schema changes (removed, renamed, or added required parameters).
"""

import unittest
from typing import Dict, Any, Tuple


def check_invocation_compatibility(
    client_call_args: Dict[str, Any],
    server_v2_schema: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    Simulates MCP runtime dispatch:
    Client constructed call args based on rolled-back V1 definition.
    Server executes call using its actual V2 inputSchema.
    Returns (is_compatible, error_reason).
    """
    v2_props = server_v2_schema.get("properties", {})
    v2_required = server_v2_schema.get("required", [])

    # 1. Check if all required parameters in server V2 are present in client args
    for req_field in v2_required:
        if req_field not in client_call_args:
            return False, f"Missing required parameter '{req_field}' expected by server V2"

    # 2. Check if client passed parameters removed/rejected in server V2 (if additionalProperties=False)
    if server_v2_schema.get("additionalProperties") is False:
        for arg_name in client_call_args:
            if arg_name not in v2_props:
                return False, f"Disallowed unexpected parameter '{arg_name}' not accepted by server V2"

    return True, "Compatible"


class TestRollbackSafety(unittest.TestCase):
    def test_removed_parameter_breaks_v1_call(self):
        # V1 had 'path' and 'encoding'. V2 removed 'encoding' with additionalProperties=False.
        server_v2_schema = {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False
        }
        client_v1_args = {"path": "/tmp/test.txt", "encoding": "utf-8"}
        compat, reason = check_invocation_compatibility(client_v1_args, server_v2_schema)
        self.assertFalse(compat)
        self.assertIn("Disallowed unexpected parameter 'encoding'", reason)

    def test_new_required_parameter_in_v2_breaks_v1_call(self):
        # V2 added required parameter 'auth_token'. V1 client did not supply it.
        server_v2_schema = {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "auth_token": {"type": "string"}
            },
            "required": ["query", "auth_token"]
        }
        client_v1_args = {"query": "SELECT * FROM users"}
        compat, reason = check_invocation_compatibility(client_v1_args, server_v2_schema)
        self.assertFalse(compat)
        self.assertIn("Missing required parameter 'auth_token'", reason)

    def test_optional_parameter_addition_remains_compatible(self):
        # V2 added optional parameter 'limit'. V1 client supplies only 'query'.
        server_v2_schema = {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 10}
            },
            "required": ["query"]
        }
        client_v1_args = {"query": "SELECT * FROM users"}
        compat, reason = check_invocation_compatibility(client_v1_args, server_v2_schema)
        self.assertTrue(compat)


if __name__ == "__main__":
    unittest.main()
