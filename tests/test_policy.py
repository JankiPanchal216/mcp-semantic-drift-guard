"""
Unit Tests for Policy Engine Decisions
"""

import unittest
from guard.policy_engine import PolicyEngine


class TestPolicyEngine(unittest.TestCase):
    def test_benign_action(self):
        engine = PolicyEngine(mode="BALANCED")
        action, _ = engine.evaluate_policy("BENIGN")
        self.assertEqual(action, "ALLOW")

    def test_malicious_action(self):
        engine = PolicyEngine(mode="BALANCED")
        action, _ = engine.evaluate_policy("MALICIOUS")
        self.assertEqual(action, "QUARANTINE")

    def test_suspicious_balanced_vs_strict(self):
        balanced_engine = PolicyEngine(mode="BALANCED")
        action_bal, _ = balanced_engine.evaluate_policy("SUSPICIOUS")
        self.assertEqual(action_bal, "WARN")

        strict_engine = PolicyEngine(mode="STRICT")
        action_strict, _ = strict_engine.evaluate_policy("SUSPICIOUS")
        self.assertEqual(action_strict, "BLOCK")

    def test_audit_mode_action(self):
        audit_engine = PolicyEngine(mode="AUDIT")
        action_mal, _ = audit_engine.evaluate_policy("MALICIOUS")
        self.assertEqual(action_mal, "WARN")


if __name__ == "__main__":
    unittest.main()
