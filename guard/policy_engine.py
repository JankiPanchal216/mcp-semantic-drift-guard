"""
Phase 4 Policy Engine Module
Translates detector verdicts (BENIGN, SUSPICIOUS, MALICIOUS, ERROR) and policy tiers
(STRICT, BALANCED, AUDIT) into deterministic actions (ALLOW, WARN, BLOCK, QUARANTINE).
"""

from typing import Dict, List, Any, Tuple


class PolicyEngine:
    """
    Policy Engine mapping:
    - Verdict: BENIGN, SUSPICIOUS, MALICIOUS, ERROR
    - Modes: STRICT, BALANCED, AUDIT
    """
    def __init__(self, mode: str = "BALANCED", fail_safe_mode: str = "FAIL_CLOSED_ON_MALICIOUS"):
        self.mode = mode.upper()
        self.fail_safe_mode = fail_safe_mode.upper()

    def evaluate_policy(
        self,
        verdict: str,
        confidence: float = 1.0,
        static_flagged: bool = False,
        error_info: str = None
    ) -> Tuple[str, str]:
        """
        Returns (action, rationale).
        Actions:
        - ALLOW: Update trusted baseline and allow execution.
        - WARN: Allow execution with warning, retain previous baseline.
        - BLOCK: Reject execution, retain previous baseline.
        - QUARANTINE: Reject execution, flag in quarantine log, retain previous baseline.
        """
        verdict = verdict.upper()

        if static_flagged and verdict != "MALICIOUS":
            # Static rule high-severity flag overrides semantic verdict if static rules triggered
            verdict = "MALICIOUS"

        if verdict == "BENIGN":
            return "ALLOW", "Semantic drift analysis confirmed benign developer update."

        if verdict == "MALICIOUS":
            if self.mode == "AUDIT":
                return "WARN", "AUDIT MODE: Malicious drift detected, logged warning without blocking."
            return "QUARANTINE", "Malicious tool drift intercepted. Action: Blocked and quarantined."

        if verdict == "SUSPICIOUS":
            if self.mode == "STRICT":
                return "BLOCK", "STRICT POLICY: Suspicious semantic drift blocked."
            elif self.mode == "BALANCED":
                return "WARN", "BALANCED POLICY: Suspicious tool modification flagged for security review."
            else: # AUDIT
                return "ALLOW", "AUDIT MODE: Suspicious modification allowed and logged."

        if verdict in ("ERROR", "TIMEOUT", "UNAVAILABLE"):
            if self.fail_safe_mode == "FAIL_CLOSED_ON_MALICIOUS" and static_flagged:
                return "BLOCK", f"FAIL-CLOSED: Static rules flagged potential threat during LLM error: {error_info}"
            if self.mode == "STRICT":
                return "BLOCK", f"STRICT POLICY: Evaluation error occurred ({error_info}). Blocked for safety."
            else:
                return "WARN", f"FALLBACK: Evaluation error ({error_info}). Allowed with audit warning."

        return "WARN", f"Unknown verdict '{verdict}'. Applied default fallback action."
