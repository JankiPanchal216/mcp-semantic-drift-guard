"""
Phase 4 MCP Semantic Drift Guard Middleware
Unified Guard Pipeline orchestrating Tier 0 Hash -> Tier 1 Static -> Tier 2 Diff -> Tier 3 Semantic Judge (Mode B).
Enforces configurable policy actions (ALLOW, WARN, BLOCK, QUARANTINE) and persistent baseline updates.
"""

import os
import sys
import time
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from guard.config import GuardConfig
from guard.baseline_store import BaselineStore, normalize_tool_def, compute_sha256
from guard.audit_logger import AuditLogger
from guard.policy_engine import PolicyEngine
from guard.static_rules import evaluate_static_rules
from guard.schema_security_rules import inspect_schema_security_diff
from experiments.phase3_structured_diff import compute_structured_diff
from guard.semantic_judge import (
    build_mode_b_prompt,
    call_ollama_judge
)


class MCPGuardMiddleware:
    def __init__(self, config: Optional[GuardConfig] = None):
        self.config = config or GuardConfig.load_default()
        self.baseline_store = BaselineStore(self.config.baseline_db_path)
        self.audit_logger = AuditLogger(self.config.audit_log_path)
        self.policy_engine = PolicyEngine(
            mode=self.config.policy_mode,
            fail_safe_mode=self.config.fail_safe_mode
        )

    def evaluate_tool_update(
        self,
        server_id: str,
        new_tool_def: Dict[str, Any],
        mock_judge_response: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Main inspection entry point for a tool definition update.
        Returns complete decision result dict.
        """
        start_time = time.time()
        tool_name = new_tool_def.get("name", "unknown_tool") if new_tool_def is not None else "removed_tool"

        # Normalize & Hash new tool definition
        new_norm = normalize_tool_def(new_tool_def)
        new_hash = compute_sha256(new_norm)

        # Retrieve previous trusted definition
        old_tool_def, trusted_hash = self.baseline_store.get_trusted_definition(server_id, tool_name)
        if tool_name == "removed_tool" and old_tool_def is not None:
            tool_name = old_tool_def.get("name", "removed_tool")

        # -------------------------------------------------------------------
        # TIER 0: Hash Comparison (Fast Path)
        # -------------------------------------------------------------------
        if old_tool_def is not None and trusted_hash == new_hash:
            latency_ms = (time.time() - start_time) * 1000
            audit_rec = self.audit_logger.log_event(
                server_id=server_id,
                tool_name=tool_name,
                previous_hash=trusted_hash,
                new_hash=new_hash,
                change_detected=False,
                structured_diff={},
                static_rule_result={"flagged": False},
                semantic_judge_result={"skipped": True, "reason": "Hash match (Fast Path)"},
                final_verdict="BENIGN",
                action_taken="ALLOW",
                policy_mode=self.config.policy_mode,
                latency_ms=latency_ms
            )
            return {
                "server_id": server_id,
                "tool_name": tool_name,
                "change_detected": False,
                "verdict": "BENIGN",
                "action": "ALLOW",
                "active_tool_definition": new_tool_def,
                "latency_ms": latency_ms,
                "audit_record": audit_rec
            }

        # Definition has changed or is new! Compute structured diff
        change_detected = True

        # -------------------------------------------------------------------
        # TIER 1: Compute Structured Diff
        # -------------------------------------------------------------------
        diff_res = compute_structured_diff(old_tool_def, new_tool_def)

        # -------------------------------------------------------------------
        # TIER 1.5: Deterministic Schema Security Rules
        # -------------------------------------------------------------------
        old_schema = old_tool_def.get("inputSchema") if isinstance(old_tool_def, dict) else None
        new_schema = new_tool_def.get("inputSchema") if isinstance(new_tool_def, dict) else None
        schema_findings = inspect_schema_security_diff(old_schema, new_schema)
        schema_flagged = any(f.get("severity") in ("CRITICAL", "HIGH") for f in schema_findings)

        if schema_flagged:
            action, rationale = self.policy_engine.evaluate_policy(
                verdict="MALICIOUS",
                confidence=1.0,
                static_flagged=True
            )
            self.baseline_store.record_blocked_update(
                server_id, tool_name, new_tool_def, status="QUARANTINED", reason="SCHEMA_SECURITY_RULE_TRIGGERED"
            )
            latency_ms = (time.time() - start_time) * 1000
            audit_rec = self.audit_logger.log_event(
                server_id=server_id,
                tool_name=tool_name,
                previous_hash=trusted_hash,
                new_hash=new_hash,
                change_detected=True,
                structured_diff=diff_res,
                static_rule_result={"flagged": False},
                semantic_judge_result={"skipped": True, "reason": "Schema security violation triggered"},
                final_verdict="MALICIOUS",
                action_taken=action,
                policy_mode=self.config.policy_mode,
                latency_ms=latency_ms
            )
            active_def = old_tool_def if old_tool_def is not None else new_tool_def
            return {
                "server_id": server_id,
                "tool_name": tool_name,
                "change_detected": True,
                "verdict": "MALICIOUS",
                "action": action,
                "rationale": rationale,
                "active_tool_definition": active_def,
                "latency_ms": latency_ms,
                "audit_record": audit_rec
            }

        # -------------------------------------------------------------------
        # TIER 2: Static Rules Scan
        # -------------------------------------------------------------------
        diff_summary = diff_res.get("description_diff_summary", "")
        static_res = evaluate_static_rules(new_tool_def, diff_summary)
        static_flagged = static_res.get("flagged", False)

        # Fast Alert if static high-severity match
        if static_flagged and static_res.get("severity") == "high":
            action, rationale = self.policy_engine.evaluate_policy(
                verdict="MALICIOUS",
                confidence=1.0,
                static_flagged=True
            )
            # Record quarantine without updating baseline
            self.baseline_store.record_blocked_update(
                server_id, tool_name, new_tool_def, status="QUARANTINED", reason="STATIC_RULE_HIGH_SEVERITY"
            )
            latency_ms = (time.time() - start_time) * 1000
            audit_rec = self.audit_logger.log_event(
                server_id=server_id,
                tool_name=tool_name,
                previous_hash=trusted_hash,
                new_hash=new_hash,
                change_detected=True,
                structured_diff=diff_res,
                static_rule_result=static_res,
                semantic_judge_result={"skipped": True, "reason": "High-severity static rule triggered"},
                final_verdict="MALICIOUS",
                action_taken=action,
                policy_mode=self.config.policy_mode,
                latency_ms=latency_ms
            )
            # Rollback: Return old trusted definition if available
            active_def = old_tool_def if old_tool_def is not None else new_tool_def
            return {
                "server_id": server_id,
                "tool_name": tool_name,
                "change_detected": True,
                "verdict": "MALICIOUS",
                "action": action,
                "rationale": rationale,
                "active_tool_definition": active_def,
                "latency_ms": latency_ms,
                "audit_record": audit_rec
            }

        # -------------------------------------------------------------------
        # TIER 3: Semantic Drift Judge (Mode B Diff Only)
        # -------------------------------------------------------------------
        semantic_res = {}
        verdict = "BENIGN"
        confidence = 0.95
        error_info = None

        if mock_judge_response is not None:
            # Reusable for unit tests without Ollama dependency
            semantic_res = mock_judge_response
            verdict = mock_judge_response.get("label", "BENIGN")
            confidence = mock_judge_response.get("confidence", 0.95)
        else:
            try:
                mode_b_prompt = build_mode_b_prompt(diff_res)
                parsed_json, raw_text, err, judge_lat_ms = call_ollama_judge(mode_b_prompt)

                if err or not parsed_json:
                    error_info = err or "JSON parsing failed"
                    verdict = "ERROR"
                    semantic_res = {"error": error_info, "raw_text": raw_text, "skipped": False}
                else:
                    semantic_res = parsed_json
                    verdict = parsed_json.get("label", "BENIGN")
                    confidence = parsed_json.get("confidence", 0.95)
            except Exception as e:
                error_info = str(e)
                verdict = "ERROR"
                semantic_res = {"error": error_info, "skipped": False}

        # -------------------------------------------------------------------
        # Policy Engine Decision
        # -------------------------------------------------------------------
        action, rationale = self.policy_engine.evaluate_policy(
            verdict=verdict,
            confidence=confidence,
            static_flagged=static_flagged,
            error_info=error_info
        )

        # Baseline & Rollback Execution
        active_def = new_tool_def
        if action == "ALLOW":
            # Update trusted baseline database
            self.baseline_store.update_trusted_baseline(
                server_id, tool_name, new_tool_def, reason=f"BENIGN_VERDICT ({rationale})"
            )
            active_def = new_tool_def
        else: # WARN, BLOCK, QUARANTINE
            # Retain previous baseline! Record history as QUARANTINED/SUSPICIOUS
            self.baseline_store.record_blocked_update(
                server_id, tool_name, new_tool_def, status=verdict, reason=rationale
            )
            # Rollback to old trusted definition if available
            if old_tool_def is not None:
                active_def = old_tool_def

        latency_ms = (time.time() - start_time) * 1000

        audit_rec = self.audit_logger.log_event(
            server_id=server_id,
            tool_name=tool_name,
            previous_hash=trusted_hash,
            new_hash=new_hash,
            change_detected=True,
            structured_diff=diff_res,
            static_rule_result=static_res,
            semantic_judge_result=semantic_res,
            final_verdict=verdict,
            action_taken=action,
            policy_mode=self.config.policy_mode,
            latency_ms=latency_ms,
            error_info=error_info
        )

        return {
            "server_id": server_id,
            "tool_name": tool_name,
            "change_detected": True,
            "verdict": verdict,
            "action": action,
            "rationale": rationale,
            "active_tool_definition": active_def,
            "latency_ms": latency_ms,
            "audit_record": audit_rec
        }
