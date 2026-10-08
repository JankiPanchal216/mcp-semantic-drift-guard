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
        mock_judge_response: Optional[Dict[str, Any]] = None,
        anchor_mode: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Main inspection entry point for a tool definition update.
        Supports anchor modes:
          - 'adjacent' (default): compares candidate against immediate predecessor (V_{i-1})
          - 'cumulative': compares candidate against root trusted baseline (V_1)
          - 'dual': evaluates both adjacent and cumulative diffs, conservatively selecting highest risk
        Returns complete decision result dict.
        """
        mode = (anchor_mode or self.config.anchor_mode or "adjacent").lower()
        start_time = time.time()
        tool_name = new_tool_def.get("name", "unknown_tool") if new_tool_def is not None else "removed_tool"

        # Normalize & Hash new tool definition
        new_norm = normalize_tool_def(new_tool_def)
        new_hash = compute_sha256(new_norm)

        # Retrieve previous trusted definition (adjacent baseline)
        old_tool_def, trusted_hash = self.baseline_store.get_trusted_definition(server_id, tool_name)
        if tool_name == "removed_tool" and old_tool_def is not None:
            tool_name = old_tool_def.get("name", "removed_tool")

        # Retrieve root trusted baseline (V1)
        root_tool_def, root_hash = self.baseline_store.get_root_definition(server_id, tool_name)
        if root_tool_def is None:
            root_tool_def, root_hash = old_tool_def, trusted_hash

        # -------------------------------------------------------------------
        # TIER 0: Hash Comparison (Fast Path)
        # -------------------------------------------------------------------
        if mode == "adjacent" and old_tool_def is not None and trusted_hash == new_hash:
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
                "audit_record": audit_rec,
                "anchor_mode": mode
            }

        if mode == "cumulative" and root_tool_def is not None and root_hash == new_hash:
            latency_ms = (time.time() - start_time) * 1000
            audit_rec = self.audit_logger.log_event(
                server_id=server_id,
                tool_name=tool_name,
                previous_hash=root_hash,
                new_hash=new_hash,
                change_detected=False,
                structured_diff={},
                static_rule_result={"flagged": False},
                semantic_judge_result={"skipped": True, "reason": "Hash match with Root (Fast Path)"},
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
                "audit_record": audit_rec,
                "anchor_mode": mode
            }

        # -------------------------------------------------------------------
        # TIER 1: Compute Structured Diffs
        # -------------------------------------------------------------------
        diff_adj = compute_structured_diff(old_tool_def, new_tool_def)
        diff_cumul = compute_structured_diff(root_tool_def, new_tool_def)

        primary_diff = diff_adj if mode in ("adjacent", "dual") else diff_cumul

        # -------------------------------------------------------------------
        # TIER 1.5: Deterministic Schema Security Rules
        # -------------------------------------------------------------------
        old_schema = old_tool_def.get("inputSchema") if isinstance(old_tool_def, dict) else None
        root_schema = root_tool_def.get("inputSchema") if isinstance(root_tool_def, dict) else None
        new_schema = new_tool_def.get("inputSchema") if isinstance(new_tool_def, dict) else None

        findings_adj = inspect_schema_security_diff(old_schema, new_schema)
        findings_cumul = inspect_schema_security_diff(root_schema, new_schema)

        if mode == "adjacent":
            schema_flagged = any(f.get("severity") in ("CRITICAL", "HIGH") for f in findings_adj)
            active_findings = findings_adj
        elif mode == "cumulative":
            schema_flagged = any(f.get("severity") in ("CRITICAL", "HIGH") for f in findings_cumul)
            active_findings = findings_cumul
        else:  # dual mode
            schema_flagged = any(f.get("severity") in ("CRITICAL", "HIGH") for f in findings_adj + findings_cumul)
            active_findings = findings_adj if findings_adj else findings_cumul

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
                structured_diff=primary_diff,
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
                "audit_record": audit_rec,
                "anchor_mode": mode
            }

        # -------------------------------------------------------------------
        # TIER 2: Static Rules Scan
        # -------------------------------------------------------------------
        static_adj = evaluate_static_rules(new_tool_def, diff_adj.get("description_diff_summary", ""))
        static_cumul = evaluate_static_rules(new_tool_def, diff_cumul.get("description_diff_summary", ""))

        if mode == "adjacent":
            static_res = static_adj
        elif mode == "cumulative":
            static_res = static_cumul
        else:  # dual
            if static_adj.get("flagged") and static_adj.get("severity") == "high":
                static_res = static_adj
            elif static_cumul.get("flagged") and static_cumul.get("severity") == "high":
                static_res = static_cumul
            elif static_adj.get("flagged"):
                static_res = static_adj
            else:
                static_res = static_cumul

        static_flagged = static_res.get("flagged", False)

        if static_flagged and static_res.get("severity") == "high":
            action, rationale = self.policy_engine.evaluate_policy(
                verdict="MALICIOUS",
                confidence=1.0,
                static_flagged=True
            )
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
                structured_diff=primary_diff,
                static_rule_result=static_res,
                semantic_judge_result={"skipped": True, "reason": "High-severity static rule triggered"},
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
                "audit_record": audit_rec,
                "anchor_mode": mode
            }

        # -------------------------------------------------------------------
        # TIER 3: Semantic Drift Judge (Mode B Diff Only)
        # -------------------------------------------------------------------
        semantic_res = {}
        verdict = "BENIGN"
        confidence = 0.95
        error_info = None

        def _judge_diff(diff_payload: Dict[str, Any], mock_resp: Optional[Dict[str, Any]]) -> Tuple[str, float, Dict[str, Any], Optional[str]]:
            if mock_resp is not None:
                return mock_resp.get("label", "BENIGN"), mock_resp.get("confidence", 0.95), mock_resp, None
            try:
                mode_b_prompt = build_mode_b_prompt(diff_payload)
                parsed_json, raw_text, err, judge_lat = call_ollama_judge(mode_b_prompt, model_name=self.config.model_name)
                if err or not parsed_json:
                    return "ERROR", 0.5, {"error": err or "JSON parsing failed", "raw_text": raw_text, "skipped": False}, err or "JSON parsing failed"
                return parsed_json.get("label", "BENIGN"), parsed_json.get("confidence", 0.95), parsed_json, None
            except Exception as e:
                return "ERROR", 0.5, {"error": str(e), "skipped": False}, str(e)

        if mode == "adjacent":
            verdict, confidence, semantic_res, error_info = _judge_diff(diff_adj, mock_judge_response)
        elif mode == "cumulative":
            verdict, confidence, semantic_res, error_info = _judge_diff(diff_cumul, mock_judge_response)
        else:  # dual mode
            mock_adj = mock_judge_response.get("adjacent") if isinstance(mock_judge_response, dict) and "adjacent" in mock_judge_response else mock_judge_response
            mock_cumul = mock_judge_response.get("cumulative") if isinstance(mock_judge_response, dict) and "cumulative" in mock_judge_response else mock_judge_response
            
            v_adj, c_adj, s_adj, err_adj = _judge_diff(diff_adj, mock_adj)
            v_cumul, c_cumul, s_cumul, err_cumul = _judge_diff(diff_cumul, mock_cumul)

            # Conservative highest-risk selection: MALICIOUS > SUSPICIOUS / ERROR > BENIGN
            risk_map = {"MALICIOUS": 3, "SUSPICIOUS": 2, "ERROR": 2, "BENIGN": 1}
            r_adj = risk_map.get(v_adj, 1)
            r_cumul = risk_map.get(v_cumul, 1)

            if r_adj >= r_cumul:
                verdict = v_adj
                confidence = c_adj
                semantic_res = s_adj
                error_info = err_adj
            else:
                verdict = v_cumul
                confidence = c_cumul
                semantic_res = s_cumul
                error_info = err_cumul

            semantic_res["dual_evaluation"] = {
                "adjacent_verdict": v_adj,
                "adjacent_confidence": c_adj,
                "cumulative_verdict": v_cumul,
                "cumulative_confidence": c_cumul
            }

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
            self.baseline_store.update_trusted_baseline(
                server_id, tool_name, new_tool_def, reason=f"BENIGN_VERDICT ({rationale})"
            )
            active_def = new_tool_def
        else:
            self.baseline_store.record_blocked_update(
                server_id, tool_name, new_tool_def, status=verdict, reason=rationale
            )
            if old_tool_def is not None:
                active_def = old_tool_def

        latency_ms = (time.time() - start_time) * 1000

        audit_rec = self.audit_logger.log_event(
            server_id=server_id,
            tool_name=tool_name,
            previous_hash=trusted_hash,
            new_hash=new_hash,
            change_detected=True,
            structured_diff=primary_diff,
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
            "audit_record": audit_rec,
            "anchor_mode": mode
        }
