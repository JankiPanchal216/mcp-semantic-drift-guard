"""
Phase 4 Audit Logger Module
Emits machine-readable JSONL audit logs for every tool update decision.
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional


class AuditLogger:
    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        server_id: str,
        tool_name: str,
        previous_hash: Optional[str],
        new_hash: str,
        change_detected: bool,
        structured_diff: Optional[Dict[str, Any]],
        static_rule_result: Optional[Dict[str, Any]],
        semantic_judge_result: Optional[Dict[str, Any]],
        final_verdict: str,
        action_taken: str,
        policy_mode: str,
        latency_ms: float,
        error_info: Optional[str] = None
    ) -> Dict[str, Any]:
        """Writes a structured JSON record to the JSONL log file."""
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "server_id": server_id,
            "tool_name": tool_name,
            "previous_hash": previous_hash,
            "new_hash": new_hash,
            "change_detected": change_detected,
            "structured_diff": structured_diff or {},
            "static_rules_result": static_rule_result or {},
            "semantic_judge_result": semantic_judge_result or {},
            "final_verdict": final_verdict,
            "action_taken": action_taken,
            "policy_mode": policy_mode,
            "latency_ms": round(latency_ms, 2),
            "error_info": error_info
        }

        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            print(f"[AuditLogger Error] Failed to write audit log: {e}")

        return record
