"""
Phase 4 Guard Configuration Module
Manages environment settings, policy modes, timeouts, and DB file paths.
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent

class GuardConfig:
    def __init__(
        self,
        policy_mode: str = "BALANCED",
        ollama_url: str = "http://localhost:11434/api/chat",
        model_name: str = "qwen3:8b",
        temperature: float = 0.0,
        llm_timeout: int = 60,
        fail_safe_mode: str = "FAIL_CLOSED_ON_MALICIOUS",
        baseline_db_path: Optional[Path] = None,
        audit_log_path: Optional[Path] = None
    ):
        self.policy_mode = policy_mode.upper()  # STRICT, BALANCED, AUDIT
        self.ollama_url = ollama_url
        self.model_name = model_name
        self.temperature = temperature
        self.llm_timeout = llm_timeout
        self.fail_safe_mode = fail_safe_mode.upper()
        
        self.baseline_db_path = baseline_db_path or (ROOT_DIR / "data" / "trusted_baselines.db")
        self.audit_log_path = audit_log_path or (ROOT_DIR / "results" / "phase4_audit_log.jsonl")

        os.makedirs(self.baseline_db_path.parent, exist_ok=True)
        os.makedirs(self.audit_log_path.parent, exist_ok=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_mode": self.policy_mode,
            "ollama_url": self.ollama_url,
            "model_name": self.model_name,
            "temperature": self.temperature,
            "llm_timeout": self.llm_timeout,
            "fail_safe_mode": self.fail_safe_mode,
            "baseline_db_path": str(self.baseline_db_path),
            "audit_log_path": str(self.audit_log_path)
        }

    @classmethod
    def load_default(cls) -> "GuardConfig":
        config_file = ROOT_DIR / "config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return cls(
                        policy_mode=data.get("policy_mode", "BALANCED"),
                        ollama_url=data.get("ollama_url", "http://localhost:11434/api/chat"),
                        model_name=data.get("model_name", "qwen3:8b"),
                        temperature=data.get("temperature", 0.0),
                        llm_timeout=data.get("llm_timeout", 60),
                        fail_safe_mode=data.get("fail_safe_mode", "FAIL_CLOSED_ON_MALICIOUS")
                    )
            except Exception:
                pass
        return cls()
