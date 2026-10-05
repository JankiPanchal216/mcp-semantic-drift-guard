"""
Trace Exporter Utility for MCP Semantic Drift Experiments.
Streams standardized per-item prediction rows with real timing measurements, host hardware, and 40-char commit hash.

Unified Schema:
item_id, server_id, tool_name, gold_label, predicted_label, deciding_tier, llm_called, latency_ms_total, latency_ms_llm, model, hardware, run_id, source_file, export_commit
"""

import os
import json
import time
import uuid
import platform
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, Union

DEFAULT_COMMIT = "381125b09dee2d05f23e170e32762a71f815305d"


def get_git_commit() -> str:
    """Returns the current 40-character git commit hash."""
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL)
        commit = out.decode("utf-8").strip()
        if len(commit) == 40:
            return commit
    except Exception:
        pass
    return DEFAULT_COMMIT


def get_hardware_info() -> str:
    """Captures CPU and GPU platform specification."""
    cpu_str = f"{platform.system()}-{platform.release()} {platform.machine()} ({platform.processor()})"
    gpu_info = "0 NVIDIA GPUs"
    try:
        out = subprocess.check_output(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"], stderr=subprocess.DEVNULL)
        gpus = out.decode("utf-8").strip().splitlines()
        if gpus:
            gpu_info = "; ".join(gpus)
    except Exception:
        pass
    return f"{cpu_str} [{gpu_info}]"


class TraceWriter:
    """Appends validated per-item prediction records to a JSONL file."""

    def __init__(self, output_path: Path, source_file: str, run_id: Optional[str] = None):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.source_file = source_file
        self.export_commit = get_git_commit()
        self.hardware = get_hardware_info()
        self.run_id = run_id or f"run_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        self.file_handle = open(self.output_path, "w", encoding="utf-8")

    def write_item(
        self,
        item_id: str,
        server_id: str,
        tool_name: str,
        gold_label: str,
        predicted_label: str,
        deciding_tier: Union[int, float, str],
        llm_called: bool,
        latency_ms_total: float,
        latency_ms_llm: Optional[float] = None,
        model: str = "none"
    ) -> Dict[str, Any]:
        """Writes a single validated JSONL trace row."""
        # Normalize deciding_tier to 0, 1, 1.5, 2, 3 or "none"
        tier_val = deciding_tier
        if tier_val in ("none", "None", None, ""):
            tier_val = "none"
        elif tier_val in (0, "0", "0.0", "Tier 0", "Tier 0 (Hash Fast-Path)", "Tier 0 (Hash Pinning)"):
            tier_val = 0
        elif tier_val in (1, "1", "1.0", "Tier 1", "Tier 1 (Diff)"):
            tier_val = 1
        elif tier_val in (1.5, "1.5", "Tier 1.5", "Tier 1.5 (Schema Rules)", "Tier 1.5 (Schema Security Rules)"):
            tier_val = 1.5
        elif tier_val in (2, "2", "2.0", "Tier 2", "Tier 2 (Static Rules)", "Tier 2 (Static Regex)"):
            tier_val = 2
        elif tier_val in (3, "3", "3.0", "Tier 3", "Tier 3 (Semantic Judge Mode A)", "Tier 3 (Semantic Judge Mode B)"):
            tier_val = 3

        row = {
            "item_id": str(item_id),
            "server_id": str(server_id),
            "tool_name": str(tool_name),
            "gold_label": str(gold_label).upper(),
            "predicted_label": str(predicted_label).upper(),
            "deciding_tier": tier_val,
            "llm_called": bool(llm_called),
            "latency_ms_total": float(round(latency_ms_total, 4)),
            "latency_ms_llm": float(round(latency_ms_llm, 4)) if latency_ms_llm is not None else None,
            "model": str(model),
            "hardware": self.hardware,
            "run_id": self.run_id,
            "source_file": str(self.source_file),
            "export_commit": self.export_commit
        }
        self.file_handle.write(json.dumps(row) + "\n")
        self.file_handle.flush()
        return row

    def close(self):
        if self.file_handle and not self.file_handle.closed:
            self.file_handle.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
