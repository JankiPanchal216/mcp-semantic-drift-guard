"""
guard/capability_tracker.py - Capability-Set Tracking & Root-Anchored Delta Auditing

Extracts fine-grained security capability sets from MCP tool definitions:
- network: HTTP, webhook, socket, URL, DNS, connect, fetch, download
- filesystem: file read, write, directory, path, temp, disk, storage
- exec: bash, shell, command, process, spawn, subprocess, run, eval
- credentials: token, api_key, password, secret, auth, ssh, aws, certificate
- auth_tls: tls, ssl, cert_verify, verify_peer, bypass_auth, insecure
- data_egress: telemetry, report_url, sync_endpoint, send_log, exfiltrate
- environment_probe: os_env, system_info, whoami, platform, hostname

A tool update flags an alert when C(V_k) \\ C(V_0) != empty (adds capabilities absent in root).
"""

import re
import json
from typing import Dict, List, Set, Any, Tuple
from pathlib import Path

CAPABILITY_TAXONOMY = {
    "network": {
        "keywords": [
            "http", "https", "url", "webhook", "socket", "network", "endpoint",
            "request", "download", "fetch", "remote", "proxy", "uri", "dns", "port", "ip_address"
        ],
        "weight": 1.5
    },
    "filesystem": {
        "keywords": [
            "file", "path", "directory", "folder", "read_file", "write_file", "append_file",
            "disk", "storage", "filesystem", "filepath", "temp_dir", "save_path", "log_file"
        ],
        "weight": 1.2
    },
    "exec": {
        "keywords": [
            "exec", "execute", "shell", "bash", "command", "cmd", "process", "subprocess",
            "spawn", "run", "eval", "system", "script", "terminal"
        ],
        "weight": 2.0
    },
    "credentials": {
        "keywords": [
            "token", "api_key", "password", "secret", "auth", "credential", "ssh", "private_key",
            "id_rsa", "shadow", "aws_key", "bearer", "authorization", "master_key"
        ],
        "weight": 2.5
    },
    "auth_tls": {
        "keywords": [
            "tls", "ssl", "cert", "certificate", "verify_ssl", "insecure", "verify_peer",
            "bypass_auth", "allow_untrusted", "skip_verify", "trust_all"
        ],
        "weight": 2.0
    },
    "data_egress": {
        "keywords": [
            "telemetry", "report_url", "sync_endpoint", "send_log", "upload_url", "exfiltrate",
            "remote_logger", "tracking_id", "external_host", "beacon"
        ],
        "weight": 2.0
    },
    "environment_probe": {
        "keywords": [
            "env", "environment", "os_env", "sysinfo", "system_info", "whoami", "hostname",
            "platform", "arch", "hardware", "cpu_info", "probe"
        ],
        "weight": 1.0
    }
}


def extract_capabilities(tool_def: Dict[str, Any]) -> Set[str]:
    """Extracts the set of capability categories present in a tool definition."""
    if not tool_def:
        return set()
    
    found_caps = set()
    
    # Collect all text strings from tool definition (name, description, schema properties, descriptions)
    text_corpus = []
    text_corpus.append(str(tool_def.get("name", "")).lower())
    text_corpus.append(str(tool_def.get("description", "")).lower())
    
    schema = tool_def.get("inputSchema", {})
    props = schema.get("properties", {})
    for p_name, p_info in props.items():
        text_corpus.append(str(p_name).lower())
        if isinstance(p_info, dict):
            text_corpus.append(str(p_info.get("description", "")).lower())
            text_corpus.append(str(p_info.get("type", "")).lower())
            
    full_text = " ".join(text_corpus)
    
    # Regex match against keywords
    for cap_name, cap_meta in CAPABILITY_TAXONOMY.items():
        for kw in cap_meta["keywords"]:
            # Word-boundary matching
            pattern = r'\b' + re.escape(kw) + r'\b'
            if re.search(pattern, full_text):
                found_caps.add(cap_name)
                break
                
    return found_caps


def evaluate_capability_delta(root_def: Dict[str, Any], curr_def: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compares current definition capabilities against root anchor.
    Flags when C(V_k) \\ C(V_0) is non-empty (new capabilities added).
    """
    root_caps = extract_capabilities(root_def)
    curr_caps = extract_capabilities(curr_def)
    
    added_caps = sorted(list(curr_caps - root_caps))
    removed_caps = sorted(list(root_caps - curr_caps))
    retained_caps = sorted(list(root_caps & curr_caps))
    
    # Calculate weighted severity score
    severity_score = sum(CAPABILITY_TAXONOMY[cap]["weight"] for cap in added_caps)
    
    flagged = len(added_caps) > 0
    
    return {
        "root_capabilities": sorted(list(root_caps)),
        "current_capabilities": sorted(list(curr_caps)),
        "added_capabilities": added_caps,
        "removed_capabilities": removed_caps,
        "retained_capabilities": retained_caps,
        "capability_severity_score": round(severity_score, 2),
        "flagged": flagged
    }
