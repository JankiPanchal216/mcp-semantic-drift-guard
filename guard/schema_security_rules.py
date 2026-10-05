"""
Deterministic Schema-Level Security Checker for MCP Tool Definitions.
Inspects JSON Schema modifications, parameter constraints, property additions,
default value injections (e.g. URLs, paths), and authorization metadata.
Produces structured security findings.
"""

import re
from typing import Dict, List, Any, Optional, Tuple


# Regex patterns for high-risk default values
URL_REGEX = re.compile(r'https?://[^\s"\']+|www\.[^\s"\']+', re.IGNORECASE)
SENSITIVE_PATH_REGEX = re.compile(r'(/etc/shadow|/etc/passwd|~?/\.ssh|\.aws/credentials|\.env|/var/www)', re.IGNORECASE)


def inspect_schema_security_diff(
    old_schema: Optional[Dict[str, Any]],
    new_schema: Optional[Dict[str, Any]],
    old_annotations: Optional[Dict[str, Any]] = None,
    new_annotations: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Analyzes contract schema and metadata differences between old and new tool definitions.
    Returns a list of structured security finding dicts:
      {
        "category": "SCHEMA_SECURITY_CHANGE",
        "field": field_name,
        "old": old_val,
        "new": new_val,
        "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
        "rationale": explanation_string
      }
    """
    findings = []
    
    old_schema = old_schema or {}
    new_schema = new_schema or {}
    old_annotations = old_annotations or {}
    new_annotations = new_annotations or {}

    # -------------------------------------------------------------------
    # 1. Metadata / Annotation Checks (readOnly, destructiveHint, auth)
    # -------------------------------------------------------------------
    # Check top-level or annotation readOnly toggle (True -> False)
    old_ro = old_schema.get("readOnly", old_annotations.get("readOnly", None))
    new_ro = new_schema.get("readOnly", new_annotations.get("readOnly", None))
    if old_ro is True and new_ro is False:
        findings.append({
            "category": "SCHEMA_SECURITY_CHANGE",
            "field": "annotations.readOnly",
            "old": True,
            "new": False,
            "severity": "HIGH",
            "rationale": "Tool permission escalated: readOnly toggled from true to false."
        })

    # Check destructiveHint (False -> True or True -> False)
    old_dh = old_schema.get("destructiveHint", old_annotations.get("destructiveHint", None))
    new_dh = new_schema.get("destructiveHint", new_annotations.get("destructiveHint", None))
    if old_dh != new_dh and new_dh is not None:
        findings.append({
            "category": "SCHEMA_SECURITY_CHANGE",
            "field": "annotations.destructiveHint",
            "old": old_dh,
            "new": new_dh,
            "severity": "MEDIUM",
            "rationale": f"Destructive behavior hint modified from {old_dh} to {new_dh}."
        })

    # -------------------------------------------------------------------
    # 2. Property Additions, Removals, and Modifications
    # -------------------------------------------------------------------
    old_props = old_schema.get("properties", {}) if isinstance(old_schema, dict) else {}
    new_props = new_schema.get("properties", {}) if isinstance(new_schema, dict) else {}
    if not isinstance(old_props, dict):
        old_props = {}
    if not isinstance(new_props, dict):
        new_props = {}

    old_req = set(old_schema.get("required", [])) if isinstance(old_schema.get("required"), list) else set()
    new_req = set(new_schema.get("required", [])) if isinstance(new_schema.get("required"), list) else set()

    # Check for newly added required parameters (Breaking Change / Interface Hijacking)
    newly_required = new_req - old_req
    for p in newly_required:
        findings.append({
            "category": "SCHEMA_SECURITY_CHANGE",
            "field": f"properties.{p}.required",
            "old": False,
            "new": True,
            "severity": "MEDIUM",
            "rationale": f"Parameter '{p}' was converted to a mandatory required argument."
        })

    # Check properties added
    added_props = set(new_props.keys()) - set(old_props.keys())
    for p in added_props:
        p_def = new_props[p] if isinstance(new_props[p], dict) else {}
        
        # Check if property has a default containing an external URL or sensitive path
        p_default = str(p_def.get("default", ""))
        p_desc = str(p_def.get("description", ""))

        if URL_REGEX.search(p_default):
            findings.append({
                "category": "SCHEMA_SECURITY_CHANGE",
                "field": f"properties.{p}.default",
                "old": None,
                "new": p_default,
                "severity": "CRITICAL",
                "rationale": f"New parameter '{p}' injected with default external webhook/URL destination: '{p_default}'."
            })
        elif SENSITIVE_PATH_REGEX.search(p_default):
            findings.append({
                "category": "SCHEMA_SECURITY_CHANGE",
                "field": f"properties.{p}.default",
                "old": None,
                "new": p_default,
                "severity": "CRITICAL",
                "rationale": f"New parameter '{p}' injected with default sensitive filesystem path: '{p_default}'."
            })
        elif "sudo" in p.lower() or "override" in p.lower() or "bypass" in p.lower() or "admin" in p.lower():
            if p_def.get("default") is True:
                findings.append({
                    "category": "SCHEMA_SECURITY_CHANGE",
                    "field": f"properties.{p}",
                    "old": None,
                    "new": p_def,
                    "severity": "HIGH",
                    "rationale": f"New privilege escalation parameter '{p}' added with default=True."
                })
        else:
            findings.append({
                "category": "SCHEMA_SECURITY_CHANGE",
                "field": f"properties.{p}",
                "old": None,
                "new": p_def,
                "severity": "LOW",
                "rationale": f"New parameter '{p}' added to tool input schema."
            })

    # Check properties removed (Breaking Change / Contract degradation)
    removed_props = set(old_props.keys()) - set(new_props.keys())
    for p in removed_props:
        findings.append({
            "category": "SCHEMA_SECURITY_CHANGE",
            "field": f"properties.{p}",
            "old": old_props[p],
            "new": None,
            "severity": "MEDIUM",
            "rationale": f"Existing parameter '{p}' was removed from tool schema."
        })

    # Check modified properties
    common_props = set(old_props.keys()).intersection(set(new_props.keys()))
    for p in common_props:
        op = old_props[p] if isinstance(old_props[p], dict) else {}
        np_ = new_props[p] if isinstance(new_props[p], dict) else {}

        # Check property-level readOnly toggle
        if op.get("readOnly") is True and np_.get("readOnly") is False:
            findings.append({
                "category": "SCHEMA_SECURITY_CHANGE",
                "field": f"properties.{p}.readOnly",
                "old": True,
                "new": False,
                "severity": "HIGH",
                "rationale": f"Parameter '{p}' permission relaxed: readOnly toggled from True to False."
            })

        # Check type changes (e.g. integer -> string)
        if "type" in op and "type" in np_ and op["type"] != np_["type"]:
            findings.append({
                "category": "SCHEMA_SECURITY_CHANGE",
                "field": f"properties.{p}.type",
                "old": op["type"],
                "new": np_["type"],
                "severity": "MEDIUM",
                "rationale": f"Parameter '{p}' type mutated from '{op['type']}' to '{np_['type']}'."
            })

        # Check default value modifications
        if op.get("default") != np_.get("default") and "default" in np_:
            new_def_val = str(np_["default"])
            if URL_REGEX.search(new_def_val):
                findings.append({
                    "category": "SCHEMA_SECURITY_CHANGE",
                    "field": f"properties.{p}.default",
                    "old": op.get("default"),
                    "new": np_["default"],
                    "severity": "CRITICAL",
                    "rationale": f"Parameter '{p}' default value changed to external URL: '{new_def_val}'."
                })
            elif SENSITIVE_PATH_REGEX.search(new_def_val):
                findings.append({
                    "category": "SCHEMA_SECURITY_CHANGE",
                    "field": f"properties.{p}.default",
                    "old": op.get("default"),
                    "new": np_["default"],
                    "severity": "CRITICAL",
                    "rationale": f"Parameter '{p}' default value changed to sensitive path: '{new_def_val}'."
                })
            else:
                findings.append({
                    "category": "SCHEMA_SECURITY_CHANGE",
                    "field": f"properties.{p}.default",
                    "old": op.get("default"),
                    "new": np_["default"],
                    "severity": "LOW",
                    "rationale": f"Parameter '{p}' default value changed from {op.get('default')} to {np_.get('default')}."
                })

        # Check enum changes
        old_enum = set(op.get("enum", [])) if isinstance(op.get("enum"), list) else set()
        new_enum = set(np_.get("enum", [])) if isinstance(np_.get("enum"), list) else set()
        if old_enum and new_enum and old_enum != new_enum:
            added_enums = new_enum - old_enum
            findings.append({
                "category": "SCHEMA_SECURITY_CHANGE",
                "field": f"properties.{p}.enum",
                "old": list(old_enum),
                "new": list(new_enum),
                "severity": "MEDIUM",
                "rationale": f"Parameter '{p}' allowed enum values modified. Added: {list(added_enums)}."
            })

    return findings


def evaluate_schema_security_example(example: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluates schema security checker against a single dataset example."""
    old_def = example.get("old_definition") or {}
    new_def = example.get("new_definition") or {}

    old_schema = old_def.get("inputSchema", {})
    new_schema = new_def.get("inputSchema", {})

    old_annotations = old_def.get("annotations", {})
    new_annotations = new_def.get("annotations", {})

    findings = inspect_schema_security_diff(old_schema, new_schema, old_annotations, new_annotations)
    
    severities = [f["severity"] for f in findings]
    has_critical = "CRITICAL" in severities
    has_high = "HIGH" in severities

    flagged = has_critical or has_high

    return {
        "example_id": example.get("example_id"),
        "flagged": flagged,
        "findings": findings,
        "highest_severity": "CRITICAL" if has_critical else ("HIGH" if has_high else ("MEDIUM" if "MEDIUM" in severities else ("LOW" if "LOW" in severities else "NONE")))
    }
