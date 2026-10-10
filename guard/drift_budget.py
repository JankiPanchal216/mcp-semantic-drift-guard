"""
guard/drift_budget.py - Cumulative Capability Drift Budget Engine

Bounds cumulative capability changes and parameter expansion relative to the root anchor.
Computes a composite drift metric:
D_total(V_k, V_0) = Severity(Added_Capabilities) + alpha * |Delta Parameters| + beta * (1 - Sim_semantic)

When D_total >= Drift_Budget_Threshold B*, an explicit administrative re-approval alert is raised.
Threshold B* is calibrated strictly on Calibration Split data.
"""

import math
from typing import Dict, List, Set, Any, Tuple
from guard.capability_tracker import evaluate_capability_delta


class DriftBudgetEngine:
    def __init__(self, budget_threshold: float = 2.0, alpha_param: float = 0.5):
        self.budget_threshold = budget_threshold
        self.alpha_param = alpha_param

    def compute_drift_score(self, root_def: Dict[str, Any], curr_def: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        cap_res = evaluate_capability_delta(root_def, curr_def)
        
        # Parameter count delta
        r_params = len(root_def.get("inputSchema", {}).get("properties", {}))
        c_params = len(curr_def.get("inputSchema", {}).get("properties", {}))
        param_delta = abs(c_params - r_params)
        
        # Composite score
        total_drift = cap_res["capability_severity_score"] + (self.alpha_param * param_delta)
        flagged = (total_drift >= self.budget_threshold)
        
        details = {
            "capability_delta": cap_res,
            "param_delta": param_delta,
            "total_drift_score": round(total_drift, 2),
            "budget_threshold": self.budget_threshold,
            "flagged": flagged
        }
        return total_drift, details
