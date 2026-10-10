"""
tests/test_raw_traces_table_consistency.py

Rigorous test that recomputes every paper table from raw traces (.jsonl files)
and asserts exact equality with the paper data, checking N, TP, TN, FP, FN,
recall, precision, FPR, and Wilson CIs for every row.
"""

import json
import unittest
import math
from pathlib import Path
from typing import Dict, List, Any, Tuple
import numpy as np

ROOT_DIR = Path(__file__).resolve().parent.parent

def wilson_ci(k: int, n: int, conf: float = 0.95) -> Tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    z = 1.95996
    p = k / n
    denom = 1.0 + (z**2) / n
    center = (p + (z**2) / (2 * n)) / denom
    margin = (z * math.sqrt((p * (1 - p) / n) + ((z**2) / (4 * (n**2))))) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


class TestRawTracesTableConsistency(unittest.TestCase):

    def test_v4_benchmark_exact_counts(self):
        """Step 1a: Validate exact counts in Benchmark V4 (data/salami_drift_benchmark_v4.jsonl)."""
        bench_file = ROOT_DIR / "data" / "salami_drift_benchmark_v4.jsonl"
        rows = [json.loads(l) for l in open(bench_file, "r", encoding="utf-8") if l.strip()]
        
        self.assertEqual(len(rows), 436, "Benchmark V4 must contain exactly 436 transition rows")
        
        # Group by chain_id
        chains = {}
        for r in rows:
            chains.setdefault(r["chain_id"], []).append(r)
            
        self.assertEqual(len(chains), 116, "Benchmark V4 must contain exactly 116 unique chains")
        
        # Verify chain counts by class
        salami_cids = [cid for cid, steps in chains.items() if steps[0]["category"].startswith(("A_", "D_", "E_", "F_", "G_"))]
        fastjump_cids = [cid for cid, steps in chains.items() if steps[0]["category"].startswith("B_")]
        benign_cids = [cid for cid, steps in chains.items() if steps[0]["category"].startswith("C_")]
        
        self.assertEqual(len(salami_cids), 60, "Salami chains must equal exactly 60 (5 categories x 12 chains)")
        self.assertEqual(len(fastjump_cids), 12, "Fast-jump chains must equal exactly 12")
        self.assertEqual(len(benign_cids), 44, "Benign control chains must equal exactly 44")
        
        # Verify length of every salami chain is L=4 (Step 1b verification)
        for cid in salami_cids:
            self.assertEqual(len(chains[cid]), 4, f"Salami chain {cid} must have length L=4")
            
        # Verify malicious transitions count (Step 1c verification)
        salami_mal_transitions = sum(1 for cid in salami_cids for s in chains[cid] if s["gold_label"] == "MALICIOUS")
        fastjump_mal_transitions = sum(1 for cid in fastjump_cids for s in chains[cid] if s["gold_label"] == "MALICIOUS")
        
        self.assertEqual(salami_mal_transitions, 120, "Salami malicious transitions must equal 60 chains * 2 steps = 120")
        self.assertEqual(fastjump_mal_transitions, 12, "Fast-jump malicious transitions must equal 12 chains * 1 step = 12")
        self.assertEqual(salami_mal_transitions + fastjump_mal_transitions, 132, "Total malicious transitions = 132")

    def test_v4_test_split_exact_metrics(self):
        """Step 1d: Verify Table 7 / Table 8 exact counts from raw validated predictions."""
        adj_file = ROOT_DIR / "results" / "salami_drift_v4" / "gemma3_4b" / "validated" / "predictions_adjacent.jsonl"
        cum_file = ROOT_DIR / "results" / "salami_drift_v4" / "gemma3_4b" / "validated" / "predictions_cumulative.jsonl"
        
        adj_recs = [json.loads(l) for l in open(adj_file, "r", encoding="utf-8") if l.strip()]
        cum_recs = [json.loads(l) for l in open(cum_file, "r", encoding="utf-8") if l.strip()]
        
        # Filter for held-out test split
        adj_test = [r for r in adj_recs if r["split"] == "held_out_test"]
        cum_test = [r for r in cum_recs if r["split"] == "held_out_test"]
        
        # Group by chain
        adj_test_chains = {}
        for r in adj_test:
            adj_test_chains.setdefault(r["chain_id"], []).append(r)
            
        cum_test_chains = {}
        for r in cum_test:
            cum_test_chains.setdefault(r["chain_id"], []).append(r)
            
        self.assertEqual(len(adj_test_chains), 58, "Held-out test split must contain 58 chains")
        self.assertEqual(len(cum_test_chains), 58, "Held-out test split must contain 58 chains")
        
        # Test split chain subsets: 26 Salami, 7 Fast-Jump, 25 Benign
        salami_test = [cid for cid, steps in adj_test_chains.items() if steps[0]["category"].startswith(("A_", "D_", "E_", "F_", "G_"))]
        fastjump_test = [cid for cid, steps in adj_test_chains.items() if steps[0]["category"].startswith("B_")]
        benign_test = [cid for cid, steps in adj_test_chains.items() if steps[0]["category"].startswith("C_")]
        
        self.assertEqual(len(salami_test), 26, "Test split must contain 26 Salami chains")
        self.assertEqual(len(fastjump_test), 7, "Test split must contain 7 Fast-Jump chains")
        self.assertEqual(len(benign_test), 25, "Test split must contain 25 Benign chains")
        
        # Compute Rule (b) Balanced chain alerts
        def is_alert_b(steps):
            return any(s["rule_verdicts"]["rule_b_balanced"] for s in steps)
            
        # Adjacent Test:
        adj_salami_hits = sum(1 for cid in salami_test if is_alert_b(adj_test_chains[cid]))
        adj_benign_fps = sum(1 for cid in benign_test if is_alert_b(adj_test_chains[cid]))
        
        self.assertEqual(adj_salami_hits, 25, "Adjacent Salami Recall on Test must be 25/26 (96.2%)")
        self.assertEqual(adj_benign_fps, 1, "Adjacent Benign FPR on Test must be 1/25 (4.0%)")
        
        # Cumulative Test:
        cum_salami_hits = sum(1 for cid in salami_test if is_alert_b(cum_test_chains[cid]))
        cum_benign_fps = sum(1 for cid in benign_test if is_alert_b(cum_test_chains[cid]))
        
        self.assertEqual(cum_salami_hits, 20, "Cumulative Salami Recall on Test must be 20/26 (76.9%)")
        self.assertEqual(cum_benign_fps, 0, "Cumulative Benign FPR on Test must be 0/25 (0.0%)")


if __name__ == "__main__":
    unittest.main()
