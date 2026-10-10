"""
tests/test_stats.py - Unit tests for statistical testing and McNemar exact verification.
"""

import unittest
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scripts.stats import (
    mcnemar_exact,
    load_v3_metrics,
    compute_chain_level_contingency,
    run_cluster_bootstrap
)


class TestStatsModule(unittest.TestCase):
    
    def test_mcnemar_exact_edge_cases(self):
        # Zero discordant pairs -> p = 1.0
        self.assertEqual(mcnemar_exact(0, 0), 1.0)
        # Equal discordant pairs (symmetric)
        self.assertAlmostEqual(mcnemar_exact(5, 5), 1.0)
        # Highly asymmetric discordant pairs (0 vs 8) -> 2 * (0.5^8) = 2/256 = 0.0078125
        p = mcnemar_exact(0, 8)
        self.assertAlmostEqual(p, 0.0078125, places=5)

    def test_transition_mcnemar_reproduction(self):
        metrics = load_v3_metrics()
        trans_adj_cum = metrics["comparisons"]["mcnemar_adjacent_vs_cumulative"]
        trans_adj_dual = metrics["comparisons"]["mcnemar_adjacent_vs_dual"]
        
        # Verify exact reproduction of frozen benchmark p-values
        self.assertAlmostEqual(trans_adj_cum["mcnemar_exact_p_value"], 0.21011, places=4)
        self.assertAlmostEqual(trans_adj_dual["mcnemar_exact_p_value"], 0.02246, places=4)

    def test_chain_level_mcnemar_malicious(self):
        metrics = load_v3_metrics()
        chains_adj = metrics["strategy_metrics"]["adjacent"]["chain_summaries"]
        chains_dual = metrics["strategy_metrics"]["dual"]["chain_summaries"]
        
        res = compute_chain_level_contingency(chains_adj, chains_dual, malicious_only=True)
        # 14 both correct, 0 adj only, 8 dual only, 2 neither
        self.assertEqual(res["contingency_table"]["both_correct"], 14)
        self.assertEqual(res["contingency_table"]["a_correct_only"], 0)
        self.assertEqual(res["contingency_table"]["b_correct_only"], 8)
        self.assertEqual(res["contingency_table"]["both_incorrect"], 2)
        self.assertAlmostEqual(res["mcnemar_exact_p_value"], 0.00781, places=4)

    def test_cluster_bootstrap_reproducibility(self):
        metrics = load_v3_metrics()
        boot_res = run_cluster_bootstrap(metrics, n_bootstraps=500, seed=42)
        adj_rec = boot_res["strategy_bootstrap_summary"]["adjacent"]["chain_recall"]["mean"]
        dual_rec = boot_res["strategy_bootstrap_summary"]["dual"]["chain_recall"]["mean"]
        
        # Dual recall should substantially exceed adjacent recall
        self.assertGreater(dual_rec, adj_rec)
        self.assertAlmostEqual(adj_rec, 0.5833, delta=0.03)
        self.assertAlmostEqual(dual_rec, 0.9167, delta=0.03)


    def test_benign_chain_transition_flag_consistency(self):
        """Asserts that number of benign chains flagged >= 1 whenever any transition in a benign chain is flagged,
        and matches the exact number of unique benign chains containing flagged transitions."""
        from scripts.audit_decision_rules import load_jsonl, evaluate_metrics, group_by_chain, PREDS_PER_STEP, PREDS_CUMULATIVE, PREDS_DUAL
        
        rule_a = lambda p: (p.get("predicted_label") == "MALICIOUS" or p.get("verdict") == "MALICIOUS" or p.get("action") == "BLOCK")
        rule_b = lambda p: (p.get("predicted_label") in ("MALICIOUS", "SUSPICIOUS") or p.get("action") in ("BLOCK", "WARN") or p.get("verdict") != "BENIGN")
        
        for path, strat_name in [(PREDS_PER_STEP, "adjacent"), (PREDS_CUMULATIVE, "cumulative"), (PREDS_DUAL, "dual")]:
            preds = load_jsonl(path)
            chains_dict = group_by_chain(preds)
            benign_cids = set(cid for cid, steps in chains_dict.items() if not any(s["gold_label"] == "MALICIOUS" for s in steps))
            
            for rule_fn, rule_name, excl_fb in [
                (rule_a, "rule_a_mal_only", False),
                (rule_b, "rule_b_primary", False),
                (rule_b, "rule_c_parsed_only", True)
            ]:
                filtered = [p for p in preds if not p.get("parse_error")] if excl_fb else preds
                # Transitions belonging to benign chains
                benign_chain_trans = [p for p in filtered if p["chain_id"] in benign_cids]
                flagged_benign_trans = [p for p in benign_chain_trans if rule_fn(p)]
                unique_flagged_cids = set(p["chain_id"] for p in flagged_benign_trans)
                
                m = evaluate_metrics(preds, rule_fn, strict_step_ge_m=True, exclude_fallbacks=excl_fb)
                benign_chains_flagged = m["chain_benign"]["flagged"]
                
                # Assert mathematical consistency
                if len(flagged_benign_trans) > 0:
                    self.assertGreaterEqual(benign_chains_flagged, 1, f"Failed >= 1 check for {strat_name} under {rule_name}")
                else:
                    self.assertEqual(benign_chains_flagged, 0, f"Failed 0 check for {strat_name} under {rule_name}")
                self.assertEqual(benign_chains_flagged, len(unique_flagged_cids), f"Chain count mismatch for {strat_name} under {rule_name}")



if __name__ == "__main__":
    unittest.main()

