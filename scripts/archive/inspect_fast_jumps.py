import json
from pathlib import Path

for strat, filename in [
    ("Cumulative", "results/salami_drift_v3_cumulative/predictions.jsonl"),
    ("Dual", "results/salami_drift_v3_dual/predictions.jsonl"),
    ("Adjacent", "results/salami_drift_v3_per_step/predictions.jsonl"),
]:
    print("=" * 70)
    print(f"STRATEGY: {strat}")
    print("=" * 70)
    with open(filename, "r", encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    
    cat_b = [l for l in lines if l.get("category") == "B_adjacent_detectable"]
    chains = {}
    for l in cat_b:
        chains.setdefault(l["chain_id"], []).append(l)
        
    for cid in sorted(chains.keys()):
        steps = sorted(chains[cid], key=lambda x: x["step_index"])
        print(f"\n--- Chain {cid} ---")
        for s in steps:
            st = s["step_index"]
            gold = s["gold_label"]
            pred = s.get("predicted_label")
            raw_v = s.get("raw_verdict")
            parsed_v = s.get("parsed_verdict")
            action = s.get("action")
            parse_err = s.get("parse_error")
            err_msg = s.get("error_message")
            resp = s.get("response", "")[:120] if s.get("response") else ""
            print(f"  Step {st} [{gold}]: pred={pred}, raw={raw_v}, parsed={parsed_v}, action={action}, parse_err={parse_err}")
            if parse_err:
                print(f"    Parse Error: {err_msg}")
                print(f"    Raw Response: {repr(resp)}")
            elif gold == "MALICIOUS" and pred == "BENIGN":
                print(f"    Judge Miss (Wrong Verdict): Response snippet: {repr(resp)}")
