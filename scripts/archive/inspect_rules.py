import json
from pathlib import Path

data_path = Path("results/DECISION_RULE_AUDIT_DATA.json")
with open(data_path, "r", encoding="utf-8") as f:
    d = json.load(f)

for cfg, strats in d["configurations"].items():
    print("=" * 60)
    print("CONFIG:", cfg)
    print("=" * 60)
    for s, m in strats.items():
        t = m["transition"]
        sal = m["chain_salami_only"]
        fast = m["chain_fast_jump"]
        allm = m["chain_all_malicious"]
        ben = m["chain_benign"]
        print(f"  Strategy: {s}")
        print(f"    Transitions: TP={t['tp']}, TN={t['tn']}, FP={t['fp']}, FN={t['fn']} | Recall={t['recall']*100:.1f}%, FPR={t['fpr']*100:.1f}%")
        print(f"    Chains Salami:   {sal['detected']}/{sal['n']} ({sal['recall']*100:.1f}%) | Exp={sal['mean_exposure']:.3f}")
        print(f"    Chains FastJump: {fast['detected']}/{fast['n']} ({fast['recall']*100:.1f}%) | Exp={fast['mean_exposure']:.3f}")
        print(f"    Chains All Mal:  {allm['detected']}/{allm['n']} ({allm['recall']*100:.1f}%) | Exp={allm['mean_exposure']:.3f}")
        print(f"    Chains Benign:   {ben['flagged']}/{ben['n']} ({ben['fpr']*100:.1f}%)")

print("\nFALLBACK DETAILS:")
print(json.dumps(d["fallbacks"], indent=2))
