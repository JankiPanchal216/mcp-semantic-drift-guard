import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import json
from guard.static_rules import evaluate_static_rules
from guard.schema_security_rules import evaluate_schema_security_example
from experiments.phase3_structured_diff import compute_structured_diff
from experiments.baseline_hash_pinning import evaluate_hash_pinning_example
from experiments.baseline_embedding import EmbeddingCosineBaseline

test_path = ROOT_DIR / "data" / "drift_test.jsonl"
test_exs = [json.loads(line) for line in open(test_path, encoding="utf-8") if line.strip()]

print(f"Loaded {len(test_exs)} test examples.")

hash_fps = 0
hash_fns = 0
static_fps = 0
static_fns = 0
schema_fps = 0
schema_fns = 0

for ex in test_exs:
    expected = ex.get("expected_label")
    h_res = evaluate_hash_pinning_example(ex)
    s_res = evaluate_static_rules(ex.get("new_definition") or {}, (ex.get("structured_diff") or {}).get("description_diff_summary", ""))
    sc_res = evaluate_schema_security_example(ex)

    if expected == "BENIGN" and h_res.get("flagged"):
        hash_fps += 1
    if expected == "MALICIOUS" and not h_res.get("flagged"):
        hash_fns += 1

    if expected == "BENIGN" and s_res.get("flagged"):
        static_fps += 1
    if expected == "MALICIOUS" and not s_res.get("flagged"):
        static_fns += 1

    if expected == "BENIGN" and sc_res.get("flagged"):
        schema_fps += 1
    if expected == "MALICIOUS" and not sc_res.get("flagged"):
        schema_fns += 1

print(f"Hash Pinning (N=56): FPs={hash_fps}/23 (FPR={hash_fps/23*100:.1f}%), FNs={hash_fns}/33 (FNR={hash_fns/33*100:.1f}%)")
print(f"Static Rules (N=56): FPs={static_fps}/23 (FPR={static_fps/23*100:.1f}%), FNs={static_fns}/33 (FNR={static_fns/33*100:.1f}%)")
print(f"Schema Checks (N=56): FPs={schema_fps}/23 (FPR={schema_fps/23*100:.1f}%), FNs={schema_fns}/33 (FNR={schema_fns/33*100:.1f}%)")
