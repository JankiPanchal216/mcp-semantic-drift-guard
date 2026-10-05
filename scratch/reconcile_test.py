import json
from pathlib import Path

test_path = Path("data/drift_test.jsonl")
test_exs = [json.loads(line) for line in open(test_path, encoding="utf-8") if line.strip()]
print(f"Total test examples: {len(test_exs)}")

benign = [ex for ex in test_exs if ex.get("expected_label") == "BENIGN"]
malicious = [ex for ex in test_exs if ex.get("expected_label") == "MALICIOUS"]

print(f"Benign: {len(benign)}, Malicious: {len(malicious)}")

print("\n--- All 23 Benign Test Examples ---")
for i, b in enumerate(benign, 1):
    print(f"{i:2d}. ID: {b.get('example_id')} | Server: {b.get('server_id')} | Tool: {b.get('tool_name')} | Change: {b.get('change_type')} | Source: {b.get('source')}")

print("\n--- All 33 Malicious Test Examples ---")
for i, m in enumerate(malicious, 1):
    print(f"{i:2d}. ID: {m.get('example_id')} | Server: {m.get('server_id')} | Tool: {m.get('tool_name')} | Change: {m.get('change_type')} | Paradigm: {m.get('paradigm')}")
