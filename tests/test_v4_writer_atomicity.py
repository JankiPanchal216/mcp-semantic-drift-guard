"""
tests/test_v4_writer_atomicity.py

Unit tests for atomic prediction writes, robust stream JSON decoding,
and recovery from interleaved stream buffer artifacts.
"""

import os
import json
import tempfile
from pathlib import Path
import unittest
from scripts.validate_and_repair_v4_predictions import parse_robust_json_stream


class TestV4WriterAtomicity(unittest.TestCase):
    def test_parse_robust_json_stream_nominal(self):
        sample_records = [
            {"item_id": "test_1", "verdict": "BENIGN", "confidence": 0.99},
            {"item_id": "test_2", "verdict": "MALICIOUS", "confidence": 0.85},
            {"item_id": "test_3", "verdict": "SUSPICIOUS", "confidence": 0.70}
        ]
        raw_text = "\n".join(json.dumps(r) for r in sample_records) + "\n"
        records, anomalies = parse_robust_json_stream(raw_text)
        self.assertEqual(len(records), 3)
        self.assertEqual(len(anomalies), 0)
        self.assertEqual([r["item_id"] for r in records], ["test_1", "test_2", "test_3"])

    def test_parse_robust_json_stream_with_corrupted_prefix_and_missing_newlines(self):
        raw_text = (
            '{"item_id": "step_1", "val": 10}\n'
            '{"it{"item_id": "step_2", "val": 20}'
            '{"item_id": "step_3", "val": 30}\n'
        )
        records, anomalies = parse_robust_json_stream(raw_text)
        self.assertEqual(len(records), 3)
        self.assertEqual([r["item_id"] for r in records], ["step_1", "step_2", "step_3"])
        self.assertGreater(len(anomalies), 0)

    def test_atomic_line_writer_integrity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_file = Path(tmpdir) / "test_atomic.jsonl"
            
            # Simulate writing 50 records atomically
            records_to_write = [{"item_id": f"record_{i}", "data": "x" * 100} for i in range(50)]
            with open(tmp_file, "w", encoding="utf-8") as f:
                for r in records_to_write:
                    line = json.dumps(r, ensure_ascii=False) + "\n"
                    f.write(line)
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except Exception:
                        pass

            # Verify exact line-by-line reading
            read_records = []
            with open(tmp_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        read_records.append(json.loads(line))

            self.assertEqual(len(read_records), 50)
            self.assertEqual([r["item_id"] for r in read_records], [f"record_{i}" for i in range(50)])


if __name__ == "__main__":
    unittest.main()
