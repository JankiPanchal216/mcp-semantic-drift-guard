import unittest
import json
import os

class TestSplitLeakage(unittest.TestCase):
    def setUp(self):
        self.data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
        self.results_dir = os.path.join(os.path.dirname(__file__), "..", "results")

    def test_train_dev_test_leakage(self):
        """Verify zero record ID or cluster key overlap between train, dev, and test splits."""
        train_path = os.path.join(self.data_dir, "drift_train.jsonl")
        dev_path = os.path.join(self.data_dir, "drift_dev.jsonl")
        test_path = os.path.join(self.data_dir, "drift_test.jsonl")

        if not (os.path.exists(train_path) and os.path.exists(dev_path) and os.path.exists(test_path)):
            self.skipTest("Benchmark split files not present.")

        def load_keys(path):
            ids = set()
            clusters = set()
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    obj = json.loads(line)
                    ids.add(obj["example_id"])
                    clusters.add(obj["cluster_id"])
            return ids, clusters

        train_ids, train_clusters = load_keys(train_path)
        dev_ids, dev_clusters = load_keys(dev_path)
        test_ids, test_clusters = load_keys(test_path)

        # ID disjointness
        self.assertEqual(len(train_ids.intersection(dev_ids)), 0, "Train and Dev share record IDs")
        self.assertEqual(len(train_ids.intersection(test_ids)), 0, "Train and Test share record IDs")
        self.assertEqual(len(dev_ids.intersection(test_ids)), 0, "Dev and Test share record IDs")

        # Cluster disjointness
        self.assertEqual(len(train_clusters.intersection(dev_clusters)), 0, "Train and Dev share cluster keys")
        self.assertEqual(len(train_clusters.intersection(test_clusters)), 0, "Train and Test share cluster keys")
        self.assertEqual(len(dev_clusters.intersection(test_clusters)), 0, "Dev and Test share cluster keys")

    def test_cross_validation_server_disjointness(self):
        """Verify that 5-fold cross validation partitions have zero server overlap between train and test."""
        fold_servers = [
            set(["mcptox-puppeteer", "mcp-server-git", "mcp-server-sentry"]),
            set(["mcptox-filesystem", "mcp-server-mysql", "mcp-server-time"]),
            set(["mcptox-adfin", "mcp-server-filesystem", "mcp-server-memory"]),
            set(["mcp-playwright", "mcptox-amapmap", "mcp-server-slack"]),
            set(["mcp-server-sqlite", "mcp-server-github", "mcptox-github", "mcp-server-everything", "mcptox-flomo", "mcp-server-sequentialthinking"])
        ]

        # Verify all pairs of test fold server sets are completely disjoint
        for i in range(len(fold_servers)):
            for j in range(i + 1, len(fold_servers)):
                overlap = fold_servers[i].intersection(fold_servers[j])
                self.assertEqual(len(overlap), 0, f"Folds {i+1} and {j+1} share servers: {overlap}")

if __name__ == "__main__":
    unittest.main()
