"""
Baseline 3: Embedding / Cosine Similarity Drift Baseline (Vectorized).
Computes text embeddings of old and new tool definitions, calculates cosine similarity,
and flags updates as DRIFT / MALICIOUS when similarity drops below a learned threshold theta.
Threshold theta is calibrated strictly on Train/Dev split data (no test set tuning).
"""

import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"


class EmbeddingCosineBaseline:
    def __init__(self, threshold: float = 0.85):
        self.threshold = threshold
        self.vectorizer = TfidfVectorizer(
            analyzer='word',
            ngram_range=(1, 3),
            min_df=1,
            sublinear_tf=True
        )
        self.fitted = False

    def fit_corpus(self, text_list: List[str]):
        """Fits vectorizer on training text corpus."""
        self.vectorizer.fit(text_list)
        self.fitted = True

    def compute_similarity(self, old_text: str, new_text: str) -> float:
        """Calculates cosine similarity between old and new tool definition representations."""
        if not self.fitted:
            self.vectorizer.fit([old_text, new_text])
        
        vecs = self.vectorizer.transform([old_text, new_text])
        sim = cosine_similarity(vecs[0:1], vecs[1:2])[0][0]
        return float(sim)

    def evaluate_example(self, example: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates a single drift example using learned threshold."""
        old_d = example.get("old_definition") or {}
        new_d = example.get("new_definition") or {}

        old_text = f"{old_d.get('name', '')} {old_d.get('description', '')} {json.dumps(old_d.get('inputSchema', {}))}"
        new_text = f"{new_d.get('name', '')} {new_d.get('description', '')} {json.dumps(new_d.get('inputSchema', {}))}"

        sim = self.compute_similarity(old_text, new_text)
        flagged = (sim < self.threshold)
        
        expected = example.get("expected_label", "BENIGN")
        predicted = "MALICIOUS" if flagged else "BENIGN"

        return {
            "example_id": example.get("example_id"),
            "similarity": sim,
            "threshold": self.threshold,
            "flagged": flagged,
            "prediction": predicted,
            "expected_label": expected,
            "is_tp": (expected == "MALICIOUS" and flagged),
            "is_fp": (expected == "BENIGN" and flagged),
            "is_tn": (expected == "BENIGN" and not flagged),
            "is_fn": (expected == "MALICIOUS" and not flagged)
        }


def run_embedding_evaluation() -> Dict[str, Any]:
    train_ex = [json.loads(line) for line in open(DATA_DIR / "drift_train.jsonl", 'r', encoding='utf-8') if line.strip()]
    dev_ex = [json.loads(line) for line in open(DATA_DIR / "drift_dev.jsonl", 'r', encoding='utf-8') if line.strip()]
    test_ex = [json.loads(line) for line in open(DATA_DIR / "drift_test.jsonl", 'r', encoding='utf-8') if line.strip()]

    # Collect training corpus
    all_texts = []
    for ex in train_ex + dev_ex:
        o = ex.get("old_definition") or {}
        n = ex.get("new_definition") or {}
        all_texts.extend([
            f"{o.get('name', '')} {o.get('description', '')} {json.dumps(o.get('inputSchema', {}))}",
            f"{n.get('name', '')} {n.get('description', '')} {json.dumps(n.get('inputSchema', {}))}"
        ])

    model = EmbeddingCosineBaseline()
    model.fit_corpus(all_texts)

    # Precalculate dev similarities
    dev_sims = []
    for ex in dev_ex:
        o = ex.get("old_definition") or {}
        n = ex.get("new_definition") or {}
        old_text = f"{o.get('name', '')} {o.get('description', '')} {json.dumps(o.get('inputSchema', {}))}"
        new_text = f"{n.get('name', '')} {n.get('description', '')} {json.dumps(n.get('inputSchema', {}))}"
        sim = model.compute_similarity(old_text, new_text)
        dev_sims.append((sim, ex.get("expected_label", "BENIGN")))

    # Calibrate threshold on dev set
    best_f1 = 0.0
    best_th = 0.85

    for th in np.linspace(0.40, 0.99, 60):
        tp = sum(1 for sim, exp in dev_sims if exp == "MALICIOUS" and sim < th)
        fp = sum(1 for sim, exp in dev_sims if exp == "BENIGN" and sim < th)
        fn = sum(1 for sim, exp in dev_sims if exp == "MALICIOUS" and sim >= th)
        
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        
        if f1 > best_f1:
            best_f1 = f1
            best_th = float(th)

    # Evaluate on held-out test split
    model.threshold = best_th
    test_preds = [model.evaluate_example(ex) for ex in test_ex]
    
    tp = sum(1 for p in test_preds if p["is_tp"])
    fp = sum(1 for p in test_preds if p["is_fp"])
    tn = sum(1 for p in test_preds if p["is_tn"])
    fn = sum(1 for p in test_preds if p["is_fn"])

    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0

    return {
        "calibrated_threshold": best_th,
        "dev_best_f1": best_f1,
        "test_total": len(test_preds),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "benign_fpr": fpr,
        "malicious_fnr": fnr
    }


if __name__ == "__main__":
    res = run_embedding_evaluation()
    print("Embedding Baseline Evaluation Results on N=56 Test Split:")
    print(json.dumps(res, indent=2))
