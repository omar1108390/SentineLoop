"""Train a compact logistic-regression classifier from the train split only."""

import argparse
import json
from pathlib import Path

from firewall.layers.normalizer import normalize
from firewall.layers.l1_model import _features

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threshold", type=float, default=0.3)
    parser.add_argument("--output", type=Path, default=Path("firewall/models/injection_classifier.json"))
    args = parser.parse_args()

    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.linear_model import LogisticRegression

    attacks = json.loads((ROOT / "evaluation/train/attacks.json").read_text(encoding="utf-8"))
    benign = json.loads((ROOT / "evaluation/train/benign.json").read_text(encoding="utf-8"))
    examples = attacks + benign
    texts = [normalize(row["prompt"]) for row in examples]
    labels = [1] * len(attacks) + [0] * len(benign)
    vectorizer = CountVectorizer(binary=True, ngram_range=(1, 2), token_pattern=r"(?u)\b\w\w+\b")
    matrix = vectorizer.fit_transform(texts)
    model = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=42)
    model.fit(matrix, labels)
    feature_names = vectorizer.get_feature_names_out().tolist()
    result = {"format": 1, "algorithm": "binary unigram/bigram logistic regression",
              "features": feature_names, "weights": model.coef_[0].tolist(),
              "intercept": float(model.intercept_[0]), "bigrams": True,
              "threshold": args.threshold, "train_rows": len(examples),
              "train_attacks": len(attacks), "train_benign": len(benign),
              "training_source": "evaluation/train only"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Trained on {len(examples)} rows ({len(attacks)} attacks, {len(benign)} benign); wrote {args.output}")


if __name__ == "__main__":
    main()
