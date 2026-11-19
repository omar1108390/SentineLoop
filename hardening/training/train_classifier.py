"""Train the L1b logistic-regression injection classifier.

Training data (never validation or holdout):

* attacks: training-split seeds, the same seeds under every mutation operator, and a
  synthetic attack set covering every family (``augment.py``, with a leak guard);
* benign: training-split benign requests, a training-only background set of
  everyday requests and hard negatives, chat-style (slang/typo) versions of them,
  and the sandbox's own documents.

During hardening, bypasses found on the training split are added as attacks.
The result is exported as plain JSON so the firewall needs no ML library.

    python -m hardening.training.train_classifier
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from firewall.layers.ml_classifier import features
from firewall.layers.similarity import attacker_texts

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "firewall" / "models" / "injection_classifier.json"
BACKGROUND = Path(__file__).with_name("benign_background.json")
CHAR_NGRAMS = (3, 5)
MAX_FEATURES = 12000


def benign_texts_of(rows: list[dict]) -> list[str]:
    texts = []
    for row in rows:
        texts.extend(row.get("turns") or [])
        texts.append(row["prompt"])
    return texts


def environment_texts() -> list[str]:
    """The sandbox's own (trusted) emails, files and pages: known-good content."""
    from target_app.tools import SandboxState

    state = SandboxState()
    return [item["body"] for item in state.emails + state.files + state.web_pages]


def training_texts(report: dict | None = None) -> tuple[list[str], list[str]]:
    from .augment import casual_benign, mutated_training_attacks, synthetic_attacks

    attacks = json.loads((ROOT / "evaluation/train/attacks.json").read_text(encoding="utf-8"))
    benign = json.loads((ROOT / "evaluation/train/benign.json").read_text(encoding="utf-8"))
    seed_texts = [text for row in attacks for text in attacker_texts(row)]
    mutated = mutated_training_attacks()
    synthetic, discarded = synthetic_attacks()
    background = json.loads(BACKGROUND.read_text(encoding="utf-8")) if BACKGROUND.is_file() else []
    benign_texts = benign_texts_of(benign) + background
    benign_texts += casual_benign(benign_texts) + environment_texts()
    attack_texts = list(dict.fromkeys(seed_texts + mutated + synthetic))
    benign_texts = list(dict.fromkeys(benign_texts))
    if report is not None:
        report.update(
            seed_attacks=len(seed_texts),
            mutated_attacks=len(mutated),
            synthetic_attacks=len(synthetic),
            synthetic_discarded_by_leak_guard=discarded,
            benign=len(benign_texts),
        )
    return attack_texts, benign_texts


def choose_threshold(model: dict, fp_cost: float = 3.0) -> float:
    """Pick the threshold on the *validation* split (never the holdout).

    Maximises ``detection_rate - fp_cost * false_positive_rate``: blocking a real
    user is treated as three times worse than missing one attack, because the
    architectural layers (quarantine, tool policy, output guard) still stand
    behind the detectors. Ties go to the higher, more conservative threshold.
    """
    from firewall.layers.ml_classifier import InjectionModel

    scorer = InjectionModel.from_dict(model)
    attacks = json.loads((ROOT / "evaluation/validation/attacks.json").read_text(encoding="utf-8"))
    benign = json.loads((ROOT / "evaluation/validation/benign.json").read_text(encoding="utf-8"))
    attack_scores = [max(scorer.score(text) for text in attacker_texts(row)) for row in attacks]
    benign_scores = [
        max(scorer.score(text) for text in (row.get("turns") or []) + [row["prompt"]]) for row in benign
    ]
    # Every email/file task also retrieves the sandbox's own documents.
    environment = max(scorer.score(text) for text in environment_texts())
    benign_scores = [max(score, environment) for score in benign_scores]
    best = (float("-inf"), 0.0)
    for step in range(50, 96, 5):
        threshold = step / 100
        fpr = sum(score >= threshold for score in benign_scores) / max(1, len(benign_scores))
        tpr = sum(score >= threshold for score in attack_scores) / max(1, len(attack_scores))
        utility = round(tpr - fp_cost * fpr, 6)
        if (utility, threshold) >= best:
            best = (utility, threshold)
    return best[1]


def choose_similarity_threshold(index_rows: list[dict], fp_cost: float = 3.0) -> float:
    """Tune the L2 similarity threshold on the validation split, like the classifier's."""
    from firewall.layers.similarity import SimilarityIndex

    index = SimilarityIndex(index_rows)
    attacks = json.loads((ROOT / "evaluation/validation/attacks.json").read_text(encoding="utf-8"))
    benign = json.loads((ROOT / "evaluation/validation/benign.json").read_text(encoding="utf-8"))
    attack_scores = [max(index.score(text)[0] for text in attacker_texts(row)) for row in attacks]
    benign_texts = benign_texts_of(benign) + environment_texts()
    benign_scores = [index.score(text)[0] for text in benign_texts]
    best = (float("-inf"), 0.0)
    for step in range(40, 91, 5):
        threshold = step / 100
        fpr = sum(score >= threshold for score in benign_scores) / max(1, len(benign_scores))
        tpr = sum(score >= threshold for score in attack_scores) / max(1, len(attack_scores))
        utility = round(tpr - fp_cost * fpr, 6)
        if (utility, threshold) >= best:
            best = (utility, threshold)
    return best[1]


def train(
    attack_texts: list[str],
    benign_texts: list[str],
    threshold: float = 0.5,
    version: str = "v0",
    source: str = "evaluation/train + mutations + synthetic attacks",
) -> dict:
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.linear_model import LogisticRegression

    texts = attack_texts + benign_texts
    labels = [1] * len(attack_texts) + [0] * len(benign_texts)
    # The analyzer is the firewall's own feature function: training and inference match exactly.
    vectorizer = CountVectorizer(
        analyzer=lambda text: sorted(features(text, True, CHAR_NGRAMS)), binary=True, min_df=2
    )
    matrix = vectorizer.fit_transform(texts)
    model = LogisticRegression(C=0.5, class_weight="balanced", max_iter=4000, random_state=42)
    model.fit(matrix, labels)
    names = vectorizer.get_feature_names_out().tolist()
    weights = model.coef_[0].tolist()
    # Keep the most influential features so the JSON stays small (about 1 MB).
    kept = sorted(zip(names, weights), key=lambda item: abs(item[1]), reverse=True)[:MAX_FEATURES]
    kept = [(name, weight) for name, weight in kept if abs(weight) >= 1e-3]
    return {
        "format": 2,
        "version": version,
        "algorithm": "binary word uni/bigram + char 3-5-gram logistic regression",
        "features": [name for name, _ in kept],
        "weights": [round(weight, 5) for _, weight in kept],
        "intercept": round(float(model.intercept_[0]), 6),
        "bigrams": True,
        "char_ngrams": list(CHAR_NGRAMS),
        "threshold": threshold,
        "train_rows": len(texts),
        "train_attacks": len(attack_texts),
        "train_benign": len(benign_texts),
        "vocabulary": len(names),
        "training_source": source,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--threshold", type=float, default=None, help="Fixed threshold (default: tune on validation)"
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report: dict = {}
    attack_texts, benign_texts = training_texts(report)
    result = train(attack_texts, benign_texts)
    result["threshold"] = args.threshold if args.threshold is not None else choose_threshold(result)
    result["threshold_source"] = "fixed" if args.threshold is not None else "validation (max TPR - 3 x FPR)"
    train_rows = json.loads((ROOT / "evaluation/train/attacks.json").read_text(encoding="utf-8"))
    result["similarity_threshold"] = choose_similarity_threshold(train_rows)
    result["data"] = report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, separators=(",", ":")), encoding="utf-8")
    print(
        f"Trained on {result['train_rows']} rows ({len(attack_texts)} attack texts, {len(benign_texts)} benign; "
        f"{report['synthetic_attacks']} synthetic, {report['synthetic_discarded_by_leak_guard']} discarded by "
        f"leak guard); {len(result['features'])} features; threshold {result['threshold']:.2f}"
    )


if __name__ == "__main__":
    main()
