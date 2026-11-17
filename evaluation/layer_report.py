"""Measure rules, trained L1, TF-IDF L2, and combined detection on validation/locked holdout."""

import argparse
import json
import math
from pathlib import Path
from time import perf_counter

from firewall.layers.classifier import classify
from firewall.layers.l1_model import InjectionModel
from firewall.layers.similarity import SimilarityIndex

from .split_corpus import verify

ROOT = Path(__file__).resolve().parent


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def score_row(row: dict, index: SimilarityIndex, model: InjectionModel, threshold: float,
              enabled_layers: set[str] | None = None) -> tuple[dict, float]:
    prompts = row.get("turns") or [row["prompt"]]
    enabled = enabled_layers if enabled_layers is not None else {"rules", "classifier", "similarity"}
    start = perf_counter()
    rule_hit = similarity_hit = False
    model_score, similarity, nearest = 0.0, 0.0, ""
    for prompt in prompts:
        if "rules" in enabled:
            matched, _, _ = classify(prompt)
            rule_hit = rule_hit or matched
        if "classifier" in enabled:
            score = model.score(prompt)
            model_score = max(model_score, score)
        if "similarity" in enabled:
            score, example = index.score(prompt)
            if score > similarity:
                similarity, nearest = score, example
    elapsed = (perf_counter() - start) * 1000
    similarity_hit = similarity >= threshold
    return {"rules": rule_hit, "classifier": model_score >= model.threshold,
            "similarity": similarity_hit,
            "combined": rule_hit or model_score >= model.threshold or similarity_hit,
            "classifier_score": model_score, "similarity_score": similarity,
            "nearest_training_id": nearest}, elapsed


def evaluate_split(name: str, index: SimilarityIndex, model: InjectionModel,
                   similarity_threshold: float, enabled_layers: set[str] | None = None) -> dict:
    attacks = json.loads((ROOT / name / "attacks.json").read_text(encoding="utf-8"))
    benign = json.loads((ROOT / name / "benign.json").read_text(encoding="utf-8"))
    results = {layer: {"tp": 0, "fp": 0} for layer in ("rules", "classifier", "similarity", "combined")}
    timings, nearest_examples = [], []
    for label, rows in ((1, attacks), (0, benign)):
        for row in rows:
            predictions, elapsed = score_row(row, index, model, similarity_threshold, enabled_layers)
            timings.append(elapsed)
            nearest_examples.append({"id": row["id"], **{key: predictions[key] for key in
                                      ("classifier_score", "similarity_score", "nearest_training_id")}})
            for layer in results:
                if label and predictions[layer]:
                    results[layer]["tp"] += 1
                elif not label and predictions[layer]:
                    results[layer]["fp"] += 1
    for counts in results.values():
        counts["attack_count"] = len(attacks)
        counts["benign_count"] = len(benign)
        counts["detection_rate"] = counts["tp"] / len(attacks) if attacks else 0.0
        counts["false_positive_rate"] = counts["fp"] / len(benign) if benign else 0.0
    results["latency_ms"] = {"p50": percentile(timings, 0.5), "p95": percentile(timings, 0.55)}
    results["nearest_examples"] = nearest_examples
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threshold", type=float, default=0.55)
    parser.add_argument("--output", type=Path, default=Path("artifacts/layer-evaluation.json"))
    args = parser.parse_args()
    if not verify():
        raise SystemExit("Locked holdout integrity check failed")
    train = json.loads((ROOT / "train" / "attacks.json").read_text(encoding="utf-8"))
    model = InjectionModel()
    index = SimilarityIndex(train)
    result = {"index_source": "evaluation/train/attacks.json", "classifier_source": "evaluation/train only",
              "classifier_threshold": model.threshold, "similarity_threshold": args.threshold,
              "validation": evaluate_split("validation", index, model, args.threshold),
              "holdout": evaluate_split("holdout", index, model, args.threshold)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    for split in ("validation", "holdout"):
        metrics = result[split]
        print(f"{split}: L1 classifier {metrics['classifier']['detection_rate']:.1%}/{metrics['classifier']['false_positive_rate']:.1%}; "
              f"L2 similarity {metrics['similarity']['detection_rate']:.1%}/{metrics['similarity']['false_positive_rate']:.1%}; "
              f"combined {metrics['combined']['detection_rate']:.1%}/{metrics['combined']['false_positive_rate']:.1%}; "
              f"p95 {metrics['latency_ms']['p95']:.4f} ms")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
