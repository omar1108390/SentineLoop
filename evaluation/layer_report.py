"""Measure rules, trained L1, TF-IDF L2, and combined detection on validation/holdout."""

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


def evaluate_split(name: str, index: SimilarityIndex, model: InjectionModel,
                   similarity_threshold: float) -> dict:
    attacks = json.loads((ROOT / name / "attacks.json").read_text(encoding="utf-8"))
    benign = json.loads((ROOT / name / "benign.json").read_text(encoding="utf-8"))
    results = {layer: {"tp": 0, "fp": 0} for layer in ("rules", "classifier", "similarity", "combined")}
    timings = []
    for label, rows in ((1, attacks), (0, benign)):
        for row in rows:
            started = perf_counter()
            rule_hit, _, _ = classify(row["prompt"])
            model_score = model.score(row["prompt"])
            similarity, nearest = index.score(row["prompt"])
            timings.append((perf_counter() - started) * 1000)
            predictions = {"rules": rule_hit, "classifier": model_score >= model.threshold,
                           "similarity": similarity >= similarity_threshold,
                           "combined": rule_hit or model_score >= model.threshold or similarity >= similarity_threshold}
            for layer, prediction in predictions.items():
                if label and prediction:
                    results[layer]["tp"] += 1
                elif not label and prediction:
                    results[layer]["fp"] += 1
    for counts in results.values():
        counts["attack_count"] = len(attacks)
        counts["benign_count"] = len(benign)
        counts["detection_rate"] = counts["tp"] / len(attacks) if attacks else 0.0
        counts["false_positive_rate"] = counts["fp"] / len(benign) if benign else 0.0
    results["latency_ms"] = {"p50": percentile(timings, 0.5), "p95": percentile(timings, 0.95)}
    results["nearest_examples"] = [
        {"id": row["id"], "similarity": index.score(row["prompt"])[0],
         "nearest_training_id": index.score(row["prompt"])[1], "classifier_score": model.score(row["prompt"])}
        for row in attacks + benign
    ]
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
