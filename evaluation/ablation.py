"""Measure input-detector ablations on validation and locked holdout splits."""

import argparse
import json
from pathlib import Path

from firewall.layers.l1_model import InjectionModel
from firewall.layers.similarity import SimilarityIndex
from .layer_report import evaluate_split
from .split_corpus import verify

ROOT = Path(__file__).resolve().parent
LAYERS = ("rules", "classifier", "similarity")
CONFIGURATIONS = {
    "all": set(LAYERS),
    "without_rules": set(LAYERS) - {"rules"},
    "without_classifier": set(LAYERS) - {"classifier"},
    "without_similarity": set(LAYERS) - {"similarity"},
    "none": set(),
}


def summarize(metrics: dict) -> dict[str, float | int]:
    combined = metrics["combined"]
    return {
        "attack_count": combined["attack_count"],
        "benign_count": combined["benign_count"],
        "detected_attacks": combined["tp"],
        "blocked_benign": combined["fp"],
        "asr": 1.0 - combined["detection_rate"],
        "detection_rate": combined["detection_rate"],
        "false_positive_rate": combined["false_positive_rate"],
        "p50_latency_ms": metrics["latency_ms"]["p50"],
        "p95_latency_ms": metrics["latency_ms"]["p95"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threshold", type=float, default=0.55)
    parser.add_argument("--output", type=Path, default=Path("artifacts/ablation.json"))
    args = parser.parse_args()
    if not verify():
        raise SystemExit("Locked holdout integrity check failed")
    attacks = json.loads((ROOT / "train" / "attacks.json").read_text(encoding="utf-8"))
    model = InjectionModel()
    index = SimilarityIndex(attacks)
    result = {
        "scope": "input detectors only; excludes output redaction and tool-policy enforcement",
        "layers": list(LAYERS),
        "similarity_threshold": args.threshold,
        "classifier_threshold": model.threshold,
        "splits": {},
    }
    for split in ("validation", "holdout"):
        result["splits"][split] = {
            name: summarize(evaluate_split(split, index, model, args.threshold, enabled))
            for name, enabled in CONFIGURATIONS.items()
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    for split, rows in result["splits"].items():
        print(f"{split}:")
        for name, values in rows.items():
            print(f"  {name:<20} ASR={values['asr']:.1%} FPR={values['false_positive_rate']:.1%} "
                  f"p95={values['p95_latency_ms']:.4f} ms")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
