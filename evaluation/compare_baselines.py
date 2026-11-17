"""Compare no defense, a transparent keyword filter, and the full input firewall."""

import argparse
import json
from pathlib import Path

from firewall.layers.l1_model import InjectionModel
from firewall.layers.similarity import SimilarityIndex

from .layer_report import evaluate_split
from .split_corpus import verify

ROOT = Path(__file__).resolve().parent
BASELINES = {
    "no_defense": set(),
    "keyword_filter": {"rules"},
    "layered_firewall": {"rules", "classifier", "similarity"},
}


def summarize(metrics: dict) -> dict[str, float | int]:
    row = metrics["combined"]
    return {
        "attack_count": row["attack_count"],
        "benign_count": row["benign_count"],
        "asr": 1.0 - row["detection_rate"],
        "false_positive_rate": row["false_positive_rate"],
        "p50_latency_ms": metrics["latency_ms"]["p50"],
        "p95_latency_ms": metrics["latency_ms"]["p95"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threshold", type=float, default=0.55)
    parser.add_argument("--output", type=Path, default=Path("artifacts/baseline-comparison.json"))
    args = parser.parse_args()
    if not verify():
        raise SystemExit("Locked holdout integrity check failed")
    train = json.loads((ROOT / "train" / "attacks.json").read_text(encoding="utf-8"))
    model, index = InjectionModel(), SimilarityIndex(train)
    result = {
        "scope": "offline deterministic sandbox; Prompt Guard and Llama Guard are not installed or evaluated",
        "training_data": "evaluation/train/attacks.json",
        "splits": {
            split: {
                name: summarize(evaluate_split(split, index, model, args.threshold, enabled))
                for name, enabled in BASELINES.items()
            }
            for split in ("validation", "holdout")
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    for split, rows in result["splits"].items():
        print(f"{split}:")
        for name, values in rows.items():
            print(f"  {name:<18} ASR={values['asr']:.1%} FPR={values['false_positive_rate']:.1%} "
                  f"p95={values['p95_latency_ms']:.4f} ms")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
