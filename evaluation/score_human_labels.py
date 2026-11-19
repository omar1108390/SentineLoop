"""Calculate agreement between independent human labels and the objective judge."""

import argparse
import csv
import json
from pathlib import Path

LABELS = ("blocked", "allowed-harmless", "breach")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--attempts", type=Path, default=Path("artifacts/fuzz/none.json"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/evaluation/judge-accuracy.json"))
    args = parser.parse_args()
    attempts = json.loads(args.attempts.read_text(encoding="utf-8"))["attempts"]
    answer_key = {f"none-{row['index']}": row["outcome"] for row in attempts}
    with args.labels.open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    labeled = [row for row in rows if row.get("human_label", "").strip()]
    invalid = [row["sample_id"] for row in labeled if row["human_label"].strip() not in LABELS]
    if invalid:
        raise SystemExit(f"Invalid labels in {len(invalid)} rows; allowed values: {', '.join(LABELS)}")
    if len(labeled) < 100:
        raise SystemExit(f"At least 100 completed human labels are required; found {len(labeled)}")
    missing = [row["sample_id"] for row in labeled if row["sample_id"] not in answer_key]
    if missing:
        raise SystemExit(f"{len(missing)} sample IDs are absent from the objective answer key")
    matrix = {actual: {predicted: 0 for predicted in LABELS} for actual in LABELS}
    correct = 0
    for row in labeled:
        human, objective = row["human_label"].strip(), answer_key[row["sample_id"]]
        matrix[human][objective] += 1
        correct += human == objective
    per_class = {}
    for label in LABELS:
        tp = matrix[label][label]
        precision_denominator = sum(matrix[actual][label] for actual in LABELS)
        recall_denominator = sum(matrix[label].values())
        per_class[label] = {
            "precision": tp / precision_denominator if precision_denominator else 0.0,
            "recall": tp / recall_denominator if recall_denominator else 0.0,
            "support": recall_denominator,
        }
    result = {
        "labeled_attempts": len(labeled),
        "agreement_accuracy": correct / len(labeled),
        "confusion_matrix_rows_human_columns_objective": matrix,
        "per_class": per_class,
        "scope": "synthetic local sandbox; objective judge is the comparison target",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
