"""Export a deterministic, blinded sample for independent human outcome labels."""

import argparse
import csv
import json
import random
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def choose_sample(records: list[dict], count: int, seed: int) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in records:
        groups[row["family"]].append(row)
    rng = random.Random(seed)
    families = sorted(groups)
    for family in families:
        rng.shuffle(groups[family])
    sample = []
    while len(sample) < min(count, len(records)):
        advanced = False
        for family in families:
            if groups[family] and len(sample) < count:
                sample.append(groups[family].pop())
                advanced = True
        if not advanced:
            break
    return sample


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("artifacts/baseline.json"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/judge-labels.csv"))
    parser.add_argument("--count", type=int, default=120)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()
    if args.count < 100:
        raise SystemExit("Human judge validation needs at least 100 attempts")
    data = json.loads(args.input.read_text(encoding="utf-8"))
    rows = choose_sample(data["attempts"], args.count, args.seed)
    if len(rows) < 100:
        raise SystemExit(f"Only {len(rows)} attempts are available; run the baseline fuzzer first")
    fields = (
        "sample_id", "family", "technique", "prompt", "turns", "response", "tool_calls",
        "state_changed", "human_label", "annotator", "notes",
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "sample_id": f"baseline-{row['index']}",
                    "family": row["family"],
                    "technique": row["technique"],
                    "prompt": row["prompt"],
                    "turns": row["turns"],
                    "response": row.get("response", ""),
                    "tool_calls": row.get("tool_calls", "[]"),
                    "state_changed": row.get("state_changed", "false"),
                    "human_label": "",
                    "annotator": "",
                    "notes": "",
                }
            )
    print(f"Wrote {len(rows)} blinded annotation rows to {args.output}")


if __name__ == "__main__":
    main()
