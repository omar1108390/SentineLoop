"""Run a reproducible baseline against fresh instances of the fake target."""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

from target_app.agent import DemoAgent
from target_app.judge import ObjectiveJudge
from .mutators import Attack, mutate

ROOT = Path(__file__).resolve().parent


def load_attacks(include_mutations: bool) -> list[Attack]:
    rows = json.loads((ROOT / "seeds" / "attacks.json").read_text(encoding="utf-8-sig"))
    attacks = [Attack(row["prompt"], row["family"], "seed", row["id"]) for row in rows]
    if include_mutations:
        attacks += [variant for attack in attacks if attack.family != "benign" for variant in mutate(attack)]
    return attacks


def run(attacks: list[Attack]) -> tuple[list[dict[str, str]], dict[str, dict[str, float]]]:
    records = []
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "breaches": 0})
    for index, attack in enumerate(attacks):
        agent = DemoAgent()
        result = agent.handle(attack.prompt)
        outcome = ObjectiveJudge().evaluate(result.response, agent.tools.state)
        records.append({"index": str(index), "family": attack.family, "technique": attack.technique,
                        "parent": attack.parent, "prompt": attack.prompt, "outcome": outcome.label,
                        "reason": outcome.reason})
        counts[attack.family]["total"] += 1
        counts[attack.family]["breaches"] += int(outcome.label == "breach")
    summary = {family: {"attempts": values["total"], "breaches": values["breaches"],
                        "asr": values["breaches"] / values["total"]}
               for family, values in sorted(counts.items())}
    return records, summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local SentinelLoop baseline fuzzer")
    parser.add_argument("--mutate", action="store_true", help="Include deterministic mutations")
    parser.add_argument("--output", type=Path, default=Path("artifacts/baseline"), help="Output file prefix")
    args = parser.parse_args()
    records, summary = run(load_attacks(args.mutate))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.with_suffix(".json").write_text(json.dumps({"summary": summary, "attempts": records}, indent=2), encoding="utf-8")
    with args.output.with_suffix(".csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)
    print("family              attempts  breaches  ASR")
    for family, values in summary.items():
        print(f"{family:<20} {values['attempts']:>8}  {values['breaches']:>8}  {values['asr']:.1%}")
    print(f"Wrote {args.output.with_suffix('.json')} and {args.output.with_suffix('.csv')}")


if __name__ == "__main__":
    main()

