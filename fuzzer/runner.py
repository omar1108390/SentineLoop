"""Run reproducible baseline or firewall experiments against the fake target."""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

from firewall import Firewall
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


def run(attacks: list[Attack], use_firewall: bool = False) -> tuple[list[dict[str, str]], dict[str, dict[str, float]]]:
    records: list[dict[str, str]] = []
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "breaches": 0})
    for index, attack in enumerate(attacks):
        agent = DemoAgent()
        firewall = Firewall() if use_firewall else None
        input_check = firewall.inspect_input(attack.prompt) if firewall else None
        output_check = None
        if input_check and input_check.verdict == "block":
            response = "Request blocked by firewall."
        else:
            guard = (lambda text: firewall.inspect_untrusted(text).verdict != "block") if firewall else None
            result = agent.handle(attack.prompt, content_guard=guard)
            response = result.response
            if firewall:
                response, output_check = firewall.inspect_output(response)
        outcome = ObjectiveJudge().evaluate(response, agent.tools.state)
        records.append({
            "index": str(index), "family": attack.family, "technique": attack.technique,
            "parent": attack.parent, "prompt": attack.prompt, "outcome": outcome.label,
            "reason": outcome.reason,
            "input_verdict": input_check.verdict if input_check else "disabled",
            "output_verdict": output_check.verdict if output_check else "not-run",
            "latency_ms": f"{(input_check.latency_ms if input_check else 0) + (output_check.latency_ms if output_check else 0):.4f}",
        })
        counts[attack.family]["total"] += 1
        counts[attack.family]["breaches"] += int(outcome.label == "breach")
    summary = {
        family: {"attempts": values["total"], "breaches": values["breaches"], "asr": values["breaches"] / values["total"]}
        for family, values in sorted(counts.items())
    }
    return records, summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local SentinelLoop baseline fuzzer")
    parser.add_argument("--mutate", action="store_true", help="Include deterministic mutations")
    parser.add_argument("--firewall", action="store_true", help="Enable the local firewall pipeline")
    parser.add_argument("--output", type=Path, default=None, help="Output file prefix")
    args = parser.parse_args()
    prefix = args.output or Path("artifacts/firewall" if args.firewall else "artifacts/baseline")
    records, summary = run(load_attacks(args.mutate), args.firewall)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    prefix.with_suffix(".json").write_text(json.dumps({"summary": summary, "attempts": records}, indent=2), encoding="utf-8")
    with prefix.with_suffix(".csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)
    print(f"Firewall: {args.firewall}")
    print("family              attempts  breaches  ASR")
    for family, values in summary.items():
        print(f"{family:<20} {values['attempts']:>8}  {values['breaches']:>8}  {values['asr']:.1%}")
    print(f"Wrote {prefix.with_suffix('.json')} and {prefix.with_suffix('.csv')}")


if __name__ == "__main__":
    main()
