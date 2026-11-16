"""Run reproducible baseline or firewall experiments against the fake target."""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

from firewall import Firewall
from firewall.gateway.event_store import default_store
from target_app.agent import DemoAgent
from target_app.judge import ObjectiveJudge
from .mutators import Attack, mutate

ROOT = Path(__file__).resolve().parent


def load_attacks(include_mutations: bool) -> list[Attack]:
    rows = json.loads((ROOT / "seeds" / "attacks.json").read_text(encoding="utf-8-sig"))
    attacks = [Attack(row["prompt"], row["family"], "seed", row["id"], tuple(row.get("turns", [])))
               for row in rows]
    if include_mutations:
        attacks += [variant for attack in attacks if attack.family != "benign" for variant in mutate(attack)]
    return attacks


def run(attacks: list[Attack], use_firewall: bool = False) -> tuple[list[dict[str, str]], dict[str, dict[str, float]]]:
    records: list[dict[str, str]] = []
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "breaches": 0})
    for index, attack in enumerate(attacks):
        agent = DemoAgent()
        firewall = Firewall() if use_firewall else None
        guard = (lambda text: firewall.inspect_untrusted(text).verdict != "block") if firewall else None
        inputs, outputs = [], []
        outcome = None
        response = ""
        prompts = attack.turns or (attack.prompt,)
        for prompt in prompts:
            input_check = firewall.inspect_input(prompt) if firewall else None
            if input_check:
                inputs.append(input_check)
                if input_check.verdict == "block":
                    response = "Request blocked by firewall."
                    outcome = ObjectiveJudge().evaluate(response, agent.tools.state)
                    break
            turn_result = agent.handle(prompt, content_guard=guard)
            response = turn_result.response
            if firewall:
                response, output_check = firewall.inspect_output(response)
                outputs.append(output_check)
            outcome = ObjectiveJudge().evaluate(response, agent.tools.state)
            if outcome.label == "breach":
                break
        if outcome is None:
            outcome = ObjectiveJudge().evaluate(response, agent.tools.state)
        input_verdict = "block" if any(item.verdict == "block" for item in inputs) else (
            "allow" if inputs else "disabled")
        output_verdict = "block" if any(item.verdict == "block" for item in outputs) else (
            "allow" if outputs else "not-run")
        records.append({
            "index": str(index), "family": attack.family, "technique": attack.technique,
            "parent": attack.parent, "prompt": attack.prompt,
            "turns": json.dumps(list(prompts), ensure_ascii=False), "turn_count": str(len(prompts)),
            "outcome": outcome.label, "reason": outcome.reason,
            "input_verdict": input_verdict, "output_verdict": output_verdict,
            "input_layers": json.dumps([{"layer": item.layer, "verdict": item.verdict} for item in inputs]),
            "output_layers": json.dumps([{"layer": item.layer, "verdict": item.verdict} for item in outputs]),
            "latency_ms": f"{sum(item.latency_ms for item in inputs + outputs):.4f}",
        })
        counts[attack.family]["total"] += 1
        counts[attack.family]["breaches"] += int(outcome.label == "breach")
    run_id = default_store().store_attempts(records)
    for record in records:
        record["run_id"] = run_id
    summary = {
        family: {"attempts": values["total"], "breaches": values["breaches"],
                 "asr": values["breaches"] / values["total"]}
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
    artifact_records = [{key: value for key, value in record.items() if key != "run_id"}
                        for record in records]
    prefix.with_suffix(".json").write_text(
        json.dumps({"summary": summary, "attempts": artifact_records}, indent=2), encoding="utf-8")
    with prefix.with_suffix(".csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=artifact_records[0].keys())
        writer.writeheader()
        writer.writerows(artifact_records)
    print(f"Firewall: {args.firewall}")
    print("family              attempts  breaches  ASR")
    for family, values in summary.items():
        print(f"{family:<20} {values['attempts']:>8}  {values['breaches']:>8}  {values['asr']:.1%}")
    print(f"Wrote {prefix.with_suffix('.json')} and {prefix.with_suffix('.csv')}")


if __name__ == "__main__":
    main()
