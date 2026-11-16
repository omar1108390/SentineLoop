"""MAP-Elites quality-diversity search over family x mutation-technique cells."""

import argparse
import json
import random
from pathlib import Path

from ..mutators import Attack, mutate
from ..runner import load_attacks
from .genetic import evaluate

TECHNIQUES = ("seed", "paraphrase", "distractor", "document-wrap", "unicode", "base64", "rot13", "crossover")


def map_elites(iterations: int = 200, seed: int = 42, use_firewall: bool = False) -> dict:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    rng = random.Random(seed)
    archive: dict[tuple[str, str], dict] = {}
    families = sorted({attack.family for attack in load_attacks(False) if attack.family != "benign"})
    evaluated: dict[str, tuple[float, str]] = {}

    def consider(attack: Attack) -> None:
        if attack.prompt in evaluated:
            fitness, label = evaluated[attack.prompt]
        else:
            fitness, label = evaluate(attack, use_firewall)
            evaluated[attack.prompt] = (fitness, label)
        descriptor = (attack.family, attack.technique if attack.technique in TECHNIQUES else "seed")
        candidate = {"family": descriptor[0], "technique": descriptor[1], "prompt": attack.prompt,
                     "fitness": fitness, "outcome": label, "parent": attack.parent}
        current = archive.get(descriptor)
        if current is None or candidate["fitness"] > current["fitness"]:
            archive[descriptor] = candidate

    seeds = [attack for attack in load_attacks(False) if attack.family != "benign"]
    for attack in seeds:
        consider(attack)
        for child in mutate(attack):
            consider(child)

    history = []
    for iteration in range(iterations):
        parent_row = rng.choice(list(archive.values()))
        parent = Attack(parent_row["prompt"], parent_row["family"], parent_row["technique"], parent_row["parent"])
        child = rng.choice(mutate(parent))
        consider(child)
        if (iteration + 1) % max(1, iterations // 10) == 0 or iteration + 1 == iterations:
            history.append({"iteration": iteration + 1, "coverage": len(archive),
                            "possible_cells": len(families) * len(TECHNIQUES),
                            "breach_cells": sum(row["fitness"] > 0 for row in archive.values())})

    cells = [archive.get((family, technique)) for family in families for technique in TECHNIQUES]
    return {"seed": seed, "firewall": use_firewall, "dimensions": {"family": families, "technique": list(TECHNIQUES)},
            "history": history, "coverage": len(archive), "possible_cells": len(families) * len(TECHNIQUES),
            "archive": [row for row in cells if row is not None]}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run MAP-Elites against the local sandbox only")
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--firewall", action="store_true")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    result = map_elites(args.iterations, args.seed, args.firewall)
    output = args.output or Path("artifacts/map-elites-firewall.json" if args.firewall else "artifacts/map-elites-baseline.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    breaches = sum(row["fitness"] > 0 for row in result["archive"])
    print(f"Coverage: {result['coverage']}/{result['possible_cells']}; breach cells: {breaches}")
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
