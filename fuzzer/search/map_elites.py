"""MAP-Elites: find *many different* working attacks, not just the best one.

The archive is a grid of cells, one per (attack family x mutation technique).
Each cell keeps its fittest attack. A random elite is repeatedly picked,
mutated, and the child replaces the elite of its own cell if it is fitter.
Coverage (how many cells are filled) and breach cells (how many contain a
successful attack) show *where* the firewall is weak, which is more useful for
hardening than a single high-scoring attack.

    python -m fuzzer.search.map_elites --profile detectors --iterations 400
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from sentinelloop.corpus import FAMILIES, Attack, load_seeds
from sentinelloop.harness import PROFILES

from ..mutators import TECHNIQUES, mutate
from .genetic import evaluate, random_mutation

ARTIFACTS = Path("artifacts") / "search"
GRID_TECHNIQUES = tuple(item for item in TECHNIQUES if item not in {"crossover", "llm-feedback"})


def map_elites(iterations: int = 400, seed: int = 42, profile: str = "detectors") -> dict:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    rng = random.Random(seed)
    archive: dict[tuple[str, str], dict] = {}
    families = sorted(FAMILIES)
    evaluated: dict[tuple, tuple[float, str]] = {}
    elites: dict[tuple[str, str], Attack] = {}

    def consider(attack: Attack) -> None:
        key = (attack.channel, attack.prompt, attack.turns)
        if key not in evaluated:
            evaluated[key] = evaluate(attack, profile)
        fitness, label = evaluated[key]
        technique = attack.technique if attack.technique in GRID_TECHNIQUES else "seed"
        cell = (attack.family, technique)
        current = archive.get(cell)
        if current is None or fitness > current["fitness"]:
            archive[cell] = {
                "family": attack.family,
                "technique": technique,
                "channel": attack.channel,
                "prompt": attack.prompt,
                "turns": list(attack.turns),
                "fitness": fitness,
                "outcome": label,
                "parent": attack.parent,
            }
            elites[cell] = attack

    for attack in load_seeds():
        consider(attack)
        for child in mutate(attack):
            consider(child)
    possible = len(families) * len(GRID_TECHNIQUES)
    history = [{"iteration": 0, "coverage": len(archive), "possible_cells": possible,
                "breach_cells": sum(row["fitness"] >= 1 for row in archive.values())}]  # fmt: skip
    for iteration in range(iterations):
        parent = elites[rng.choice(sorted(elites))]
        consider(random_mutation(parent, rng))
        if (iteration + 1) % max(1, iterations // 10) == 0:
            history.append(
                {
                    "iteration": iteration + 1,
                    "coverage": len(archive),
                    "possible_cells": possible,
                    "breach_cells": sum(row["fitness"] >= 1 for row in archive.values()),
                }
            )
    cells = [archive.get((family, technique)) for family in families for technique in GRID_TECHNIQUES]
    return {
        "algorithm": "map-elites",
        "seed": seed,
        "profile": profile,
        "evaluations": len(evaluated),
        "dimensions": {"family": families, "technique": list(GRID_TECHNIQUES)},
        "history": history,
        "coverage": len(archive),
        "possible_cells": possible,
        "breach_cells": sum(row["fitness"] >= 1 for row in archive.values()),
        "archive": [row for row in cells if row is not None],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iterations", type=int, default=400)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="detectors")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    result = map_elites(args.iterations, args.seed, args.profile)
    output = args.output or ARTIFACTS / f"map-elites-{args.profile}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    print(
        f"Coverage: {result['coverage']}/{result['possible_cells']}; "
        f"breach cells: {result['breach_cells']}; evaluations: {result['evaluations']}"
    )
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
