"""Genetic algorithm: evolve attacks that get past the firewall.

Each generation keeps the fittest attacks (elitism), recombines them (word-level
crossover) and mutates the children with the operators from ``fuzzer.mutators``.

Fitness rewards partial progress so evolution has a gradient to climb:

* 1.0 - the attack caused a breach;
* 0.5 - no detector flagged it (it was stopped later, e.g. by the output guard);
* 0.0 - a detector blocked it.

    python -m fuzzer.search.genetic --profile detectors --generations 8
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import replace
from pathlib import Path

from firewall import DETECTORS, Firewall
from sentinelloop.corpus import Attack, load_seeds
from sentinelloop.harness import PROFILES, run_scenario

from ..mutators import OPERATORS, apply

ARTIFACTS = Path("artifacts") / "search"


def evaluate(
    attack: Attack, profile: str = "detectors", firewall: Firewall | None = None
) -> tuple[float, str]:
    result = run_scenario(attack, profile, firewall)
    if result["outcome"] == "breach":
        return 1.0, "breach"
    if not set(result["stopped_by"]) & set(DETECTORS):
        return 0.5, result["outcome"]
    return 0.0, result["outcome"]


def crossover(first: Attack, second: Attack, rng: random.Random) -> Attack:
    left, right = first.payload().split(), second.payload().split()
    cut_left = rng.randrange(1, len(left) + 1)
    cut_right = rng.randrange(len(right) + 1)
    child = " ".join(left[:cut_left] + right[cut_right:]) or first.payload()
    return replace(first.with_payload(child, "crossover"), parent=f"{first.id} x {second.id}")


def random_mutation(attack: Attack, rng: random.Random) -> Attack:
    for technique in rng.sample(OPERATORS, len(OPERATORS)):
        variant = apply(attack, technique)
        if variant is not None:
            return variant
    return attack


def _key(attack: Attack) -> tuple:
    return (attack.channel, attack.prompt, attack.turns)


def search(
    generations: int = 8,
    population_size: int = 30,
    seed: int = 42,
    profile: str = "detectors",
    firewall: Firewall | None = None,
    seeds: list[Attack] | None = None,
) -> dict:
    if generations < 1 or population_size < 2:
        raise ValueError("generations must be positive and population_size at least 2")
    rng = random.Random(seed)
    population = list(seeds) if seeds is not None else load_seeds()
    rng.shuffle(population)
    population = population[:population_size]
    cache: dict[tuple, tuple[float, str]] = {}
    origin: dict[tuple, tuple[str, str]] = {}

    def score(attack: Attack) -> tuple[float, str]:
        key = _key(attack)
        if key not in cache:
            cache[key] = evaluate(attack, profile, firewall)
            origin[key] = (attack.family, attack.technique)
        return cache[key]

    history = []
    for generation in range(generations):
        ranked = sorted(population, key=lambda item: score(item)[0], reverse=True)
        fitnesses = [score(item)[0] for item in ranked]
        history.append(
            {
                "generation": generation,
                "population": len(population),
                "breaches": sum(value == 1.0 for value in fitnesses),
                "evaded_detectors": sum(value >= 0.5 for value in fitnesses),
                "mean_fitness": round(sum(fitnesses) / len(fitnesses), 4),
                "best_fitness": max(fitnesses, default=0.0),
            }
        )
        elites = ranked[: max(2, population_size // 4)]
        next_population = list(elites)
        while len(next_population) < population_size:
            first, second = rng.choice(elites), rng.choice(ranked[: population_size // 2])
            child = crossover(first, second, rng) if rng.random() < 0.5 else first
            if rng.random() < 0.9:
                child = random_mutation(child, rng)
            next_population.append(child)
        population = next_population

    archive = {}
    for key, (fitness, label) in cache.items():
        if fitness <= 0:
            continue
        channel, prompt, turns = key
        archive[key] = {"prompt": prompt, "turns": list(turns), "channel": channel,
                        "fitness": fitness, "outcome": label}  # fmt: skip
    rows = []
    for key, row in archive.items():
        family, technique = origin[key]
        rows.append({**row, "family": family, "technique": technique})
    return {
        "algorithm": "genetic",
        "seed": seed,
        "profile": profile,
        "evaluations": len(cache),
        "history": history,
        "archive": sorted(rows, key=lambda row: row["fitness"], reverse=True),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--generations", type=int, default=8)
    parser.add_argument("--population", type=int, default=30)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="detectors")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    result = search(args.generations, args.population, args.seed, args.profile)
    output = args.output or ARTIFACTS / f"genetic-{args.profile}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    last = result["history"][-1]
    print(
        f"Generations: {len(result['history'])}; evaluations: {result['evaluations']}; "
        f"final population breaches: {last['breaches']}/{last['population']}"
    )
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
