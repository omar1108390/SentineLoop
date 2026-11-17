"""Small deterministic genetic algorithm over the local prompt corpus."""

import argparse
import json
import random
from pathlib import Path

from firewall import Firewall
from target_app.agent import DemoAgent
from target_app.judge import ObjectiveJudge

from ..mutators import Attack, mutate
from ..runner import load_attacks


def evaluate(attack: Attack, use_firewall: bool) -> tuple[float, str]:
    agent = DemoAgent()
    firewall = Firewall() if use_firewall else None
    guard = (lambda text: firewall.inspect_untrusted(text).verdict != "block") if firewall else None
    outcome_label = "blocked"
    for prompt in attack.turns or (attack.prompt,):
        if firewall and firewall.inspect_input(prompt).verdict == "block":
            outcome_label = "blocked"
            break
        result = agent.handle(prompt, content_guard=guard)
        response = result.response
        if firewall:
            response, _ = firewall.inspect_output(response)
        outcome = ObjectiveJudge().evaluate(response, agent.tools.state)
        outcome_label = outcome.label
        if outcome.label == "breach":
            break
    return float(outcome_label == "breach"), outcome_label


def crossover(first: Attack, second: Attack, rng: random.Random) -> Attack:
    left, right = first.prompt.split(), second.prompt.split()
    cut_left = rng.randrange(len(left) + 1)
    cut_right = rng.randrange(len(right) + 1)
    child = " ".join(left[:cut_left] + right[cut_right:])
    if not child.strip():
        child = first.prompt
    return Attack(child, first.family, "crossover", first.prompt + " || " + second.prompt)


def search(generations: int = 5, population_size: int = 20, seed: int = 42,
           use_firewall: bool = False) -> dict:
    if generations < 1 or population_size < 2:
        raise ValueError("generations must be positive and population_size at least 2")
    rng = random.Random(seed)
    population = [attack for attack in load_attacks(False) if attack.family != "benign"]
    while len(population) < population_size:
        parent = rng.choice(population)
        population.append(rng.choice(mutate(parent)))
    scores: dict[str, tuple[float, str]] = {}
    history = []

    def score(attack: Attack) -> tuple[float, str]:
        if attack.prompt not in scores:
            scores[attack.prompt] = evaluate(attack, use_firewall)
        return scores[attack.prompt]

    for generation in range(generations):
        ranked = sorted(population, key=lambda item: score(item)[0], reverse=True)
        fitnesses = [score(item)[0] for item in ranked]
        history.append({"generation": generation, "population": len(population),
                        "breaches": int(sum(fitnesses)), "best_fitness": max(fitnesses, default=0.0),
                        "family_breaches": sum(fitnesses)})
        elites = ranked[:max(2, population_size // 4)]
        next_population = list(elites)
        while len(next_population) < population_size:
            first = rng.choice(elites)
            second = rng.choice(elites)
            child = crossover(first, second, rng)
            if rng.random() < 0.8:
                child = rng.choice(mutate(child))
            next_population.append(child)
        population = next_population

    unique = {}
    for attack in population:
        fitness, label = score(attack)
        unique[attack.prompt] = {"prompt": attack.prompt, "family": attack.family,
                                 "technique": attack.technique, "fitness": fitness, "outcome": label}
    return {"seed": seed, "firewall": use_firewall, "history": history,
            "archive": sorted(unique.values(), key=lambda row: row["fitness"], reverse=True)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Evolve attacks against the local sandbox only")
    parser.add_argument("--generations", type=int, default=5)
    parser.add_argument("--population", type=int, default=20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--firewall", action="store_true")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    result = search(args.generations, args.population, args.seed, args.firewall)
    output = args.output or Path("artifacts/genetic-firewall.json" if args.firewall else "artifacts/genetic-baseline.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Generations: {len(result['history'])}; archive: {len(result['archive'])}; "
          f"best fitness: {max((row['fitness'] for row in result['archive']), default=0):.1f}")
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
