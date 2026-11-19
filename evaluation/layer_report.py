"""Measure each detector on its own: detection rate, false positives, latency.

Attack texts are the attacker-controlled texts of the split's seeds and their
mutations (for indirect attacks: the planted document). Benign texts are the
benign prompts and benign documents of the same split.

    python -m evaluation.layer_report
"""

from __future__ import annotations

from time import perf_counter

from firewall import DETECTORS, Firewall
from firewall.layers.similarity import attacker_texts

from .common import attack_pool, benign_rows, percentile, write
from .split_corpus import verify


def _texts(split: str) -> tuple[list[str], list[str]]:
    attacks = []
    for attack in attack_pool(split):
        row = {"channel": attack.channel, "prompt": attack.prompt, "turns": list(attack.turns)}
        attacks.append(attacker_texts(row))
    benign = [[*row.get("turns", []), row["prompt"]] for row in benign_rows(split)]
    return attacks, benign


def evaluate(split: str, detectors: set[str]) -> dict:
    firewall = Firewall(detectors=detectors)
    attacks, benign = _texts(split)
    timings: list[float] = []

    def flagged(texts: list[str]) -> bool:
        hit = False
        for text in texts:
            started = perf_counter()
            hit = firewall.inspect_input(text).verdict == "block" or hit
            timings.append((perf_counter() - started) * 1000)
        return hit

    detected = sum(flagged(texts) for texts in attacks)
    false_positives = sum(flagged(texts) for texts in benign)
    return {
        "attack_items": len(attacks),
        "detected": detected,
        "detection_rate": detected / len(attacks) if attacks else 0.0,
        "benign_items": len(benign),
        "false_positives": false_positives,
        "false_positive_rate": false_positives / len(benign) if benign else 0.0,
        "latency_ms": {"p50": percentile(timings, 0.5), "p95": percentile(timings, 0.95)},
    }


def main() -> None:
    if not verify():
        raise SystemExit("Locked holdout integrity check failed")
    firewall = Firewall()
    result = {
        "classifier_threshold": firewall.injection_model.threshold,
        "classifier_version": firewall.injection_model.version,
        "similarity_threshold": firewall.similarity_threshold,
        "splits": {},
    }
    for split in ("validation", "holdout"):
        rows = {name: evaluate(split, {name}) for name in DETECTORS}
        rows["combined"] = evaluate(split, set(DETECTORS))
        result["splits"][split] = rows
        print(f"{split}:")
        for name, values in rows.items():
            print(
                f"  {name:<11} detection {values['detection_rate']:6.1%}   "
                f"FPR {values['false_positive_rate']:6.1%}   p95 {values['latency_ms']['p95']:.3f} ms"
            )
    print(f"Wrote {write('layers.json', result)}")


if __name__ == "__main__":
    main()
