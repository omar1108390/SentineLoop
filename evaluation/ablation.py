"""End-to-end ablation: switch off one layer at a time and measure the damage.

Runs the locked holdout (seeds + mutations) with the full stack, the full stack
minus each single layer, detectors only, and architectural controls only. A
layer matters if removing it raises the attack success rate (or, for benign
traffic, if removing it lowers the false-positive rate).

    python -m evaluation.ablation
"""

from __future__ import annotations

from dataclasses import replace

from firewall import DETECTORS
from sentinelloop.harness import PROFILES, Defenses

from .common import attack_metrics, attack_pool, benign_metrics, benign_rows, write
from .split_corpus import verify

FULL = PROFILES["full"]


def configurations() -> dict[str, Defenses]:
    configs: dict[str, Defenses] = {"full": FULL}
    for detector in DETECTORS:
        configs[f"without_{detector}"] = replace(FULL, detectors=FULL.detectors - {detector})
    for layer in ("quarantine", "tool_policy", "output_guard"):
        configs[f"without_{layer}"] = replace(FULL, **{layer: False})
    configs["detectors_only"] = PROFILES["detectors"]
    configs["architecture_only"] = Defenses(frozenset(), False, False, True, True, True)
    configs["none"] = PROFILES["none"]
    return configs


def main() -> None:
    if not verify():
        raise SystemExit("Locked holdout integrity check failed")
    pool, rows = attack_pool("holdout"), benign_rows("holdout")
    result = {
        "scope": "locked holdout seeds + one variant per mutation operator",
        "configurations": {},
    }
    for name, defenses in configurations().items():
        attacks = attack_metrics(pool, defenses)
        benign = benign_metrics(rows, defenses)
        result["configurations"][name] = {
            "layers": defenses.layers(),
            "asr": attacks["asr"],
            "breaches": attacks["breaches"],
            "attempts": attacks["attempts"],
            "by_family": attacks["by_family"],
            "fpr": benign["fpr"],
            "utility": benign["utility"],
        }
        print(
            f"{name:<22} ASR {attacks['asr']:6.1%} ({attacks['breaches']}/{attacks['attempts']})"
            f"   FPR {benign['fpr']:6.1%}"
        )
    print(f"Wrote {write('ablation.json', result)}")


if __name__ == "__main__":
    main()
