"""Compare defense profiles: none, keyword rules, all detectors, full stack.

For the validation and locked-holdout splits this measures, per profile:

* **ASR** - attack success rate over the split's seeds + all their mutations;
* **FPR** - share of benign requests where any layer blocked or withheld something;
* **utility** - share of benign tasks still completed correctly.

    python -m evaluation.compare_profiles
"""

from __future__ import annotations

from sentinelloop.harness import PROFILE_DESCRIPTIONS, PROFILES

from .common import attack_metrics, attack_pool, benign_metrics, benign_rows, write
from .split_corpus import verify


def main() -> None:
    if not verify():
        raise SystemExit("Locked holdout integrity check failed")
    result = {
        "scope": "deterministic sandbox; seeds + one variant per mutation operator",
        "profiles": PROFILE_DESCRIPTIONS,
        "splits": {},
    }
    for split in ("validation", "holdout"):
        pool = attack_pool(split)
        rows = benign_rows(split)
        result["splits"][split] = {
            name: {"attacks": attack_metrics(pool, name), "benign": benign_metrics(rows, name)}
            for name in PROFILES
        }
    path = write("profiles.json", result)
    for split, profiles in result["splits"].items():
        print(f"{split}:")
        for name, values in profiles.items():
            attacks, benign = values["attacks"], values["benign"]
            print(
                f"  {name:<10} ASR {attacks['asr']:6.1%} ({attacks['breaches']}/{attacks['attempts']})"
                f"   FPR {benign['fpr']:6.1%}   utility {benign['utility']:6.1%}"
            )
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
