"""The closed loop: attack -> judge -> analyse -> harden -> re-evaluate.

Each round ``vN``:

1. **Attack** the *training* attacks with every mutation operator plus a short
   genetic search against the current detectors (``vN`` model, rules and index).
2. **Judge** every attempt with the objective judge; collect the breaches.
3. **Analyse** the breaches by family and technique.
4. **Harden** the detectors for ``vN+1``:
   * retrain the ML classifier on training data + every bypass found so far,
     re-tuning its threshold on the validation split;
   * add the bypasses to the similarity index of known attacks;
   * add exact normalized signatures of the bypasses as hardened rules.
5. **Re-evaluate** on the SHA-256-locked holdout (seeds + mutations), which is
   never used for training, to show whether the gains generalise.

    python -m hardening.run_round --rounds 3 [--promote]

``--promote`` copies the final model and attack index into ``firewall/models``
so the gateway and later benchmarks use the hardened detectors.
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
from collections import Counter
from pathlib import Path

from evaluation.split_corpus import verify
from firewall import Firewall
from firewall.layers.ml_classifier import InjectionModel
from firewall.layers.normalizer import normalize
from firewall.layers.similarity import SimilarityIndex, attacker_texts
from fuzzer.mutators import compose, mutate
from fuzzer.search.genetic import search as genetic_search
from hardening.training.train_classifier import (
    choose_similarity_threshold,
    choose_threshold,
    train,
    training_texts,
)
from sentinelloop.corpus import Attack, load_split
from sentinelloop.harness import run_scenario

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "hardening"
MODELS = ROOT / "firewall" / "models"


def _rows(split: str, kind: str) -> list[dict]:
    return json.loads((ROOT / "evaluation" / split / f"{kind}.json").read_text(encoding="utf-8"))


def _as_row(attack: Attack) -> dict:
    return {"id": attack.id or "bypass", "family": attack.family, "channel": attack.channel,
            "prompt": attack.prompt, "turns": list(attack.turns)}  # fmt: skip


def build_firewall(version_dir: Path) -> Firewall:
    index_rows = json.loads((version_dir / "attack_index.json").read_text(encoding="utf-8"))
    return Firewall(
        rules_path=version_dir / "rules.json",
        similarity_index=SimilarityIndex(index_rows),
        injection_model=InjectionModel(version_dir / "model.json"),
    )


def evaluate(firewall: Firewall, split: str) -> dict:
    """ASR on the split's attacks + all their mutations, and benign false-positive rate."""
    seeds = load_split(split, "attacks")
    pool = seeds + [variant for attack in seeds for variant in mutate(attack)]
    result = {}
    for profile in ("detectors", "full"):
        outcomes = [run_scenario(attack, profile, firewall) for attack in pool]
        breaches = [row for row in outcomes if row["outcome"] == "breach"]
        by_family = Counter(row["family"] for row in breaches)
        result[profile] = {
            "attempts": len(outcomes),
            "breaches": len(breaches),
            "asr": len(breaches) / len(outcomes) if outcomes else 0.0,
            "breaches_by_family": dict(sorted(by_family.items())),
        }
    benign = load_split(split, "benign")
    blocked = 0
    for attack in benign:
        row = run_scenario(attack, "detectors", firewall)
        blocked += any(layer in {"rules", "classifier", "similarity"} for layer in row["stopped_by"])
    result["benign"] = {
        "count": len(benign),
        "blocked": blocked,
        "fpr": blocked / len(benign) if benign else 0.0,
    }
    return result


def attack_training_split(firewall: Firewall, round_seed: int) -> tuple[list[Attack], dict]:
    seeds = load_split("train", "attacks")
    rng = random.Random(round_seed)
    pool = seeds + [variant for attack in seeds for variant in mutate(attack)]
    pool += [variant for attack in seeds for variant in compose(attack, rng)]
    breaches: dict[tuple, Attack] = {}
    for attack in pool:
        if run_scenario(attack, "detectors", firewall)["outcome"] == "breach":
            breaches[(attack.channel, attack.prompt, attack.turns)] = attack
    evolved = genetic_search(6, 30, round_seed, "detectors", firewall, seeds)
    for row in evolved["archive"]:
        if row["fitness"] >= 1:
            attack = Attack(row["prompt"], row["family"], row["technique"], "genetic",
                            tuple(row["turns"]), row["channel"])  # fmt: skip
            breaches.setdefault((attack.channel, attack.prompt, attack.turns), attack)
    found = list(breaches.values())
    analysis = {
        "attempts": len(pool) + evolved["evaluations"],
        "breaches": len(found),
        "by_family": dict(sorted(Counter(item.family for item in found).items())),
        "by_technique": dict(sorted(Counter(item.technique for item in found).items())),
    }
    return found, analysis


def write_version(version_dir: Path, model: dict, index_rows: list[dict], rules: list[dict]) -> None:
    version_dir.mkdir(parents=True, exist_ok=True)
    (version_dir / "model.json").write_text(json.dumps(model, separators=(",", ":")), encoding="utf-8")
    (version_dir / "attack_index.json").write_text(
        json.dumps(index_rows, indent=1, ensure_ascii=False), encoding="utf-8"
    )
    (version_dir / "rules.json").write_text(
        json.dumps({"rules": rules}, indent=1, ensure_ascii=False), encoding="utf-8"
    )


def run_rounds(rounds: int = 3, promote: bool = False) -> dict:
    if rounds < 1:
        raise ValueError("rounds must be at least 1")
    if not verify():
        raise RuntimeError("Locked holdout integrity check failed; refusing to run hardening")
    if OUT.exists():
        shutil.rmtree(OUT)
    data_report: dict = {}
    attack_texts, benign_texts = training_texts(data_report)
    benign_signatures = [normalize(text).split("\n", 1)[0] for text in benign_texts]
    index_rows = _rows("train", "attacks")
    learned_texts: list[str] = []
    rules: list[dict] = []

    model = train(attack_texts, benign_texts, version="v0")
    model["threshold"] = choose_threshold(model)
    model["similarity_threshold"] = choose_similarity_threshold(index_rows)
    model["data"] = {**data_report, "bypass_texts": 0}
    write_version(OUT / "v0", model, index_rows, rules)
    reports = []
    for version in range(rounds + 1):
        version_dir = OUT / f"v{version}"
        firewall = build_firewall(version_dir)
        entry = {
            "version": f"v{version}",
            "classifier_threshold": model["threshold"],
            "similarity_threshold": model["similarity_threshold"],
            "classifier_training_attacks": model["train_attacks"],
            "known_attacks_in_index": len(index_rows),
            "hardened_rules": len(rules),
            "validation": evaluate(firewall, "validation"),
            "holdout": evaluate(firewall, "holdout"),
        }
        if version == rounds:
            reports.append(entry)
            break
        found, analysis = attack_training_split(firewall, 100 + version)
        entry["training_attack"] = analysis
        reports.append(entry)
        print(
            f"v{version}: {analysis['breaches']} training bypasses found; "
            f"holdout detector ASR {entry['holdout']['detectors']['asr']:.1%}"
        )
        # Harden: every bypass becomes training data, a known attack and a signature.
        for attack in found:
            texts = attacker_texts(_as_row(attack))
            learned_texts.extend(texts)
            index_rows.append({**_as_row(attack), "id": f"v{version + 1}-bypass-{len(index_rows)}"})
            for text in texts:
                signature = normalize(text).split("\n", 1)[0].strip()
                if (
                    len(signature) >= 20
                    and all(rule["exact"] != signature for rule in rules)
                    and not any(signature in benign for benign in benign_signatures)
                ):
                    rules.append({"exact": signature, "family": attack.family, "version": version + 1})
        model = train(
            attack_texts + learned_texts,
            benign_texts,
            version=f"v{version + 1}",
            source=f"train split + {len(learned_texts)} bypass texts found on the train split",
        )
        model["threshold"] = choose_threshold(model)
        model["similarity_threshold"] = choose_similarity_threshold(index_rows)
        model["data"] = {**data_report, "bypass_texts": len(learned_texts)}
        write_version(OUT / f"v{version + 1}", model, index_rows, rules)

    result = {
        "method": (
            "Each round attacks training seeds (all mutation operators + genetic search) against "
            "the detector layers, then retrains the classifier, extends the similarity index and "
            "adds exact signatures from the bypasses. Validation tunes thresholds; the locked "
            "holdout is never used for training."
        ),
        "holdout_lock_verified": True,
        "rounds": reports,
    }
    (OUT / "report.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    if promote:
        final = OUT / f"v{rounds}"
        shutil.copyfile(final / "model.json", MODELS / "injection_classifier.json")
        shutil.copyfile(final / "attack_index.json", MODELS / "attack_index.json")
        print(f"Promoted v{rounds} model and attack index to {MODELS}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument(
        "--promote", action="store_true", help="Install the final version into firewall/models"
    )
    args = parser.parse_args()
    result = run_rounds(args.rounds, args.promote)
    print("version  train-bypasses  holdout ASR (detectors)  holdout ASR (full)  holdout FPR")
    for row in result["rounds"]:
        holdout = row["holdout"]
        found = row.get("training_attack", {}).get("breaches", "-")
        print(
            f"{row['version']:<8} {found!s:>14}  {holdout['detectors']['asr']:>22.1%}  "
            f"{holdout['full']['asr']:>18.1%}  {holdout['benign']['fpr']:>10.1%}"
        )
    print(f"Wrote {OUT / 'report.json'}")


if __name__ == "__main__":
    main()
