"""Create reproducible stratified train / validation / locked-holdout splits.

* **train** - the only data the classifier, similarity index and hardening loop see.
* **validation** - used to choose thresholds and in the CI regression gate.
* **holdout** - locked with SHA-256 hashes in ``manifest.json``; never used for
  training or tuning, only for the final numbers in the report.

Attacks are stratified by family and benign prompts by expected task, so every
split contains every kind of example.
"""

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SEEDS = ROOT.parent / "fuzzer" / "seeds" / "attacks.json"
BENIGN = ROOT / "benign" / "requests.json"
RATIOS = (0.6, 0.2, 0.2)


def _order(row: dict, seed: str) -> str:
    return hashlib.sha256(f"{seed}:{row['id']}".encode()).hexdigest()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stratified(rows: list[dict], key: str, seed: str) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[row.get(key, "other")].append(row)
    result: dict[str, list[dict]] = {"train": [], "validation": [], "holdout": []}
    for _, members in sorted(groups.items()):
        members.sort(key=lambda row: _order(row, seed))
        n = len(members)
        if n >= 3:
            validation_count = max(1, round(n * RATIOS[1]))
            holdout_count = max(1, round(n * RATIOS[2]))
        else:
            validation_count, holdout_count = 0, 0
        train_count = n - validation_count - holdout_count
        result["train"].extend(members[:train_count])
        result["validation"].extend(members[train_count : train_count + validation_count])
        result["holdout"].extend(members[train_count + validation_count :])
    return result


def build(seed: str = "sentinelloop-v2") -> dict:
    attacks = json.loads(SEEDS.read_text(encoding="utf-8-sig"))
    benign = json.loads(BENIGN.read_text(encoding="utf-8-sig"))
    attack_splits = _stratified(attacks, "family", seed)
    benign_splits = _stratified(benign, "expected", seed)
    for split_name in ("train", "validation", "holdout"):
        directory = ROOT / split_name
        directory.mkdir(parents=True, exist_ok=True)
        for kind, rows in (("attacks", attack_splits[split_name]), ("benign", benign_splits[split_name])):
            (directory / f"{kind}.json").write_text(
                json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
    lock_paths = [ROOT / "holdout" / "attacks.json", ROOT / "holdout" / "benign.json"]
    manifest = {
        "seed": seed,
        "ratios": {"train": RATIOS[0], "validation": RATIOS[1], "holdout": RATIOS[2]},
        "counts": {
            name: {"attacks": len(attack_splits[name]), "benign": len(benign_splits[name])}
            for name in ("train", "validation", "holdout")
        },
        "locked_holdout_sha256": {path.name: _sha(path) for path in lock_paths},
    }
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def verify() -> bool:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    return all(
        _sha(ROOT / "holdout" / name) == digest for name, digest in manifest["locked_holdout_sha256"].items()
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", default="sentinelloop-v2")
    parser.add_argument(
        "--verify", action="store_true", help="Verify that locked holdout files match the manifest"
    )
    args = parser.parse_args()
    if args.verify:
        valid = verify()
        print("Locked holdout integrity:", "valid" if valid else "FAILED")
        raise SystemExit(0 if valid else 1)
    manifest = build(args.seed)
    print(json.dumps(manifest["counts"], indent=2))


if __name__ == "__main__":
    main()
