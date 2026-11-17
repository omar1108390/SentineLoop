"""Create reproducible stratified train/validation/locked-holdout files."""

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SEEDS = ROOT.parent / "fuzzer" / "seeds" / "attacks.json"
BENIGN = ROOT / "benign" / "requests.json"


def _order(row: dict, seed: str) -> str:
    return hashlib.sha256(f"{seed}:{row['id']}".encode()).hexdigest()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(seed: str = "sentinelloop-v1") -> dict:
    attacks = json.loads(SEEDS.read_text(encoding="utf-8-sig"))
    benign = json.loads(BENIGN.read_text(encoding="utf-8-sig"))
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in attacks:
        groups[row["family"]].append(row)
    splits = {name: {"attacks": [], "benign": []} for name in ("train", "validation", "holdout")}
    for family, rows in groups.items():
        rows.sort(key=lambda row: _order(row, seed))
        n = len(rows)
        if n >= 4:
            validation_count, holdout_count = max(1, round(n * 0.2)), max(1, round(n * 0.2))
            train_count = n - validation_count - holdout_count
        elif n >= 3:
            train_count, validation_count, holdout_count = n - 2, 1, 1
        else:
            train_count, validation_count, holdout_count = n, 0, 0
        splits["train"]["attacks"].extend(rows[:train_count])
        splits["validation"]["attacks"].extend(rows[train_count : train_count + validation_count])
        splits["holdout"]["attacks"].extend(rows[train_count + validation_count :])
    benign.sort(key=lambda row: _order(row, seed))
    train_end = int(len(benign) * 0.8)
    validation_end = train_end + max(1, int(len(benign) * 0.1))
    splits["train"]["benign"] = benign[:train_end]
    splits["validation"]["benign"] = benign[train_end:validation_end]
    splits["holdout"]["benign"] = benign[validation_end:]

    for split_name, values in splits.items():
        directory = ROOT / split_name
        directory.mkdir(parents=True, exist_ok=True)
        for kind, rows in values.items():
            (directory / f"{kind}.json").write_text(
                json.dumps(rows, indent=2) + "\n", encoding="utf-8"
            )
    lock_paths = [ROOT / "holdout" / "attacks.json", ROOT / "holdout" / "benign.json"]
    manifest = {
        "seed": seed,
        "counts": {
            name: {kind: len(rows) for kind, rows in values.items()}
            for name, values in splits.items()
        },
        "locked_holdout_sha256": {path.name: _sha(path) for path in lock_paths},
    }
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def verify() -> bool:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    return all(
        _sha(ROOT / "holdout" / name) == digest
        for name, digest in manifest["locked_holdout_sha256"].items()
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", default="sentinelloop-v1")
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
