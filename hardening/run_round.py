"""Run attack, judge, analyze, exact-rule hardening, and locked-holdout evaluation."""

import argparse
import json
import os
from collections import Counter
from pathlib import Path

from firewall.layers.normalizer import normalize
from fuzzer.mutators import Attack, mutate
from fuzzer.runner import run
from evaluation.split_corpus import verify

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "evaluation"
OUT = ROOT / "artifacts" / "closed_loop"


def load_rows(split: str, kind: str) -> list[dict]:
    return json.loads((EVAL / split / f"{kind}.json").read_text(encoding="utf-8"))


def attacks_from(split: str, kind: str = "attacks") -> list[Attack]:
    return [Attack(row["prompt"], row["family"], "seed", row["id"], tuple(row.get("turns", []))) for row in load_rows(split, kind)]


def evaluate_with_rules(attacks: list[Attack], benign: list[Attack], rules_path: Path) -> dict:
    prior = os.environ.get("SENTINELLOOP_RULES_PATH")
    os.environ["SENTINELLOOP_RULES_PATH"] = str(rules_path)
    try:
        attack_records, attack_summary = run(attacks, use_firewall=True)
        benign_records, _ = run(benign, use_firewall=True)
    finally:
        if prior is None:
            os.environ.pop("SENTINELLOOP_RULES_PATH", None)
        else:
            os.environ["SENTINELLOOP_RULES_PATH"] = prior
    breach_count = sum(record["outcome"] == "breach" for record in attack_records)
    blocked_benign = sum(record["input_verdict"] == "block" or record["output_verdict"] == "block"
                         for record in benign_records)
    return {"asr": breach_count / len(attack_records) if attack_records else 0.0,
            "breaches": breach_count, "attack_count": len(attack_records),
            "fpr": blocked_benign / len(benign_records) if benign_records else 0.0,
            "benign_blocked": blocked_benign, "benign_count": len(benign_records),
            "by_family": attack_summary}


def build_training_data(records: list[dict[str, str]], benign_rows: list[dict], rules: list[dict]) -> tuple[list[dict], list[dict]]:
    benign_texts = [normalize(row["prompt"]).split("\n", 1)[0] for row in benign_rows]
    known = {rule["exact"] for rule in rules}
    dataset, additions = [], []
    for row in records:
        if row["outcome"] != "breach":
            continue
        prompts = json.loads(row.get("turns", "[]")) or [row["prompt"]]
        for prompt in prompts:
            dataset.append({"text": prompt, "label": 1, "source": "observed-breach", "family": row["family"]})
            signature = normalize(prompt).split("\n", 1)[0]
            if not signature or signature in known or any(signature in benign for benign in benign_texts):
                continue
            rule = {"id": "exact-" + str(len(rules) + len(additions) + 1).zfill(4),
                    "exact": signature, "family": row["family"]}
            additions.append(rule)
            known.add(signature)
    dataset.extend({"text": row["prompt"], "label": 0, "source": "benign-counterexample", "family": "benign"}
                   for row in benign_rows)
    return dataset, additions


def run_rounds(rounds: int = 3) -> dict:
    if rounds < 1:
        raise ValueError("rounds must be at least 1")
    if not verify():
        raise RuntimeError("Locked holdout integrity check failed; refusing to run hardening")
    OUT.mkdir(parents=True, exist_ok=True)
    versions = ROOT / "artifacts" / "firewall_versions"
    versions.mkdir(parents=True, exist_ok=True)
    rules = []
    reports = []
    for version in range(rounds + 1):
        rules_path = versions / f"v{version}.json"
        rules_path.write_text(json.dumps({"version": version, "rules": rules}, indent=2), encoding="utf-8")
        train_rows = load_rows("train", "attacks")
        train_benign = load_rows("train", "benign")
        train_attacks = [Attack(row["prompt"], row["family"], "seed", row["id"], tuple(row.get("turns", []))) for row in train_rows]
        training_pool = list(train_attacks)
        for attack in train_attacks:
            training_pool.extend(mutate(attack))
        prior = os.environ.get("SENTINELLOOP_RULES_PATH")
        os.environ["SENTINELLOOP_RULES_PATH"] = str(rules_path)
        try:
            train_records, train_summary = run(training_pool, use_firewall=True)
        finally:
            if prior is None:
                os.environ.pop("SENTINELLOOP_RULES_PATH", None)
            else:
                os.environ["SENTINELLOOP_RULES_PATH"] = prior
        dataset, additions = build_training_data(train_records, train_benign, rules)
        dataset_path = OUT / f"v{version}-training-data.json"
        dataset_path.write_text(json.dumps(dataset, indent=2), encoding="utf-8")
        holdout_metrics = evaluate_with_rules(attacks_from("holdout"),
                                               [Attack(row["prompt"], "benign") for row in load_rows("holdout", "benign")],
                                               rules_path)
        reports.append({"version": version, "training": train_summary,
                        "training_breaches": sum(row["outcome"] == "breach" for row in train_records),
                        "hardening_rules_added": len(additions), "training_data": str(dataset_path.relative_to(ROOT)),
                        "holdout": holdout_metrics})
        rules.extend(additions)
    baseline = run(attacks_from("holdout"), use_firewall=False)[1]
    baseline_count = sum(item["attempts"] for item in baseline.values())
    baseline_breaches = sum(item["breaches"] for item in baseline.values())
    result = {"rounds": reports, "baseline_holdout": baseline,
              "baseline_holdout_overall": {"attempts": baseline_count, "breaches": baseline_breaches,
                                           "asr": baseline_breaches / baseline_count if baseline_count else 0.0},
              "holdout_lock_verified": True,
              "method": "exact normalized attack-text signatures; benign training prompts are checked as counterexamples"}
    (OUT / "report.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    result = run_rounds(args.rounds)
    print("round  train-breaches  new-rules  holdout-ASR  holdout-FPR")
    for row in result["rounds"]:
        holdout = row["holdout"]
        print(f"v{row['version']:<5} {row['training_breaches']:>14}  {row['hardening_rules_added']:>9}  "
              f"{holdout['asr']:.1%}        {holdout['fpr']:.1%}")
    print("Wrote artifacts/closed_loop/report.json")


if __name__ == "__main__":
    main()
