"""Run the attack corpus (and its mutations) against a chosen defense profile.

    python -m fuzzer.runner --mutate --profile none       # unprotected baseline
    python -m fuzzer.runner --mutate --profile full       # full SentinelLoop stack

Writes ``artifacts/fuzz/<profile>.json`` and ``.csv`` with one row per attempt
and an attack-success-rate (ASR) table per family.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from firewall import Firewall
from sentinelloop.corpus import Attack, load_seeds
from sentinelloop.harness import PROFILES, Defenses, run_scenario

from .mutators import mutate

ARTIFACTS = Path("artifacts")
logger = logging.getLogger(__name__)


def load_attacks(include_mutations: bool, seeds: list[Attack] | None = None) -> list[Attack]:
    attacks = list(seeds if seeds is not None else load_seeds())
    if include_mutations:
        attacks += [variant for attack in list(attacks) for variant in mutate(attack)]
    return attacks


def flatten(index: int, result: dict[str, Any]) -> dict[str, str]:
    last = result["transcript"][-1] if result["transcript"] else {}
    return {
        "index": str(index),
        "id": result["id"],
        "family": result["family"],
        "technique": result["technique"],
        "channel": result["channel"],
        "parent": result["parent"],
        "prompt": result["prompt"],
        "turns": json.dumps(result["turns"], ensure_ascii=False),
        "turn_count": str(len(result["turns"])),
        "outcome": result["outcome"],
        "reason": result["reason"],
        "signals": json.dumps(result["signals"]),
        "stopped_by": json.dumps(result["stopped_by"]),
        "response": last.get("response", ""),
        "tool_calls": json.dumps(result["tool_calls"], ensure_ascii=False),
        "latency_ms": f"{result['latency_ms']:.4f}",
    }


def summarize(records: list[dict[str, str]]) -> dict[str, dict[str, float]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"attempts": 0, "breaches": 0})
    for record in records:
        counts[record["family"]]["attempts"] += 1
        counts[record["family"]]["breaches"] += int(record["outcome"] == "breach")
    return {
        family: {**values, "asr": values["breaches"] / values["attempts"]}
        for family, values in sorted(counts.items())
    }


def run(
    attacks: list[Attack],
    use_firewall: bool | str | Defenses = False,
    firewall: Firewall | None = None,
    store: bool = True,
) -> tuple[list[dict[str, str]], dict[str, dict[str, float]]]:
    """Run every attack in a fresh sandbox and return flat records plus a family summary."""
    if isinstance(use_firewall, bool):
        defenses: Defenses | str = "full" if use_firewall else "none"
    else:
        defenses = use_firewall
    records = [
        flatten(index, run_scenario(attack, defenses, firewall)) for index, attack in enumerate(attacks)
    ]
    if store and records:
        try:
            from firewall.gateway.event_store import default_store

            run_id = default_store().store_attempts(records)
            for record in records:
                record["run_id"] = run_id
        except Exception:  # storage is optional for offline experiments
            logger.warning("could not store fuzzer attempts", exc_info=True)
    return records, summarize(records)


def write_artifacts(prefix: Path, records: list[dict[str, str]], summary: dict, meta: dict) -> None:
    prefix.parent.mkdir(parents=True, exist_ok=True)
    rows = [{key: value for key, value in record.items() if key != "run_id"} for record in records]
    total = len(rows)
    breaches = sum(row["outcome"] == "breach" for row in rows)
    overview = {
        **meta,
        "overall": {"attempts": total, "breaches": breaches, "asr": breaches / total if total else 0.0},
        "summary": summary,
    }
    # Small summary (committed, read by the dashboard) + full per-attempt dump (git-ignored).
    prefix.with_name(prefix.name + "-summary.json").write_text(
        json.dumps(overview, indent=1), encoding="utf-8"
    )
    prefix.with_suffix(".json").write_text(
        json.dumps({**overview, "attempts": rows}, ensure_ascii=False), encoding="utf-8"
    )
    if rows:
        with prefix.with_suffix(".csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)


def print_summary(profile: str, summary: dict) -> None:
    print(f"Defense profile: {profile}")
    print(f"{'family':<22} {'attempts':>8} {'breaches':>8}   ASR")
    for family, values in summary.items():
        print(f"{family:<22} {values['attempts']:>8} {values['breaches']:>8}  {values['asr']:6.1%}")
    attempts = sum(values["attempts"] for values in summary.values())
    breaches = sum(values["breaches"] for values in summary.values())
    print(f"{'TOTAL':<22} {attempts:>8} {breaches:>8}  {breaches / max(1, attempts):6.1%}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mutate", action="store_true", help="Include deterministic mutations")
    parser.add_argument("--profile", choices=sorted(PROFILES), default=None)
    parser.add_argument("--firewall", action="store_true", help="Shortcut for --profile full")
    parser.add_argument(
        "--llm-mutations",
        action="store_true",
        help="Also generate feedback-driven variants with the configured OpenAI-compatible model",
    )
    parser.add_argument("--llm-limit", type=int, default=4, help="Maximum seed prompts to mutate")
    parser.add_argument("--output", type=Path, default=None, help="Output file prefix")
    args = parser.parse_args()
    profile = args.profile or ("full" if args.firewall else "none")
    attacks = load_attacks(args.mutate)
    if args.llm_mutations:
        from .llm_mutator import mutate_with_feedback

        if args.llm_limit < 1:
            raise SystemExit("--llm-limit must be at least 1")
        for seed in load_seeds()[: args.llm_limit]:
            probe = run_scenario(seed, profile)
            feedback = (
                f"Previous outcome: {probe['outcome']} ({probe['reason']}); "
                f"stopped by: {', '.join(probe['stopped_by']) or 'nothing'}"
            )
            attacks.append(mutate_with_feedback(seed, feedback))
    records, summary = run(attacks, profile)
    prefix = args.output or ARTIFACTS / "fuzz" / profile
    write_artifacts(prefix, records, summary, {"profile": profile, "mutations": args.mutate})
    print_summary(profile, summary)
    print(f"Wrote {prefix.with_suffix('.json')} and {prefix.with_suffix('.csv')}")


if __name__ == "__main__":
    main()
