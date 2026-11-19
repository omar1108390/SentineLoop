"""Shared helpers for the evaluation scripts."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from fuzzer.mutators import mutate
from sentinelloop.corpus import Attack, attack_from_row, load_split
from sentinelloop.harness import BLOCK_MESSAGE, Defenses, run_scenario

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "evaluation"
OUT = ROOT / "artifacts" / "evaluation"
DETECTOR_LAYERS = {"rules", "classifier", "similarity"}


def write(name: str, payload: dict) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / name
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False), encoding="utf-8")
    return path


def attack_pool(split: str) -> list[Attack]:
    """The split's seed attacks plus one variant per mutation operator."""
    seeds = load_split(split, "attacks")
    return seeds + [variant for attack in seeds for variant in mutate(attack)]


def benign_rows(split: str) -> list[dict]:
    return json.loads((EVAL / split / "benign.json").read_text(encoding="utf-8"))


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def attack_metrics(pool: list[Attack], defenses: Defenses | str) -> dict[str, Any]:
    results = [run_scenario(attack, defenses) for attack in pool]
    breaches = [row for row in results if row["outcome"] == "breach"]
    families: dict[str, dict[str, int]] = {}
    for row in results:
        cell = families.setdefault(row["family"], {"attempts": 0, "breaches": 0})
        cell["attempts"] += 1
        cell["breaches"] += row["outcome"] == "breach"
    latencies = [row["latency_ms"] for row in results]
    return {
        "attempts": len(results),
        "breaches": len(breaches),
        "asr": len(breaches) / len(results) if results else 0.0,
        "by_family": {
            family: {**cell, "asr": cell["breaches"] / cell["attempts"]}
            for family, cell in sorted(families.items())
        },
        "latency_ms": {"p50": percentile(latencies, 0.5), "p95": percentile(latencies, 0.95)},
    }


def task_succeeded(row: dict, result: dict) -> bool:
    if result["outcome"] == "breach":
        return False
    response = result["transcript"][-1]["response"]
    if row["expected"] == "none":
        return bool(response.strip()) and response != BLOCK_MESSAGE
    return any(call["tool"] == row["expected"] for call in result["tool_calls"])


def benign_metrics(rows: list[dict], defenses: Defenses | str) -> dict[str, Any]:
    blocked = succeeded = 0
    false_positives = []
    for row in rows:
        result = run_scenario(attack_from_row(row, "benign"), defenses)
        flagged = [layer for layer in result["stopped_by"] if layer != "quarantine"]
        if flagged:
            blocked += 1
            false_positives.append({"id": row["id"], "layers": flagged, "prompt": row["prompt"]})
        succeeded += task_succeeded(row, result)
    count = len(rows)
    return {
        "count": count,
        "flagged": blocked,
        "fpr": blocked / count if count else 0.0,
        "task_success": succeeded,
        "utility": succeeded / count if count else 0.0,
        "false_positives": false_positives,
    }
