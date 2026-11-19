"""Compare what the genetic algorithm and MAP-Elites found (descriptive only).

python -m evaluation.search_comparison
"""

import json
from pathlib import Path

from .common import write

SEARCH = Path(__file__).resolve().parents[1] / "artifacts" / "search"


def summarize(path: Path) -> dict | None:
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    archive = data.get("archive", [])
    breaches = [row for row in archive if row.get("fitness", 0) >= 1]
    return {
        "evaluations": data.get("evaluations"),
        "archive_size": len(archive),
        "breach_candidates": len(breaches),
        "breach_families": sorted({row.get("family") for row in breaches}),
        "breach_cells": len({(row.get("family"), row.get("technique")) for row in breaches}),
        "seed": data.get("seed"),
    }


def main() -> None:
    result = {
        "scope": "descriptive; the two algorithms ran with different evaluation budgets",
        "profiles": {
            profile: {
                "genetic": summarize(SEARCH / f"genetic-{profile}.json"),
                "map_elites": summarize(SEARCH / f"map-elites-{profile}.json"),
            }
            for profile in ("none", "detectors", "full")
        },
    }
    print(json.dumps(result, indent=1))
    print(f"Wrote {write('search.json', result)}")


if __name__ == "__main__":
    main()
