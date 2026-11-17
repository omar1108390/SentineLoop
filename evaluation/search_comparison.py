"""Descriptively compare archived GA and MAP-Elites candidates."""

import json
from pathlib import Path

ARTIFACTS = Path(__file__).resolve().parents[1] / "artifacts"


def summarize(path: str) -> dict:
    data = json.loads((ARTIFACTS / path).read_text(encoding="utf-8"))
    archive = data.get("archive", [])
    cells = {(row.get("family"), row.get("technique")) for row in archive}
    return {
        "archive_size": len(archive),
        "successful_candidates": sum(row.get("outcome") == "breach" for row in archive),
        "unique_families": len({row.get("family") for row in archive}),
        "unique_techniques": len({row.get("technique") for row in archive}),
        "family_technique_cells": len(cells),
        "search_steps": len(data.get("history", [])),
        "seed": data.get("seed"),
    }


def main() -> None:
    output = {
        "scope": "descriptive archived-candidate comparison; stored runs used different search budgets",
        "baseline": {
            "genetic": summarize("genetic-baseline.json"),
            "map_elites": summarize("map-elites-baseline.json"),
        },
        "firewall": {
            "genetic": summarize("genetic-firewall.json"),
            "map_elites": summarize("map-elites-firewall.json"),
        },
    }
    target = ARTIFACTS / "search-comparison.json"
    target.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output, indent=2))
    print(f"Wrote {target}")


if __name__ == "__main__":
    main()
