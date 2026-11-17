"""RQ jobs for asynchronous fuzzer runs."""

import csv
import json
import os
from pathlib import Path
from typing import Any

from fuzzer.runner import load_attacks, run


def run_fuzzer_job(include_mutations: bool = True, use_firewall: bool = True) -> dict[str, Any]:
    records, summary = run(load_attacks(include_mutations), use_firewall)
    job_id = records[0].get("run_id", "unknown") if records else "empty"
    artifacts = Path(os.getenv("SENTINELLOOP_ARTIFACTS_DIR", "artifacts")) / "jobs"
    artifacts.mkdir(parents=True, exist_ok=True)
    prefix = artifacts / job_id
    artifact_records = [
        {key: value for key, value in record.items() if key != "run_id"} for record in records
    ]
    prefix.with_suffix(".json").write_text(
        json.dumps({"summary": summary, "attempts": artifact_records}, indent=2), encoding="utf-8"
    )
    if artifact_records:
        with prefix.with_suffix(".csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=artifact_records[0].keys())
            writer.writeheader()
            writer.writerows(artifact_records)
    return {"run_id": job_id, "summary": summary, "artifact": str(prefix.with_suffix(".json"))}
