"""Log checked-in benchmark outputs and firewall version tags to local or remote MLflow."""

import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"


def _read(name: str) -> dict:
    return json.loads((ARTIFACTS / name).read_text(encoding="utf-8"))


def collect_metrics() -> tuple[dict[str, float], dict[str, str]]:
    comparison = _read("baseline-comparison.json")
    input_ablation = _read("ablation.json")
    guard_ablation = _read("guard-ablation.json")
    stats = _read("benchmark-stats.json")
    utility = _read("utility-report.json")
    holdout = comparison["splits"]["holdout"]
    guards = guard_ablation["splits"]["holdout"]
    ablation = input_ablation["splits"]["holdout"]
    metrics = {
        "holdout.no_defense.asr": holdout["no_defense"]["asr"],
        "holdout.keyword.asr": holdout["keyword_filter"]["asr"],
        "holdout.firewall.asr": holdout["layered_firewall"]["asr"],
        "holdout.firewall.fpr": holdout["layered_firewall"]["false_positive_rate"],
        "holdout.firewall.p95_ms": holdout["layered_firewall"]["p95_latency_ms"],
        "holdout.without_classifier.asr": ablation["without_classifier"]["asr"],
        "holdout.output.raw_canary_leaks": guards["output_redaction"]["raw_canary_leaks"],
        "holdout.output.guarded_canary_leaks": guards["output_redaction"]["guarded_canary_leaks"],
        "holdout.policy.attack_denial_rate": guards["tool_policy"]["attack_denial_rate"],
        "benign.utility.success_rate": utility["firewall_success_rate"],
        "generated.baseline.asr": stats["baseline_asr"],
        "generated.firewall.asr": stats["firewall_asr"],
        "generated.cluster_bootstrap.baseline_ci_low": stats["baseline_asr_ci95"][0],
        "generated.cluster_bootstrap.baseline_ci_high": stats["baseline_asr_ci95"][1],
        "generated.paired_sign_flip_p": stats["cluster_permutation"]["two_sided_p_value"],
    }
    manifest = (ROOT / "evaluation" / "manifest.json").read_bytes()
    params = {
        "firewall_version": "v1",
        "dataset_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "evaluation_scope": "synthetic-local-sandbox",
        "similarity_threshold": str(comparison.get("threshold", "0.55")),
    }
    return metrics, params


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment", default=os.getenv("MLFLOW_EXPERIMENT_NAME", "sentinelloop"))
    parser.add_argument("--run-name", default="firewall-v1-local-benchmark")
    args = parser.parse_args()
    try:
        import mlflow
    except ImportError as error:
        raise SystemExit(
            'Install the optional tracker with: python -m pip install -e ".[tracking]"'
        ) from error
    metrics, params = collect_metrics()
    mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "sqlite:///mlflow.db"))
    mlflow.set_experiment(args.experiment)
    with mlflow.start_run(run_name=args.run_name):
        mlflow.set_tags(
            {
                "firewall_version": "v1",
                "dataset_scope": "synthetic-local-sandbox",
                "holdout_sha256_locked": "true",
            }
        )
        mlflow.log_params(params)
        mlflow.log_metrics(metrics)
        for artifact in (
            "baseline-comparison.json",
            "ablation.json",
            "guard-ablation.json",
            "benchmark-stats.json",
            "utility-report.json",
        ):
            mlflow.log_artifact(str(ARTIFACTS / artifact), artifact_path="evaluation")
    print(f"Logged {len(metrics)} metrics to MLflow experiment '{args.experiment}'.")


if __name__ == "__main__":
    main()
