"""Log the benchmark results and firewall version to MLflow (optional).

python -m pip install -e ".[tracking]"
python -m evaluation.track_experiment
"""

import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
SOURCES = (
    "evaluation/profiles.json",
    "evaluation/ablation.json",
    "evaluation/stats.json",
    "hardening/report.json",
)


def _read(name: str) -> dict:
    return json.loads((ARTIFACTS / name).read_text(encoding="utf-8"))


def collect_metrics() -> tuple[dict[str, float], dict[str, str]]:
    profiles = _read("evaluation/profiles.json")["splits"]["holdout"]
    ablation = _read("evaluation/ablation.json")["configurations"]
    hardening = _read("hardening/report.json")["rounds"]
    metrics: dict[str, float] = {}
    for name, values in profiles.items():
        metrics[f"holdout.{name}.asr"] = values["attacks"]["asr"]
        metrics[f"holdout.{name}.fpr"] = values["benign"]["fpr"]
        metrics[f"holdout.{name}.utility"] = values["benign"]["utility"]
    for name, values in ablation.items():
        metrics[f"ablation.{name}.asr"] = values["asr"]
    for index, row in enumerate(hardening):
        metrics["hardening.holdout_detector_asr"] = row["holdout"]["detectors"]["asr"]
        metrics[f"hardening.v{index}.holdout_detector_asr"] = row["holdout"]["detectors"]["asr"]
    model = json.loads((ROOT / "firewall" / "models" / "injection_classifier.json").read_text())
    manifest = (ROOT / "evaluation" / "manifest.json").read_bytes()
    params = {
        "firewall_version": str(model.get("version", "v0")),
        "classifier_threshold": str(model.get("threshold")),
        "dataset_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "evaluation_scope": "synthetic-local-sandbox",
    }
    return metrics, params


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--experiment", default=os.getenv("MLFLOW_EXPERIMENT_NAME", "sentinelloop"))
    parser.add_argument("--run-name", default="local-benchmark")
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
        mlflow.set_tags({"firewall_version": params["firewall_version"], "holdout_locked": "true"})
        mlflow.log_params(params)
        mlflow.log_metrics(metrics)
        for artifact in SOURCES:
            mlflow.log_artifact(str(ARTIFACTS / artifact), artifact_path="evaluation")
    print(f"Logged {len(metrics)} metrics to MLflow experiment '{args.experiment}'.")


if __name__ == "__main__":
    main()
