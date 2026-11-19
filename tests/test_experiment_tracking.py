import pytest

from evaluation.track_experiment import ARTIFACTS, collect_metrics


@pytest.mark.skipif(
    not (ARTIFACTS / "evaluation" / "profiles.json").is_file(), reason="run the benchmark first"
)
def test_mlflow_export_metrics_include_core_results_and_version_tag():
    metrics, params = collect_metrics()
    assert 0 <= metrics["holdout.full.asr"] <= metrics["holdout.none.asr"] <= 1
    assert "ablation.full.asr" in metrics
    assert params["firewall_version"].startswith("v")
    assert len(params["dataset_manifest_sha256"]) == 64
