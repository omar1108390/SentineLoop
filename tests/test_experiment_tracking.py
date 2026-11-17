from evaluation.track_experiment import collect_metrics


def test_mlflow_export_metrics_include_core_results_and_version_tag():
    metrics, params = collect_metrics()
    assert metrics["holdout.firewall.asr"] == 0.0
    assert metrics["holdout.output.raw_canary_leaks"] == 6
    assert metrics["holdout.output.guarded_canary_leaks"] == 0
    assert params["firewall_version"] == "v1"
    assert len(params["dataset_manifest_sha256"]) == 64
