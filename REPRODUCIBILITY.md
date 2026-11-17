# Reproducibility guide

SentinelLoop's benchmark commands target only its deterministic fake email agent. They do not call a hosted LLM unless you explicitly configure the gateway and send a chat request.

## Environment

- Python 3.11 or newer; the development workflow uses Python 3.12.
- The core sandbox and evaluation need no GPU.
- Docker Desktop is needed for the gateway, PostgreSQL, and Redis/RQ stack.
- Optional report generation uses Matplotlib. Optional classifier retraining uses scikit-learn.
- The current report artifacts were produced on a local Windows/Python 3.12.7 environment. Hardware details were not recorded; timing numbers should be regenerated on the machine being evaluated.

## Install and verify

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,train,report]"
python -m pytest -q
python -m ruff check .
python -m evaluation.split_corpus --verify
```

Do not add API keys to Git. For the optional Groq gateway, put `SENTINELLOOP_UPSTREAM_URL`, `SENTINELLOOP_MODEL`, and a newly rotated `SENTINELLOOP_API_KEY` in ignored local `.env`, then start Docker Compose. A successful `/health` response only verifies the local gateway process; a chat completion is required to verify hosted access.

## Regenerate evaluation data

The attack seed corpus is `fuzzer/seeds/attacks.json`; benign examples and labels are in `evaluation/benign/`. The train/validation/holdout split is generated deterministically from seed `sentinelloop-v1` by `evaluation.split_corpus`. Its manifest records hashes; `--verify` must pass before using holdout results. The locked holdout is not used for model fitting or hardening.

```powershell
python -m evaluation.split_corpus
python -m evaluation.split_corpus --verify
python -m fuzzer.runner --mutate
python -m fuzzer.runner --mutate --firewall
# Optional, uses hosted tokens: python -m fuzzer.runner --mutate --firewall --llm-mutations --llm-limit 4
python -m evaluation.layer_report
python -m evaluation.ablation
python -m evaluation.guard_ablation
python -m evaluation.compare_baselines
python -m evaluation.search_comparison
python -m evaluation.benchmark_stats
python -m evaluation.utility_report
python -m hardening.run_round --rounds 4
python -m evaluation.generate_report
```

Fuzzer and split routines use fixed seeds where randomized operations occur. The commands write JSON/CSV records to `artifacts/`; several writes replace prior generated outputs. Preserve or copy artifacts before rerunning if you need to retain a previous experiment. Inspect each artifact's `scope`, seed, and dataset provenance before combining metrics. Do not compare latencies from different machines as if they were controlled measurements.

## Run the service stack

```powershell
docker compose up --build
```

Open `http://127.0.0.1:8000/docs` for API exploration and `http://127.0.0.1:8000/dashboard` for the local dashboard. The demo tools store only in-memory fake data; the database stores firewall and fuzzer event records. No real email, calendar, or network tool is invoked by the sandbox target.

## Optional model-assisted evaluation

`LLMJudge` and the `--llm-mutations` fuzzer mode are opt-in. Set `SENTINELLOOP_JUDGE_MODEL` or `SENTINELLOOP_ATTACKER_MODEL` to override the shared configured model. In Docker Compose's `tools` profile these environment variables are forwarded from your ignored `.env`. Model judgments are advisory and must not replace human labels until validated against an independent labeled sample.

## MLflow experiment tracking

Install the optional extra and log the checked-in evaluation artifacts:

```powershell
python -m pip install -e ".[tracking]"
python -m evaluation.track_experiment
```

The default tracking store is local `mlflow.db` (ignored by Git). Set `MLFLOW_TRACKING_URI` and `MLFLOW_EXPERIMENT_NAME` to use a remote MLflow server or a different experiment. Each run records firewall version, corpus manifest hash, scope tags, benchmark metrics, and source JSON artifacts.
