# SentinelLoop

SentinelLoop is a sandbox-only project for measuring and improving defenses against prompt injection. Its demo target uses fake data and fake tools; sending email is always a logged no-op.

## Run the API gateway

Requires Python 3.11+. Install the package and API dependencies. To enable the asynchronous fuzzer endpoints locally, install the `jobs` extra and run a Redis server:

```powershell
python -m pip install -e ".[jobs]"
python -m uvicorn firewall.gateway.app:app --host 127.0.0.1 --port 8000
```

Local runs use SQLite at `artifacts/sentinelloop.db` for durable firewall decisions and fuzzer attempts. Docker Compose uses PostgreSQL for those records. The default target backend is the local fake email assistant. Open `http://127.0.0.1:8000/docs` for interactive API docs. The gateway exposes `/health`, `/v1/models`, `/v1/events`, `/v1/metrics`, asynchronous fuzzer run endpoints (`POST /v1/fuzzer/runs` and `GET /v1/fuzzer/runs/{job_id}`), an OpenAI-compatible `POST /v1/chat/completions` endpoint, and a live dashboard at `http://127.0.0.1:8000/dashboard`.

Example request from another PowerShell window:

```powershell
$body = @{
  model = "sentinelloop-sandbox"
  messages = @(@{ role = "user"; content = "Summarize my unread email" })
} | ConvertTo-Json -Depth 6
Invoke-RestMethod http://127.0.0.1:8000/v1/chat/completions -Method Post -ContentType "application/json" -Body $body
```

The gateway checks user prompts and retrieved email content, blocks matching inputs, redacts the fake secret/canary in outputs, and logs each inspection as JSON. The dashboard shows benchmark ASR by attack family and generation, holdout ASR by firewall version, a family/layer heatmap, top baseline breaches, and the latest persisted gateway decisions; SQLite/PostgreSQL keeps them across restarts. Streaming is not implemented. Upstream-generated tool calls pass the L4 sandbox allowlist and argument checks; side-effect calls require trusted approval. Calls are still withheld from clients because a sandbox tool executor is not connected.

To proxy to an OpenAI-compatible backend, set `SENTINELLOOP_UPSTREAM_URL` to its API base URL (for example one ending in `/v1`), `SENTINELLOOP_MODEL` to its model name, and `SENTINELLOOP_API_KEY` if required. See `.env.example`; the gateway reads these from the process environment and never loads `.env` automatically. This path has not been verified against a live provider.

## Run with Docker Compose

Docker Desktop must be running. From the repository root:

```powershell
docker compose up --build
```

This starts the gateway on `http://localhost:8000` with the sandbox backend, plus PostgreSQL, Redis, and a background RQ worker. Stop it with `Ctrl+C`; run detached with `docker compose up --build -d` and stop with `docker compose down`. Containers run as an unprivileged user with a read-only root filesystem. Submit an asynchronous run with `POST /v1/fuzzer/runs` and check it with `GET /v1/fuzzer/runs/{job_id}`. For example:

```powershell
$job = Invoke-RestMethod http://localhost:8000/v1/fuzzer/runs -Method Post -ContentType "application/json" -Body '{"include_mutations":true,"use_firewall":true}'
Invoke-RestMethod "http://localhost:8000/v1/fuzzer/runs/$($job.job_id)"
```

To run the fuzzer as a separate one-off Compose task and write its JSON/CSV artifacts plus attempts to PostgreSQL, use:

```powershell
docker compose --profile tools run --rm fuzzer
```

The gateway returns `503` from the queue endpoints if Redis is unavailable.

## Run the local benchmark

```powershell
python -m target_app --demo
python -m fuzzer.runner --mutate
python -m fuzzer.runner --mutate --firewall  # includes multi-turn seed attacks
python -m fuzzer.search.genetic --generations 5 --population 20
python -m fuzzer.search.genetic --generations 5 --population 20 --firewall
python -m fuzzer.search.map_elites --iterations 200
python -m fuzzer.search.map_elites --iterations 200 --firewall
python -m pip install -e ".[train]"  # only needed to retrain the L1 model
python -m hardening.training.train_classifier
python -m evaluation.layer_report
python -m evaluation.ablation  # disable each input detector in turn on validation/locked holdout
python -m evaluation.split_corpus --verify
python -m hardening.run_round --rounds 4
```

The fuzzer runs each prompt in a fresh sandbox and writes JSON/CSV per-attempt details and per-family ASR under `artifacts/`. It also stores attempt records in the configured database. Local SQLite is the default; set `SENTINELLOOP_DATABASE_URL` to a PostgreSQL URL and install `python -m pip install -e ".[storage]"` to use PostgreSQL outside Compose. The genetic search evolves prompt variants with a fixed random seed and stores its generation history and final archive there too. MAP-Elites keeps candidates in a family-by-technique archive and reports coverage and breach cells. The round runner attacks training data, builds an exact-match rule set from observed breaches and benign counterexamples, then measures ASR and FPR on the hash-locked holdout.

The current local corpus has 24 attack seeds (including four two-turn attacks) and 30 benign prompts. The mutation run recorded baseline ASR of 97/168 (57.7%) and firewall ASR of 0/168. On the locked holdout, the unprotected target breached on 6/6 attacks; the firewall breached on 0/6 and blocked 0/3 benign prompts. Four hardening rounds ran (v0 to v4), but the current firewall found no training bypasses, so it added no learned rules and showed no adaptation gain. The validation/holdout layer report evaluates the trained L1 logistic-regression model and L2 TF-IDF index separately and together; the combined detector catches all attacks in both splits (6/6 validation and 6/6 holdout) at validation-selected thresholds (L1 0.30; L2 0.55), with 0/3 benign prompts flagged in each. The input-detector ablation is in `artifacts/ablation.json`: removing L1 leaves one of six holdout attacks undetected, while the rules and TF-IDF layers each have no measured effect on this tiny split. This result is directional only; the synthetic sample is too small to support general security claims. The firewall combines heuristic rules with compact trained L1 and TF-IDF L2 detectors; it remains a prototype, not a production gateway.

## Code map

- `target_app/`: intentionally vulnerable deterministic email assistant and fake tools.
- `target_app/judge.py`: objective canary, tool-call, and state-change checks.
- `fuzzer/`: categorized seeds, mutation operators, runner, genetic search, and MAP-Elites.
- `firewall/gateway/app.py`: HTTP API and optional OpenAI-compatible upstream.
- `firewall/layers/`: normalizer, heuristic rules, trained L1 model, TF-IDF similarity, exact-match hardening, and output guard.
- `firewall/policies/`: allowlisted fake-tool arguments and approval rules.
- `evaluation/`: 30 benign tasks, stratified train/validation/holdout split, holdout integrity verification, and layer metrics.
- `hardening/run_round.py`: reproducible attack/judge/analyze/harden/holdout loop.
- `artifacts/`: sample benchmark output.

See `PROJECT_DESCRIPTION.md` and `PROJECT_TASKS.md` for the full architecture and roadmap.
