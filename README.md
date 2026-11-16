# SentinelLoop

SentinelLoop is a sandbox-only project for measuring and improving defenses against prompt injection. Its demo target uses fake data and fake tools; sending email is always a logged no-op.

## Run the API gateway

Requires Python 3.11+. Install the package and API dependencies:

```powershell
python -m pip install -e .
python -m uvicorn firewall.gateway.app:app --host 127.0.0.1 --port 8000
```

The default backend is the local fake email assistant. Open `http://127.0.0.1:8000/docs` for interactive API docs. The gateway exposes `/health`, `/v1/models`, and an OpenAI-compatible `POST /v1/chat/completions` endpoint.

Example request from another PowerShell window:

```powershell
$body = @{
  model = "sentinelloop-sandbox"
  messages = @(@{ role = "user"; content = "Summarize my unread email" })
} | ConvertTo-Json -Depth 6
Invoke-RestMethod http://127.0.0.1:8000/v1/chat/completions -Method Post -ContentType "application/json" -Body $body
```

The gateway checks user prompts and retrieved email content, blocks matching inputs, redacts the fake secret/canary in outputs, and logs each inspection as JSON. Streaming is not implemented. Upstream-generated tool calls are blocked because no tool authorization policy is configured.

To proxy to an OpenAI-compatible backend, set `SENTINELLOOP_UPSTREAM_URL` to its API base URL (for example one ending in `/v1`), `SENTINELLOOP_MODEL` to its model name, and `SENTINELLOOP_API_KEY` if required. See `.env.example`; the gateway reads these from the process environment and never loads `.env` automatically. This path has not been verified against a live provider.

## Run with Docker Compose

Docker Desktop must be running. From the repository root:

```powershell
docker compose up --build
```

This starts the gateway on `http://localhost:8000` with the sandbox backend. Stop it with `Ctrl+C`; run detached with `docker compose up --build -d` and stop with `docker compose down`. The container runs as an unprivileged user with a read-only root filesystem. PostgreSQL and Redis are not wired in yet.
## Run the local benchmark

```powershell
python -m target_app --demo
python -m fuzzer.runner --mutate
python -m fuzzer.runner --mutate --firewall
python -m fuzzer.search.genetic --generations 5 --population 20
python -m fuzzer.search.genetic --generations 5 --population 20 --firewall
python -m fuzzer.search.map_elites --iterations 200
python -m fuzzer.search.map_elites --iterations 200 --firewall
```

The fuzzer runs each prompt in a fresh sandbox and writes JSON/CSV per-attempt details and per-family ASR under `artifacts/`. The genetic search evolves prompt variants with a fixed random seed and stores its generation history and final archive there too. MAP-Elites keeps candidates in a family-by-technique archive and reports coverage and breach cells.

The checked-in sample run has 35 non-benign attacks and three benign prompts: baseline ASR is 25/35 (71.4%); the heuristic firewall ASR is 0/35, with 0/3 benign prompts blocked. This tiny self-generated corpus checks the software path only; it does not establish general security. The firewall is a research prototype, not a trained classifier or production gateway.

## Code map

- `target_app/`: intentionally vulnerable deterministic email assistant and fake tools.
- `target_app/judge.py`: objective canary, tool-call, and state-change checks.
- `fuzzer/`: categorized seeds, mutation operators, runner, and genetic search.
- `firewall/gateway/app.py`: HTTP API and optional OpenAI-compatible upstream.
- `firewall/layers/`: normalizer, transparent heuristic classifier, and output guard.
- `artifacts/`: sample benchmark output.

See `PROJECT_DESCRIPTION.md` and `PROJECT_TASKS.md` for the full architecture and roadmap.
