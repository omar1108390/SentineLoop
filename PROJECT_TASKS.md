# SentinelLoop: Task List

Legend: `[ ]` to do, `[x]` done. Priority: **P0** = core (must have), **P1** = important, **P2** = stretch.
Suggested duration: about 6 weeks (adjust to your schedule).

---

## Phase 0: Setup and Planning (Days 1-3)

- [x] **P0** Create the Git repository with the folder structure from the project description
- [x] **P0** Write a short `README.md` (goal, how to run)
- [x] **P0** Set up Python environment (`pyproject.toml` or `requirements.txt`), linting (ruff), formatting (black), pre-commit
- [x] **P0** Add Docker Compose gateway, PostgreSQL, Redis, RQ worker, and fuzzer profile (sandbox target embedded)
- [x] **P0** Choose a hosted OpenAI-compatible Groq backend (`openai/gpt-oss-20b` default)
- [x] **P0** Test a live Groq completion after the local API key is configured (gateway returned HTTP 200)
- [x] **P0** Define the threat model and write the ethics/scope note (sandbox only, fake data)
- [x] **P1** Set up local MLflow experiment tracking and hash-locked dataset manifest versioning
- [ ] **P1** Add DVC remote storage for dataset artifact versioning
- [x] **P1** Set up GitHub Actions for tests, linting, and sandbox regression gating

**Done when:** `docker compose up` starts empty services and a hello-world LLM call works.

---

## Phase 1: Target App and Judge (Week 1)

### Target application
- [x] **P0** Build deterministic sandbox email-assistant agent
- [x] **P0** Implement in-memory fake tools: `read_email`, `send_email`, `search_files`, `calendar_add`, `calendar_view`
- [x] **P0** Add fake secret and canary to the sandbox agent (prompt-template separation pending)
- [x] **P0** Add a seeded-email retrieval path for indirect injection
- [x] **P0** Make fake `send_email` a logged in-memory no-op
- [x] **P1** Add 30 benign prompts for FPR/utility evaluation

### Judge
- [x] **P0** Implement objective checks for canary leakage, forbidden tool calls, and unexpected state
- [x] **P0** Define outcome labels: `blocked`, `allowed-harmless`, `breach`
- [x] **P1** Implement optional tool-free LLM-as-judge with a written rubric for ambiguous cases
- [x] **P1** Prepare a seeded blinded 120-attempt annotation export and accuracy scorer
- [ ] **P1** Hand-label 100+ attempts and measure judge accuracy
- [x] **P0** Unit tests for each judge rule

**Done when:** you can manually send an injection to the agent, and the judge correctly reports a breach.

---

## Phase 2: Attack Corpus and Baseline Fuzzer (Week 2)

### Data
- [x] **P0** Create local seed corpus for the sandbox target (external datasets remain pending)
- [x] **P0** Categorize initial seeds into override, role-play, leak, delimiter, indirect, and benign families (additional families pending)
- [x] **P0** Split the local corpus into stratified train / validation / holdout files and verify holdout SHA-256 lock (external benchmark splits pending)
- [x] **P1** Add 30 sandbox benign request prompts (benign documents/emails pending)

### Fuzzer v1
- [x] **P0** Implement paraphrase, base64/ROT13, Unicode, document wrapping, and distractor mutations (translation pending)
- [x] **P0** Implement fuzzer runner with JSON/CSV artifacts and SQLite/PostgreSQL attempt persistence
- [x] **P0** Implement seeded genetic search with elite selection, mutation, crossover, and breach fitness
- [x] **P1** Add opt-in LLM-driven mutation using sandbox outcome feedback (live provider run pending)
- [x] **P1** Add multi-turn attack support with persistent conversation state
- [x] **P0** Run reproducible no-firewall baseline and report ASR per family

**Done when:** one command runs N attacks against the unprotected app and produces a per-family ASR table.

---

## Phase 3: Firewall v1 (Week 3)

### Gateway
- [x] **P0** Build the FastAPI OpenAI-compatible proxy with sandbox default, optional upstream, input/output firewall checks and buffered SSE responses
- [x] **P0** Define a common inspection result with verdict, score, reason, and latency (context interface refinement pending)
- [x] **P0** Emit JSON decision logs with layer, score, verdict, reason, and latency

### Layers
- [x] **P0** **L0 Normalizer:** decode base64/rot13/URL, strip zero-width characters, normalize compatibility Unicode, and inspect HTML/comment text
- [x] **P0** Train a logistic-regression baseline classifier on the train split and evaluate on validation (DeBERTa-v3/ModernBERT fine-tuning remains pending)
- [ ] **P1** Export classifier to ONNX and benchmark latency
- [x] **P1** **L2 Similarity:** add TF-IDF cosine index over train attacks (sentence-transformer dense embeddings and FAISS/Qdrant pending)
- [x] **P0** **L5 Output guard:** detect and redact the fake secret and canary (broader sensitive-data patterns pending)
- [x] **P1** **L4 Policy engine:** add a Python allowlist for sandbox tool calls, strict arguments, provenance, and explicit approval (OPA/Rego runtime pending)
- [ ] **P1** **L3 Quarantine (dual-LLM):** small model reads untrusted content without tools, outputs validated JSON only

### Baselines and measurement
- [x] **P1** Add no-defense and keyword-filter baselines for comparison
- [ ] **P1** Add Prompt Guard and Llama Guard model baselines
- [x] **P0** Run fuzzer against prototype firewall and record ASR, benign block rate, and inspection latency (broader benchmark pending)
- [x] **P0** Tag firewall v1 in local MLflow runs with corpus manifest hash

**Done when:** firewall v1 measurably lowers ASR versus baseline, with FPR and latency reported.

---

## Phase 4: Advanced Fuzzer: MAP-Elites (Week 3-4)

- [x] **P0** Define MAP-Elites behavior dimensions as attack family x mutation technique
- [x] **P0** Implement MAP-Elites archive and mutation emitter with breach fitness (custom implementation; pyribs integration pending)
- [x] **P1** Visualize archive cells by family and mutation technique with best fitness and outcome
- [x] **P1** Compare GA vs. MAP-Elites archive diversity and bypass candidates (exploratory; search budgets differ)
- [x] **P1** Queue asynchronous fuzzer runs with Redis + RQ worker
- [ ] **P2** RL fine-tune a small attacker model (TRL, GRPO/PPO) with bypass as reward

**Done when:** the fuzzer finds a diverse set of bypasses against firewall v1 and the archive is visualized.

---

## Phase 5: Closed Loop and Hardening (Week 4-5)

- [x] **P0** Summarize training breaches by family and record layer verdicts (clustering pending)
- [x] **P0** Build a training dataset from observed breaches plus benign counterexamples
- [x] **P0** Add exact normalized attack signatures as a rule hardening version (classifier retraining pending)
- [x] **P0** Evaluate each rule version on SHA-256-locked holdout data that is excluded from hardening
- [x] **P0** Implement one command for attack, judge, analyze, harden, and holdout re-evaluation
- [x] **P0** Run four rounds (v0 to v4) and record metrics (no bypasses were found, so no hardening rules were added)
- [x] **P1** Automate sandbox regression checks in GitHub Actions
- [ ] **P2** Add taint tracking / provenance labels enforced at tool-call time

**Done when:** you have a table and graph of ASR and FPR across firewall versions, including holdout results.

---

## Phase 6: Dashboard and Observability (Week 5)

- [x] **P0** Dashboard panel: genetic-search ASR by generation and holdout ASR/FPR by firewall version
- [x] **P0** Dashboard panel: live firewall inspection feed (allowed / blocked; attempt outcomes pending)
- [x] **P1** Dashboard panels: attack-family vs. defense-layer activity and MAP-Elites archive-cell heatmap
- [x] **P1** Dashboard panel: top baseline breaches with payload and judge reason (failing-layer attribution pending)
- [x] **P1** Dashboard panel: live inspection latency p95 and holdout FPR by version (full benchmark p50/p95 panels pending)
- [ ] **P1** Add OpenTelemetry tracing and Langfuse/Phoenix for LLM traces
- [ ] **P2** Custom Next.js + WebSocket live dashboard (instead of Grafana only)

**Done when:** a live demo shows an attack run and the dashboard updating in real time.

---

## Phase 7: Evaluation and Analysis (Week 6)

- [x] **P0** Ablate the rules, classifier, and similarity input detectors on validation/locked holdout with ASR/FPR/latency
- [x] **P0** Extend ablations to output redaction and tool-policy enforcement
- [x] **P0** Compare no-defense and keyword-filter baselines on validation/holdout
- [ ] **P0** Compare Prompt Guard and Llama Guard baselines
- [ ] **P0** Evaluate on external benchmarks (AgentDojo, BIPIA) for generalization
- [x] **P0** Compute cluster-bootstrap confidence intervals and paired cluster permutation comparison for the local corpus (external repeated runs pending)
- [x] **P0** Measure deterministic benign-task success with vs. without the firewall using 30 manually labeled sandbox prompts
- [ ] **P1** Report judge accuracy versus hand labels
- [x] **P1** Analyze remaining weaknesses by family (for the included synthetic corpus)
- [ ] **P1** Compare with existing tools (garak, PyRIT, promptfoo) on the same target
- [ ] **P2** One research add-on: activation probing, multimodal injections, or Z3 policy verification

---

## Phase 8: Documentation and Delivery (Final week)

- [x] **P0** Final report: motivation, architecture, method, results, limitations, ethics, future work
- [x] **P0** Generate all figures from code (reproducible notebooks)
- [x] **P0** Polish `README.md` with quick start and one-command demo
- [x] **P0** Provide a reproducibility guide (seeds, versions, dataset splits, hardware)
- [ ] **P1** Record a 3-5 minute demo video
- [ ] **P1** Prepare presentation slides
- [x] **P1** Add a `SECURITY.md` / responsible-use note
- [x] **P1** Clean code and add regression tests
- [ ] **P1** Tag release `v1.0` after the remaining research items are resolved

---

## Milestone Checklist

| Milestone | Description | Target |
|---|---|---|
| **M1** | Target app and judge working | End of Week 1 |
| **M2** | Baseline fuzzer and no-firewall ASR | End of Week 2 |
| **M3** | Firewall v1 with measured improvement | End of Week 3 |
| **M4** | MAP-Elites fuzzer with diversity visualization | Week 4 |
| **M5** | Closed loop running, 3+ hardening rounds, holdout results | Week 5 |
| **M6** | Dashboard and ablation results | Week 5-6 |
| **M7** | Final report, demo, and release | End of Week 6 |

---

## Minimum Viable Version (if time is short)

Do only these **P0** items for a complete, defensible project:

1. Target app with fake tools and canary token
2. Objective judge
3. Seed corpus with train/holdout split
4. Fuzzer with a genetic algorithm and 4-5 mutation operators
5. Firewall with normalizer, classifier, and output canary check
6. Two hardening rounds with before/after ASR and FPR on holdout
7. Simple dashboard (even a notebook) and a written report

---

## Weekly Review Questions

- Did ASR go down on the **holdout** set, not just the training attacks?
- Did FPR stay acceptably low?
- Is every number reproducible from a single command?
- What is the weakest attack family right now, and why?
