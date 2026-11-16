# SentinelLoop: Task List

Legend: `[ ]` to do, `[x]` done. Priority: **P0** = core (must have), **P1** = important, **P2** = stretch.
Suggested duration: about 6 weeks (adjust to your schedule).

---

## Phase 0: Setup and Planning (Days 1-3)

- [ ] **P0** Create the Git repository with the folder structure from the project description
- [ ] **P0** Write a short `README.md` (goal, how to run)
- [ ] **P0** Set up Python environment (`pyproject.toml` or `requirements.txt`), linting (ruff), formatting (black), pre-commit
- [ ] **P0** Create `docker-compose.yml` skeleton (gateway, target app, Redis, PostgreSQL)
- [ ] **P0** Decide model strategy: local (Ollama/vLLM) vs. API; test one model end to end
- [ ] **P0** Define the threat model and write the ethics/scope note (sandbox only, fake data)
- [ ] **P1** Set up experiment tracking (MLflow or W&B) and dataset versioning (DVC)
- [ ] **P1** Set up GitHub Actions for tests and linting

**Done when:** `docker compose up` starts empty services and a hello-world LLM call works.

---

## Phase 1: Target App and Judge (Week 1)

### Target application
- [ ] **P0** Build the demo email-assistant agent (LangGraph or MCP)
- [ ] **P0** Implement fake tools: `read_email`, `send_email`, `search_files`, `calendar_add`
- [ ] **P0** Add a system prompt with a **fake secret** and a **canary token**
- [ ] **P0** Add a document/RAG input path to enable indirect injection (emails, web pages, files)
- [ ] **P0** Make `send_email` a logged no-op (no real network access)
- [ ] **P1** Write 30+ benign tasks the agent should handle correctly (used for utility and FPR)

### Judge
- [ ] **P0** Implement objective checks: canary leaked, forbidden tool called, unexpected state change
- [ ] **P0** Define outcome labels: `blocked`, `allowed-harmless`, `breach`
- [ ] **P1** Implement LLM-as-judge with a written rubric for ambiguous cases
- [ ] **P1** Hand-label 100+ attempts and measure judge accuracy
- [ ] **P0** Unit tests for each judge rule

**Done when:** you can manually send an injection to the agent, and the judge correctly reports a breach.

---

## Phase 2: Attack Corpus and Baseline Fuzzer (Week 2)

### Data
- [x] **P0** Create local seed corpus for the sandbox target (external datasets remain pending)
- [x] **P0** Categorize initial seeds into override, role-play, leak, delimiter, indirect, and benign families (additional families pending)
- [ ] **P0** Split into **train / validation / holdout** and lock the holdout set
- [ ] **P1** Build a benign dataset (realistic user requests, documents, emails)

### Fuzzer v1
- [x] **P0** Implement paraphrase, base64/ROT13, Unicode, document wrapping, and distractor mutations (translation pending)
- [x] **P0** Implement local attack runner with JSON/CSV records (PostgreSQL integration pending)
- [x] **P0** Implement seeded genetic search with elite selection, mutation, crossover, and breach fitness
- [ ] **P1** Add LLM-driven mutation (attacker LLM rewrites payloads using failure feedback)
- [ ] **P1** Add multi-turn attack support (conversation state)
- [x] **P0** Run reproducible no-firewall baseline and report ASR per family

**Done when:** one command runs N attacks against the unprotected app and produces a per-family ASR table.

---

## Phase 3: Firewall v1 (Week 3)

### Gateway
- [x] **P0** Build the FastAPI OpenAI-compatible proxy with sandbox default, optional upstream, input/output firewall checks (streaming remains pending)
- [x] **P0** Define a common inspection result with verdict, score, reason, and latency (context interface refinement pending)
- [x] **P0** Emit JSON decision logs with layer, score, verdict, reason, and latency

### Layers
- [x] **P0** **L0 Normalizer:** decode base64/rot13/URL, strip zero-width characters, normalize compatibility Unicode, and inspect HTML/comment text
- [ ] **P0** **L1 Classifier:** fine-tune DeBERTa-v3 or ModernBERT on the train split; evaluate on validation
- [ ] **P1** Export classifier to ONNX and benchmark latency
- [ ] **P1** **L2 Similarity:** embed known attacks (sentence-transformers) and index with FAISS/Qdrant
- [x] **P0** **L5 Output guard:** detect and redact the fake secret and canary (broader sensitive-data patterns pending)
- [ ] **P1** **L4 Policy engine:** write OPA/Rego rules for tool calls (e.g., untrusted-origin data cannot trigger `send_email`)
- [ ] **P1** **L3 Quarantine (dual-LLM):** small model reads untrusted content without tools, outputs validated JSON only

### Baselines and measurement
- [ ] **P1** Add off-the-shelf baselines (Prompt Guard, Llama Guard, keyword filter) for comparison
- [x] **P0** Run fuzzer against prototype firewall and record ASR, benign block rate, and inspection latency (broader benchmark pending)
- [ ] **P0** Tag firewall v1 in MLflow/W&B

**Done when:** firewall v1 measurably lowers ASR versus baseline, with FPR and latency reported.

---

## Phase 4: Advanced Fuzzer: MAP-Elites (Week 3-4)

- [ ] **P0** Define behavior dimensions for the MAP-Elites grid (e.g., attack family x technique/obfuscation level)
- [ ] **P0** Implement MAP-Elites with pyribs (archive, emitters, fitness = breach success)
- [ ] **P1** Visualize the archive as a heatmap (coverage and best fitness per cell)
- [ ] **P1** Compare GA vs. MAP-Elites on attack diversity and bypass count
- [ ] **P1** Parallelize attack execution with Celery + Redis (or Ray)
- [ ] **P2** RL fine-tune a small attacker model (TRL, GRPO/PPO) with bypass as reward

**Done when:** the fuzzer finds a diverse set of bypasses against firewall v1 and the archive is visualized.

---

## Phase 5: Closed Loop and Hardening (Week 4-5)

- [ ] **P0** Build the **bypass analysis** step: cluster successful attacks and identify failing layers
- [ ] **P0** Build the **dataset builder**: bypasses plus matching benign counterexamples become new training data
- [ ] **P0** Retrain the classifier and add new normalizer/policy rules, producing firewall v2
- [ ] **P0** Evaluate v2 on the **holdout set** (never used in hardening) to detect overfitting
- [ ] **P0** Write a single `run_round` command that executes: attack, judge, analyze, harden, re-evaluate
- [ ] **P0** Run at least 3-5 rounds (v0 to v4) and record all metrics
- [ ] **P1** Automate the loop in GitHub Actions as a red-team regression test
- [ ] **P2** Add taint tracking / provenance labels enforced at tool-call time

**Done when:** you have a table and graph of ASR and FPR across firewall versions, including holdout results.

---

## Phase 6: Dashboard and Observability (Week 5)

- [ ] **P0** Dashboard panel: ASR per generation and per firewall version
- [ ] **P0** Dashboard panel: live attempt feed (blocked / harmless / breach)
- [ ] **P1** Dashboard panel: attack-family vs. defense-layer heatmap
- [ ] **P1** Dashboard panel: top breaches (payload, failing layer)
- [ ] **P1** Dashboard panel: FPR and latency (p50/p95)
- [ ] **P1** Add OpenTelemetry tracing and Langfuse/Phoenix for LLM traces
- [ ] **P2** Custom Next.js + WebSocket live dashboard (instead of Grafana only)

**Done when:** a live demo shows an attack run and the dashboard updating in real time.

---

## Phase 7: Evaluation and Analysis (Week 6)

- [ ] **P0** **Ablation study:** disable each layer in turn and measure the change in ASR/FPR
- [ ] **P0** Compare against baselines (no defense, keyword filter, Prompt Guard / Llama Guard)
- [ ] **P0** Evaluate on external benchmarks (AgentDojo, BIPIA) for generalization
- [ ] **P0** Compute confidence intervals and significance tests (SciPy) over repeated runs
- [ ] **P0** Measure **utility** (benign task success with vs. without the firewall)
- [ ] **P1** Report judge accuracy versus hand labels
- [ ] **P1** Analyze remaining weaknesses: which families still succeed and why
- [ ] **P1** Compare with existing tools (garak, PyRIT, promptfoo) on the same target
- [ ] **P2** One research add-on: activation probing, multimodal injections, or Z3 policy verification

---

## Phase 8: Documentation and Delivery (Final week)

- [ ] **P0** Final report: motivation, architecture, method, results, limitations, ethics, future work
- [ ] **P0** Generate all figures from code (reproducible notebooks)
- [ ] **P0** Polish `README.md` with quick start and one-command demo
- [ ] **P0** Provide a reproducibility guide (seeds, versions, dataset splits, hardware)
- [ ] **P1** Record a 3-5 minute demo video
- [ ] **P1** Prepare presentation slides
- [ ] **P1** Add a `SECURITY.md` / responsible-use note
- [ ] **P1** Clean the code, add tests, tag release `v1.0`

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
