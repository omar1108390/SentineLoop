# SentinelLoop: A Self-Hardening Prompt Injection Firewall with an Evolutionary Red-Team Fuzzer

> A closed-loop security system where an automated attacker (fuzzer) continuously tries to break an LLM firewall, and the results are used to harden the firewall, with every step measured.

---

## 1. Overview

**Prompt injection** is an attack in which untrusted text (a user message, a web page, an email, a PDF, a tool description) contains instructions that hijack a Large Language Model (LLM) and make it ignore its intended behavior. It is currently one of the most important unsolved security problems in LLM applications and AI agents.

**SentinelLoop** is a project that combines two components into one adaptive system:

1. **The Firewall (defender):** a gateway that sits between an application and any LLM, inspecting inputs, outputs, and tool calls using multiple defensive layers.
2. **The Fuzzer (attacker):** an automated red-team engine that generates, mutates, and evolves prompt injection attacks to find weaknesses in the firewall.

The two components run in a loop, similar in spirit to a GAN: the fuzzer finds bypasses, the bypasses are used to improve the firewall, and the improved firewall is attacked again. Every cycle is measured with real metrics (attack success rate, false positive rate, latency).

All experiments run against a **sandboxed, deliberately vulnerable demo application with fake data**. No real systems are targeted.

---

## 2. Problem Statement

- LLM applications mix **trusted instructions** (developer prompts) with **untrusted data** (user text, documents, web content) in the same context window. The model cannot reliably tell them apart.
- Static filters and keyword blocklists are easily bypassed through paraphrasing, translation, encoding, multi-turn setups, and hidden content.
- Most defenses are evaluated once, on a fixed dataset, so their real-world robustness is unknown.
- There is a trade-off between **security** (blocking attacks) and **usability** (not blocking legitimate requests) that is rarely measured.

**Core question:** *How robust can a layered defense become when it is continuously attacked by an adaptive, automated adversary, and what are its limits?*

---

## 3. Goals and Non-Goals

### Goals
- Build a modular, OpenAI-API-compatible **LLM firewall** with multiple defense layers.
- Build an **evolutionary fuzzer** that produces diverse, effective injection attacks.
- Build an objective **judge** that decides whether an attack really succeeded.
- Implement the **closed loop** (attack, analyze, harden, re-attack).
- Produce **quantitative results**: attack success rate (ASR), false positive rate (FPR), latency overhead, per-attack-family weaknesses.
- Provide a **live dashboard** and a **reproducible benchmark**.

### Non-Goals
- Attacking real products, real users, or third-party systems.
- Publishing novel bypasses aimed at production systems.
- Claiming a "perfect" defense. The expected and honest finding is that ASR never reaches zero.

---

## 4. Ethical Scope and Safety

- All attacks target **only the project's own sandboxed demo app**.
- The target app uses **fake secrets, fake emails, and fake tools** (no real network side effects).
- The attack corpus is kept for reproducibility and research, framed as a defensive benchmark.
- Findings are reported as weaknesses of the project's own defenses, with the aim of improving them.

---

## 5. System Architecture

```
        ┌──────────────┐   attacks    ┌──────────────────────┐   allowed   ┌────────────────┐
        │    FUZZER    │ ───────────► │  FIREWALL (gateway)  │ ──────────► │   Target LLM   │
        │  (attacker)  │              │  input / output /    │             │  agent (sandbox)│
        └──────▲───────┘              │  tool-call checks    │ ◄────────── └────────────────┘
               │                      └──────────┬───────────┘   response
     feedback: which                             │ verdicts + logs
     attacks got through                         ▼
               │                      ┌──────────────────────┐
               └───────────────────── │  JUDGE + DASHBOARD   │
                                      │  (did it really      │
                                      │   succeed?)          │
                                      └──────────┬───────────┘
                                                 │ new bypasses
                                                 ▼
                                      ┌──────────────────────┐
                                      │  HARDENING PIPELINE  │
                                      │  retrain / new rules │
                                      └──────────────────────┘
```

### 5.1 Target Application (sandbox)
A deliberately vulnerable demo agent, for example an **email assistant** with:
- A **system prompt** containing a fake secret and a **canary token**.
- Fake tools: `read_email`, `send_email`, `search_files`, `calendar_add`.
- A document/RAG input path to simulate **indirect injection** (instructions hidden in emails, web pages, or files).
- Runs in Docker with no real outbound access.

### 5.2 Firewall (Defender)
A gateway that exposes an OpenAI-compatible endpoint and applies layered checks.

| Layer | Purpose |
|---|---|
| **L0: Normalizer** | Decodes base64/rot13/URL-encoding, strips zero-width and homoglyph characters, extracts text from hidden HTML/metadata before inspection |
| **L1: Classifier** | Fine-tuned transformer (DeBERTa-v3 / ModernBERT, exported to ONNX) scoring injection likelihood |
| **L2: Semantic similarity** | Embedding search (FAISS/Qdrant) against a store of known attacks |
| **L3: Quarantine (dual-LLM)** | Untrusted content is read by a small model with **no tool access**; only structured output (validated JSON) is passed on |
| **L4: Policy engine** | Declarative rules (OPA/Rego) such as "data from untrusted origin cannot trigger `send_email` without approval" |
| **L5: Output guard** | Canary-token leak detection, sensitive-data detection (PII/secret patterns), tool-call validation |
| **L6: Provenance / taint tracking (stretch)** | Labels data as trusted/untrusted and enforces it at tool-call time |

Each layer returns a verdict (`allow`, `block`, `flag`) and a score. The final decision aggregates them, and every decision is logged.

### 5.3 Fuzzer (Attacker)
An automated attack generator.

- **Seed corpus:** known attack families such as instruction override, role-play/persona, prompt leaking, delimiter confusion, encoded payloads, indirect injection in documents, multi-turn escalation, and multilingual attacks.
- **Mutation operators:** paraphrase, translate, encode, split across turns, wrap in a document/HTML/JSON, change tone/persona, insert distractor text, obfuscate with unicode.
- **Search strategy:**
  - **Genetic algorithm** (selection, crossover, mutation).
  - **MAP-Elites (quality-diversity):** maintains a grid of attacks by family and technique, so the fuzzer discovers *many different* working attacks rather than one best attack.
  - **LLM-driven mutation:** an attacker LLM rewrites payloads using feedback on why the last attempt failed.
- **Stretch:** RL fine-tuning (GRPO/PPO) of a small attacker model with "bypassed the firewall and succeeded" as the reward.

### 5.4 Judge
Decides if an attack **actually succeeded**, prioritizing objective signals:
1. **Canary token leaked** in the output.
2. **Forbidden tool called** (for example `send_email` to an attacker address).
3. **Sandbox state changed** unexpectedly.
4. **LLM-as-judge** with a rubric for ambiguous cases, validated against a hand-labeled sample (judge accuracy is reported).

Outcomes per attempt: `blocked`, `allowed-harmless`, `breach`.

### 5.5 Hardening Pipeline
After each round:
- Cluster the successful bypasses.
- Add them (with benign counterexamples) to the classifier's training data and retrain.
- Add normalizer rules or policy rules for newly discovered tricks.
- Version the firewall (v0, v1, v2, ...), tracked in an experiment tracker.
- Evaluate on a **holdout attack set** the firewall never trained on, to detect overfitting.

### 5.6 Dashboard
- Attack success rate per generation and per firewall version.
- Heatmap of attack families vs. defense layers.
- Live feed of attempts (blocked / harmless / breach).
- Top breaches with payload and the layer that failed.
- False positive rate and latency overhead.

---

## 6. Expected Behavior Over Time

| Round | Event | Illustrative result |
|---|---|---|
| 0 | No firewall, baseline attack | High ASR (for example around 60%) |
| 1 | Firewall v1 (classifier and canaries) | ASR drops sharply, survivors use encoding, translation, multi-turn |
| 2 | Fuzzer evolves the survivors | ASR partially recovers |
| 3 | Hardening, firewall v2 | ASR drops again, new weak spots emerge |
| N | Repeat | Curve flattens at a low but non-zero level |

*(Numbers are illustrative; real results come from the experiments.)*

---

## 7. Evaluation Methodology

### Metrics
- **ASR (Attack Success Rate):** fraction of attacks that reach `breach`, with confidence intervals.
- **Detection rate / recall** per attack family.
- **FPR (False Positive Rate):** fraction of benign requests wrongly blocked.
- **Utility preservation:** task success of the agent on benign tasks with and without the firewall.
- **Latency overhead** (p50 / p95) added by each layer.
- **Attack diversity:** coverage of the MAP-Elites grid.
- **Judge accuracy** versus human labels.

### Experimental design
- **Train / validation / holdout split** of attacks; the holdout is never used for hardening.
- **Benign dataset** of realistic requests for FPR and utility.
- **Ablation study:** remove each firewall layer and measure the impact.
- **Baselines:** no defense, keyword filter, off-the-shelf guard models (Prompt Guard, Llama Guard), and tools such as garak, PyRIT, promptfoo.
- **Statistics:** confidence intervals and significance tests (SciPy) over repeated runs.

### Datasets and benchmarks
AgentDojo, BIPIA, Tensor Trust, HackAPrompt, deepset/prompt-injections, plus a custom attack corpus and a custom benign set.

---

## 8. Technology Stack

| Area | Technologies |
|---|---|
| Language / API | Python, FastAPI (async), Pydantic |
| Classifier | DeBERTa-v3 / ModernBERT, Hugging Face Transformers, ONNX Runtime |
| Similarity search | sentence-transformers, FAISS or Qdrant |
| Policy engine | Open Policy Agent (Rego) or Cedar |
| Constrained output | Outlines / Pydantic structured decoding |
| Output/PII checks | Presidio, regex, canary tokens |
| Target agent | LangGraph and/or MCP Python SDK |
| Model serving | vLLM or Ollama (Llama / Qwen / Mistral), optional API models |
| Fuzzing / search | DEAP or pymoo, pyribs (MAP-Elites), TRL (optional RL) |
| Orchestration | Celery + Redis (or Ray) |
| Storage | PostgreSQL, Redis |
| Experiment tracking | MLflow or Weights & Biases, DVC for datasets |
| Observability | OpenTelemetry, Langfuse / Phoenix, Prometheus + Grafana |
| Dashboard | Grafana, or Next.js + WebSockets |
| Infrastructure / CI | Docker Compose, GitHub Actions (red-team regression tests) |

### Optional research add-ons (pick at most one)
- Activation probing with TransformerLens/nnsight to detect "instruction came from untrusted data."
- Multimodal injections (hidden text in images) with a vision-language model.
- Formal verification of tool-call policies with Z3.

---

## 9. Repository Structure

```
sentinelloop/
├── README.md
├── docker-compose.yml
├── firewall/
│   ├── gateway/            # FastAPI OpenAI-compatible proxy
│   ├── layers/             # normalizer, classifier, similarity, quarantine, output guard
│   ├── policies/           # OPA/Rego rules
│   └── models/             # exported ONNX models
├── target_app/
│   ├── agent/              # vulnerable demo agent
│   ├── tools/              # fake email/calendar/file tools
│   └── sandbox/            # isolation config
├── fuzzer/
│   ├── seeds/              # seed attack corpus
│   ├── mutators/           # mutation operators
│   ├── search/             # GA, MAP-Elites, LLM-guided search
│   └── runner/             # parallel execution (Celery/Ray)
├── judge/
│   ├── objective/          # canary/tool-call/state checks
│   └── llm_judge/          # rubric-based judge
├── hardening/
│   ├── dataset_builder/    # turn bypasses into training data
│   └── training/           # classifier retraining scripts
├── evaluation/
│   ├── benchmarks/         # AgentDojo, BIPIA, etc. adapters
│   ├── holdout/            # untouched holdout attacks
│   ├── benign/             # benign request set
│   └── reports/            # notebooks and generated figures
├── dashboard/
├── tests/
└── docs/
```

---

## 10. Deliverables

1. Working firewall gateway (versioned: v0, v1, v2, ...).
2. Working fuzzer with at least 3 mutation strategies and MAP-Elites search.
3. Sandboxed vulnerable target app.
4. Judge with measured accuracy.
5. Closed-loop automation script (one command runs a full round).
6. Live dashboard.
7. Reproducible benchmark (attack corpus, benign set, holdout set, scripts).
8. Final report with graphs, ablation study, limitations, and conclusions.
9. Demo video or live demonstration.

---

## 11. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Overfitting the firewall to the fuzzer's attacks | Strict holdout set, external datasets, cross-family evaluation |
| High false positives | Benign dataset, threshold tuning, report precision/recall trade-offs |
| Noisy or wrong judge | Prefer objective signals, validate LLM judge on labeled sample |
| Compute limits (no GPU) | Small models, quantization, API fallback, smaller attack budgets |
| Scope creep | Core scope first, stretch goals only after the loop works end to end |
| Non-deterministic LLM behavior | Fixed seeds/temperature where possible, repeated runs, confidence intervals |

---

## 12. Expected Contributions and Findings

- A reusable, measurable **red-team / defense loop** for LLM applications.
- Evidence of how **quality-diversity search** finds attack families that fixed datasets miss.
- A quantified **security vs. usability trade-off** for layered defenses.
- Per-layer **ablation results** showing which defenses actually matter.
- An honest assessment of the **limits of detection-based defenses**, and the argument for architectural defenses (taint tracking, policy enforcement).

---

## 13. Future Work

- Taint-tracking / capability-based enforcement as a primary defense.
- Multimodal and audio injections.
- RL-trained attacker models.
- Agent-to-agent and MCP tool-poisoning scenarios.
- Continuous red-teaming in CI for any LLM app.

---

## 14. References and Further Reading

- OWASP Top 10 for LLM Applications (Prompt Injection).
- *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection* (Greshake et al.).
- AgentDojo, BIPIA, Tensor Trust, and HackAPrompt benchmarks and papers.
- CaMeL: *Defeating Prompt Injections by Design* (capability-based agent security).
- MAP-Elites / quality-diversity literature and the pyribs library.
- Tools: garak, PyRIT, promptfoo, Meta Prompt Guard and Llama Guard.
