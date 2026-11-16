# SentinelLoop

SentinelLoop is a sandbox-only project for measuring and improving defenses against prompt injection. Its demo target uses fake data and fake tools; sending email is always a logged no-op.

## Quick start

Requires Python 3.11 or newer. The demo and experiments use only the Python standard library.

```console
python -m target_app --demo
python -m fuzzer.runner --mutate
python -m fuzzer.runner --mutate --firewall
```

The agent is intentionally vulnerable so local attack outcomes are measurable. The fuzzer targets only the included fake assistant. Runs write per-attempt JSON/CSV and per-family ASR under `artifacts/`. The firewall currently combines Unicode/URL/base64/ROT13 normalization, transparent heuristic rules, inspection of retrieved untrusted text, and canary output redaction. It is a research prototype, not a trained classifier or production gateway.

The checked-in sample run has 35 non-benign attacks and three benign prompts: baseline ASR is 25/35 (71.4%); the prototype firewall ASR is 0/35, with 0/3 benign prompts blocked. This tiny, self-generated corpus only verifies the software loop and does not establish general security.

## Project layout

- `target_app/`: deterministic fake email assistant and isolated fake tools.
- `target_app/judge.py`: objective canary, tool-call, and state-change checks.
- `fuzzer/`: categorized corpus, deterministic mutations, baseline/firewall runner.
- `firewall/`: normalizer, heuristic input rules, untrusted-content check, output canary guard.
- `artifacts/`: reproducible sample JSON/CSV results.

See `PROJECT_DESCRIPTION.md` and `PROJECT_TASKS.md` for the architecture and roadmap.

