# SentinelLoop

SentinelLoop is a sandbox-only project for measuring and improving defenses against prompt injection. Its demo target uses fake data and fake tools; sending email is always a logged no-op.

## Quick start

Requires Python 3.11 or newer. The demo and baseline fuzzer use only the Python standard library.

```console
python -m target_app --demo
python -m fuzzer.runner --mutate
```

The agent is intentionally vulnerable so local attack outcomes are measurable. The fuzzer targets only the included fake assistant. Results are written to `artifacts/baseline.json` and `.csv`, with attack success rate reported per family.

## Project layout

- `target_app/`: deterministic fake email assistant and isolated fake tools.
- `target_app/judge.py`: objective canary, tool-call, and state-change checks.
- `fuzzer/seeds/`: categorized local seed corpus.
- `fuzzer/mutators.py`: paraphrase, wrapping, distractor, Unicode, base64, and ROT13 variants.
- `fuzzer/runner.py`: reproducible baseline runner and per-family ASR report.
- `firewall/`, `evaluation/`: upcoming components.

See `PROJECT_DESCRIPTION.md` for architecture and `PROJECT_TASKS.md` for the roadmap.
