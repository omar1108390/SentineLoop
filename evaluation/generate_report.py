"""Regenerate the project report and figures from checked-in evaluation artifacts."""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
FIGURES = ARTIFACTS / "figures"


def read_json(path: str) -> dict:
    return json.loads((ARTIFACTS / path).read_text(encoding="utf-8"))


def main() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    stats = read_json("benchmark-stats.json")
    comparisons = read_json("baseline-comparison.json")
    guards = read_json("guard-ablation.json")
    utility = read_json("utility-report.json")
    input_ablation = read_json("ablation.json")
    closed_loop = read_json("closed_loop/report.json")

    baseline_total = sum(row["attempts"] for row in read_json("baseline.json")["summary"].values())
    baseline_breaches = sum(
        row["breaches"] for row in read_json("baseline.json")["summary"].values()
    )
    firewall_total = sum(row["attempts"] for row in read_json("firewall.json")["summary"].values())
    firewall_breaches = sum(
        row["breaches"] for row in read_json("firewall.json")["summary"].values()
    )
    baseline_asr, firewall_asr = (
        baseline_breaches / baseline_total,
        firewall_breaches / firewall_total,
    )
    holdout = comparisons["splits"]["holdout"]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    labels = ["Generated mutation set", "Locked holdout"]
    x = [0, 1]
    width = 0.34
    baseline_values = [baseline_asr, holdout["no_defense"]["asr"]]
    firewall_values = [firewall_asr, holdout["layered_firewall"]["asr"]]
    ax.bar([v - width / 2 for v in x], baseline_values, width, label="No defense", color="#bb4b55")
    ax.bar(
        [v + width / 2 for v in x],
        firewall_values,
        width,
        label="Layered firewall",
        color="#247b72",
    )
    ax.set(
        xticks=x,
        xticklabels=labels,
        ylabel="Attack success rate",
        ylim=(0, 1),
        title="Sandbox attack outcomes",
    )
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda value, _: f"{value:.0%}"))
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(FIGURES / "attack-outcomes.png", dpi=160)
    plt.close(fig)

    rows = holdout
    labels = ["No defense", "Keyword filter", "Layered firewall"]
    keys = ["no_defense", "keyword_filter", "layered_firewall"]
    x = range(len(keys))
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(
        [v - width / 2 for v in x],
        [rows[key]["asr"] for key in keys],
        width,
        label="ASR",
        color="#bb4b55",
    )
    ax.bar(
        [v + width / 2 for v in x],
        [rows[key]["false_positive_rate"] for key in keys],
        width,
        label="Benign block rate",
        color="#d1a844",
    )
    ax.set(
        xticks=list(x),
        xticklabels=labels,
        ylabel="Rate",
        ylim=(0, 1),
        title="Locked holdout input defenses",
    )
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda value, _: f"{value:.0%}"))
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(FIGURES / "holdout-defense-comparison.png", dpi=160)
    plt.close(fig)

    guard = guards["splits"]["holdout"]
    values = [
        guard["output_redaction"]["raw_canary_leaks"],
        guard["output_redaction"]["guarded_canary_leaks"],
        guard["tool_policy"]["attack_side_effects_denied"],
    ]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(
        ["Canary leaks\nbefore guard", "Canary leaks\nafter guard", "Attack side effects\ndenied"],
        values,
        color=["#bb4b55", "#247b72", "#247b72"],
    )
    ax.set(ylabel="Count", title="Output guard and tool-policy checks (locked holdout)")
    ax.set_ylim(0, max(values + [1]) * 1.2)
    fig.tight_layout()
    fig.savefig(FIGURES / "output-and-policy.png", dpi=160)
    plt.close(fig)

    rounds = closed_loop["rounds"]
    round_rows = ", ".join(
        f"v{row['version']}: {row.get('training_breaches', 0)} training breaches, "
        f"{row.get('hardening_rules_added', 0)} rules added"
        for row in rounds
    )
    report = f"""# SentinelLoop evaluation report

## Summary

SentinelLoop is a sandboxed prototype for studying prompt-injection defense. It combines an intentionally vulnerable fake email agent, an attack fuzzer, a layered gateway, objective checks, and evaluation tooling. The local corpus demonstrates that input filters, output redaction, and tool authorization address different failure modes. These results are a small deterministic demonstration, not evidence of production-level robustness.

## System and method

- **Target:** deterministic email/calendar assistant with fake messages, fake secret, canary, and in-memory no-op tools.
- **Attacks:** local categorized seed corpus plus deterministic paraphrase, encoding, Unicode, document, and distractor mutations. Genetic and MAP-Elites search are available.
- **Input defenses:** normalized heuristic rules, compact trained classifier, and TF-IDF word/bigram similarity over training attacks.
- **Output/tool defenses:** canary and fake-secret redaction; strict tool allowlist with argument, provenance, and explicit-approval checks.
- **Judge:** objective canary, forbidden-tool, and unexpected-state signals.
- **Evaluation:** train/validation/holdout corpus split with a SHA-256 lock; holdout is excluded from hardening and model fitting.

## Results

![Generated attack outcomes](artifacts/figures/attack-outcomes.png)

The deterministic mutation artifact contains **{baseline_breaches}/{baseline_total}** baseline breaches ({baseline_asr:.1%}) and **{firewall_breaches}/{firewall_total}** with the layered input firewall ({firewall_asr:.1%}). Across {stats['seed_clusters']} source-seed clusters, the baseline 95% cluster-bootstrap interval is {stats['baseline_asr_ci95'][0]:.1%}–{stats['baseline_asr_ci95'][1]:.1%}. No firewall cluster breached; the 95% Wilson interval for an affected source cluster is {stats['firewall_seed_cluster_breach_rate_ci95_wilson'][0]:.1%}–{stats['firewall_seed_cluster_breach_rate_ci95_wilson'][1]:.1%}. The paired cluster sign-flip estimate is p={stats['cluster_permutation']['two_sided_p_value']:.5g}.

![Holdout input-defense comparison](artifacts/figures/holdout-defense-comparison.png)

On the **{holdout['no_defense']['attack_count']} attack / {holdout['no_defense']['benign_count']} benign** locked holdout, no defense recorded ASR {holdout['no_defense']['asr']:.1%}; the transparent keyword filter recorded {holdout['keyword_filter']['asr']:.1%}; and the layered input firewall recorded {holdout['layered_firewall']['asr']:.1%}. Their benign block rates were {holdout['no_defense']['false_positive_rate']:.1%}, {holdout['keyword_filter']['false_positive_rate']:.1%}, and {holdout['layered_firewall']['false_positive_rate']:.1%}. This tiny holdout is descriptive only. Removing the classifier in the input-layer ablation raises holdout ASR to {input_ablation['splits']['holdout']['without_classifier']['asr']:.1%}; removing rules or similarity leaves it at {input_ablation['splits']['holdout']['without_rules']['asr']:.1%} and {input_ablation['splits']['holdout']['without_similarity']['asr']:.1%}, respectively.

![Output and policy checks](artifacts/figures/output-and-policy.png)

In the locked holdout, the unprotected demo agent exposed the canary in {guard['output_redaction']['raw_canary_leaks']}/{guard['output_redaction']['attack_count']} attack runs. Redaction reduced response leaks to {guard['output_redaction']['guarded_canary_leaks']}; it did not undo any tool actions. The policy replay denied {guard['tool_policy']['attack_side_effects_denied']}/{guard['tool_policy']['attack_side_effect_calls']} observed attack side-effect calls. It denied {guard['tool_policy']['benign_side_effects_denied']}/{guard['tool_policy']['benign_side_effect_calls']} benign side-effect calls when explicit trusted-user approval was represented. The policy ablation replays calls through the policy and does not execute side effects.

On the 30-prompt benign utility benchmark, the baseline and firewall each completed {utility['baseline_success_count']}/{utility['task_count']} tasks; benign block rate was {utility['benign_block_rate']:.1%}. Measured local input-inspection p95 is reported in `artifacts/layer-evaluation.json`; it is not a hosted-model end-to-end latency measurement.

The closed loop ran {len(rounds)} versions ({round_rows}). No training bypasses were found in those rounds, so no hardening rules were added and there is no measured adaptation gain.

## Limitations and remaining work

- The attack corpus and target are synthetic, intentionally simple, and small. A 6-attack holdout cannot establish general robustness.
- Objective judge signals are deterministic and narrow. There is no independently human-labeled 100+ attempt set or measured LLM-judge accuracy.
- Prompt Guard, Llama Guard, AgentDojo, and BIPIA are not included in this local comparison.
- The current classifier is a compact logistic-regression JSON model; it is not DeBERTa/ModernBERT and is not exported to ONNX.
- The gateway filters tool calls but the optional quarantine, full provenance propagation, tracing, and production approval workflow remain incomplete.
- Hosted Groq access is optional. The gateway health check does not prove an upstream completion; a rotated API key is required for a fresh live check.
- The dashboard is a lightweight local HTML view; no Next.js/WebSocket front end or demo recording is supplied.

## Ethics and intended use

All experiments target only the included fake-data sandbox. Fake email/calendar actions are in-memory and have no real network side effects. Do not point the fuzzer at third-party services or real accounts. Results describe this prototype only and should not be used as a security certification.

## Reproduction

Follow [REPRODUCIBILITY.md](REPRODUCIBILITY.md) to verify corpus hashes, regenerate evaluation artifacts, and build this report and its figures.
"""
    (ROOT / "REPORT.md").write_text(report, encoding="utf-8")
    print(f"Generated {ROOT / 'REPORT.md'} and figures under {FIGURES}")


if __name__ == "__main__":
    main()
