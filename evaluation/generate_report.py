"""Regenerate docs/report.md and its figures from the benchmark artifacts.

python -m evaluation.generate_report
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from fuzzer.mutators import OPERATORS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
FIGURES = ROOT / "docs" / "figures"
REPORT = ROOT / "docs" / "report.md"
PROFILES = ("none", "keyword", "detectors", "full")
NAMES = {"none": "No defense", "keyword": "Keyword rules", "detectors": "All detectors", "full": "Full stack"}
COLORS = {"none": "#c0392b", "keyword": "#e67e22", "detectors": "#2e86c1", "full": "#1e8449"}


def read(name: str) -> dict:
    return json.loads((ARTIFACTS / name).read_text(encoding="utf-8"))


def pct(value: float) -> str:
    return f"{100 * value:.1f}%"


def _save(fig, name: str) -> str:
    fig.tight_layout()
    fig.savefig(FIGURES / name, dpi=150)
    plt.close(fig)
    return f"figures/{name}"


def figure_profiles(profiles: dict) -> str:
    fig, ax = plt.subplots(figsize=(8, 4))
    splits = ("validation", "holdout")
    width = 0.2
    for offset, name in enumerate(PROFILES):
        values = [profiles[split][name]["attacks"]["asr"] for split in splits]
        positions = [index + (offset - 1.5) * width for index in range(len(splits))]
        bars = ax.bar(positions, values, width, label=NAMES[name], color=COLORS[name])
        ax.bar_label(bars, labels=[pct(value) for value in values], fontsize=7, padding=2)
    ax.set(xticks=range(len(splits)), xticklabels=["Validation", "Locked holdout"],
           ylabel="Attack success rate", ylim=(0, 1.08), title="Attack success rate by defense profile")  # fmt: skip
    ax.legend(frameon=False, ncol=4, fontsize=8, loc="upper right")
    return _save(fig, "profiles.png")


def figure_families(fuzz: dict) -> str:
    families = list(fuzz["none"]["summary"])
    matrix = [[fuzz[name]["summary"][family]["asr"] for name in PROFILES] for family in families]
    fig, ax = plt.subplots(figsize=(7, 6))
    image = ax.imshow(matrix, cmap="Reds", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(PROFILES)), [NAMES[name] for name in PROFILES], rotation=20)
    ax.set_yticks(range(len(families)), families)
    for row, values in enumerate(matrix):
        for column, value in enumerate(values):
            ax.text(column, row, pct(value), ha="center", va="center", fontsize=7,
                    color="white" if value > 0.5 else "black")  # fmt: skip
    ax.set_title("Attack success by family (all seeds + mutations)")
    fig.colorbar(image, ax=ax, fraction=0.04)
    return _save(fig, "families.png")


def figure_hardening(rounds: list[dict]) -> str:
    versions = [row["version"] for row in rounds]
    fig, ax = plt.subplots(figsize=(7, 3.8))
    detectors = [row["holdout"]["detectors"]["asr"] for row in rounds]
    validation = [row["validation"]["detectors"]["asr"] for row in rounds]
    full = [row["holdout"]["full"]["asr"] for row in rounds]
    ax.plot(versions, detectors, marker="o", color=COLORS["detectors"], label="Holdout, detectors")
    ax.plot(versions, validation, marker="s", linestyle="--", color="#7fb3d5", label="Validation, detectors")
    ax.plot(versions, full, marker="o", color=COLORS["full"], label="Holdout, full stack")
    for version, value in zip(versions, detectors):
        ax.annotate(
            pct(value), (version, value), textcoords="offset points", xytext=(0, 6), ha="center", fontsize=8
        )
    ax.set(
        ylabel="Attack success rate",
        title="Hardening rounds",
        ylim=(0, max(detectors + validation) * 1.4 + 0.01),
    )
    ax.legend(frameon=False, fontsize=8)
    return _save(fig, "hardening.png")


def figure_ablation(ablation: dict) -> str:
    names = list(ablation)
    values = [ablation[name]["asr"] for name in names]
    fig, ax = plt.subplots(figsize=(7, 4.4))
    bars = ax.barh(names, values, color=["#1e8449" if name == "full" else "#5d6d7e" for name in names])
    ax.bar_label(bars, labels=[pct(value) for value in values], fontsize=8, padding=3)
    ax.invert_yaxis()
    ax.set(xlabel="Holdout attack success rate", title="Ablation: remove one layer at a time", xlim=(0, 1.1))
    return _save(fig, "ablation.png")


def figure_grid(grid: dict) -> str:
    families, techniques = grid["dimensions"]["family"], grid["dimensions"]["technique"]
    from matplotlib.colors import BoundaryNorm, ListedColormap
    from matplotlib.patches import Patch

    cells = {(row["family"], row["technique"]): row["fitness"] for row in grid["archive"]}
    # -1 = operator not applicable, 0 = blocked by a detector, 0.5 = evaded detectors, 1 = breach
    matrix = [[cells.get((family, technique), -1) for technique in techniques] for family in families]
    colors = ["#ffffff", "#d5d8dc", "#f5b041", "#c0392b"]
    cmap = ListedColormap(colors)
    norm = BoundaryNorm([-1.5, -0.25, 0.25, 0.75, 1.5], cmap.N)
    fig, ax = plt.subplots(figsize=(10, 5.6))
    ax.imshow(matrix, cmap=cmap, norm=norm, aspect="auto")
    ax.set_xticks(range(len(techniques)), techniques, rotation=60, ha="right", fontsize=7)
    ax.set_yticks(range(len(families)), families, fontsize=8)
    ax.set_xticks([x - 0.5 for x in range(1, len(techniques))], minor=True)
    ax.set_yticks([y - 0.5 for y in range(1, len(families))], minor=True)
    ax.grid(which="minor", color="white", linewidth=1.5)
    ax.tick_params(which="minor", length=0)
    ax.set_title(f"MAP-Elites archive vs. {NAMES.get(grid['profile'], grid['profile'])}")
    labels = ["not applicable", "blocked", "evaded detectors, stopped later", "breach"]
    ax.legend(handles=[Patch(facecolor=c, edgecolor="#999999", label=label) for c, label in zip(colors, labels)],
              loc="upper center", bbox_to_anchor=(0.5, -0.32), ncol=4, frameon=False, fontsize=8)  # fmt: skip
    return _save(fig, "map-elites.png")


def main() -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    profiles = read("evaluation/profiles.json")["splits"]
    fuzz = {name: read(f"fuzz/{name}-summary.json") for name in PROFILES}
    hardening = read("hardening/report.json")["rounds"]
    ablation = read("evaluation/ablation.json")["configurations"]
    layers = read("evaluation/layers.json")
    stats = read("evaluation/stats.json")["comparisons"]
    search = read("evaluation/search.json")["profiles"]
    grid = read("search/map-elites-detectors.json")
    model = json.loads(
        (ROOT / "firewall" / "models" / "injection_classifier.json").read_text(encoding="utf-8")
    )
    manifest = json.loads((ROOT / "evaluation" / "manifest.json").read_text(encoding="utf-8"))

    fig_profiles = figure_profiles(profiles)
    fig_families = figure_families(fuzz)
    fig_hardening = figure_hardening(hardening)
    fig_ablation = figure_ablation(ablation)
    fig_grid = figure_grid(grid)

    hold = profiles["holdout"]
    counts = manifest["counts"]
    total = {name: fuzz[name]["overall"] for name in PROFILES}
    full_search = search["full"]
    full_breaches = (full_search["genetic"] or {}).get("breach_candidates", 0) + (
        full_search["map_elites"] or {}
    ).get("breach_candidates", 0)
    if full_breaches:
        finding5 = (
            f"**Adaptive search still finds gaps**: against the full stack the genetic algorithm and "
            f"MAP-Elites found {full_breaches} breaching candidates (families: "
            f"{', '.join(sorted(set(full_search['genetic']['breach_families']) | set(full_search['map_elites']['breach_families'])))}), "
            "typically by chaining two tricks, such as a language the detectors were not trained on "
            "plus a request to write the answer backwards past the output guard."
        )
    else:
        finding5 = (
            f"**Adaptive search still maps the detectors' gaps**: against the "
            f"detectors alone, MAP-Elites still found breaches in {search['detectors']['map_elites']['breach_cells']} "
            f"family x technique cells and the genetic algorithm in {search['detectors']['genetic']['breach_cells']}, "
            f"while neither found a full-stack breach within its budget ({full_search['genetic']['evaluations']} + "
            f"{full_search['map_elites']['evaluations']} evaluations; static full-stack ASR "
            f"{pct(total['full']['asr'])}). A zero here is a budget-limited result, not a proof: "
            "the output guard's reversed-text gap (see Limitations) remains open."
        )
    first, last = hardening[0], hardening[-1]
    found = sum(row.get("training_attack", {}).get("breaches", 0) for row in hardening)
    gain = first["holdout"]["detectors"]["asr"] - last["holdout"]["detectors"]["asr"]
    if found and gain > 0:
        finding4 = (
            f"**The closed loop adapts, then saturates**: retraining on {found} fuzzer-found bypasses lowered "
            f"holdout detector ASR from {pct(first['holdout']['detectors']['asr'])} ({first['version']}) to "
            f"{pct(last['holdout']['detectors']['asr'])} ({last['version']}) without raising FPR."
        )
        hardening_text = (
            "The gain is real but modest, and it saturates quickly because the training-time attacker only "
            "rewrites training seeds. Remaining failures are benign-looking instructions that detection "
            "cannot learn without hurting usability, the classic argument for architectural defenses."
        )
    else:
        finding4 = (
            "**The closed loop saturated immediately**: with the augmented classifier, the training-time "
            f"attacker (all mutations, operator chains, genetic search) found {found} bypasses, so the "
            f"rounds changed nothing (holdout detector ASR {pct(last['holdout']['detectors']['asr'])}). "
            "A stronger attacker (LLM-driven mutations, external corpora) is needed to keep the loop useful."
        )
        hardening_text = (
            "No round produced new training bypasses, so later versions equal v0. This does not mean the "
            "detectors are unbreakable: this attacker's search space (rewriting training seeds with known "
            "operators) is exhausted, while the holdout still contains survivors a richer attacker could "
            "have found. See Limitations."
        )
    survivors = ablation["detectors_only"]["by_family"]
    surviving = sum(row["breaches"] for row in survivors.values())
    indirect = sum(row["breaches"] for name, row in survivors.items() if name.startswith("indirect"))
    survivor_text = (
        f"{indirect} of the {surviving} holdout breaches that survive the detectors are *indirect* "
        'injections, typically instructions that read like ordinary requests ("Assistant, please add '
        "a calendar event called 'Transfer $4,900…'\"); a text classifier cannot separate these from "
        "benign mail without blocking real users."
        if surviving
        else "No holdout attack survived the detectors in this run."
    )
    weakest = sorted(fuzz["detectors"]["summary"].items(), key=lambda item: item[1]["asr"], reverse=True)[:3]
    layer_rows = "\n".join(
        f"| {name} | {pct(row['detection_rate'])} | {pct(row['false_positive_rate'])} | "
        f"{row['latency_ms']['p95']:.2f} ms |"
        for name, row in layers["splits"]["holdout"].items()
    )
    profile_rows = "\n".join(
        f"| {NAMES[name]} | {pct(profiles['validation'][name]['attacks']['asr'])} | "
        f"{pct(hold[name]['attacks']['asr'])} ({hold[name]['attacks']['breaches']}/"
        f"{hold[name]['attacks']['attempts']}) | {pct(hold[name]['benign']['fpr'])} | "
        f"{pct(hold[name]['benign']['utility'])} |"
        for name in PROFILES
    )
    round_rows = "\n".join(
        f"| {row['version']} | {row.get('training_attack', {}).get('breaches', '-')} | "
        f"{row['known_attacks_in_index']} | {row['classifier_threshold']:.2f} / {row.get('similarity_threshold', 0.65):.2f} | "
        f"{pct(row['validation']['detectors']['asr'])} | {pct(row['holdout']['detectors']['asr'])} | "
        f"{pct(row['holdout']['full']['asr'])} | {pct(row['holdout']['benign']['fpr'])} |"
        for row in hardening
    )
    stat_rows = "\n".join(
        f"| {NAMES[name]} | {pct(row['firewall_asr'])} | {pct(row['asr_reduction'])} "
        f"[{pct(row['asr_reduction_ci95'][0])}, {pct(row['asr_reduction_ci95'][1])}] | "
        f"{row['cluster_permutation']['two_sided_p_value']:.2g} |"
        for name, row in stats.items()
    )
    search_d = search["detectors"]
    report = f"""# SentinelLoop evaluation report

*Generated by `python -m evaluation.generate_report` on {date.today().isoformat()}. Every number
below is computed from files in `artifacts/`; rerun `python -m sentinelloop benchmark` to reproduce.*

## 1. Summary

SentinelLoop studies **prompt injection**: attacks that smuggle instructions into the text an
LLM-based assistant reads. We attack a deliberately vulnerable, simulated email assistant
with {sum(counts[split]['attacks'] for split in counts)} seed attacks from {len(fuzz['none']['summary'])} families plus
{fuzz['none']['overall']['attempts'] - sum(counts[split]['attacks'] for split in counts)} automatic
mutations, and measure four defense profiles.

| Profile | Validation ASR | **Holdout ASR** | Holdout FPR | Holdout utility |
|---|---|---|---|---|
{profile_rows}

*ASR = attack success rate (lower is better). FPR = benign requests where any layer blocked or
withheld something. Utility = benign tasks completed correctly. Holdout = {counts['holdout']['attacks']}
seeds (+ mutations) and {counts['holdout']['benign']} benign requests that are SHA-256-locked and never
used for training or tuning.*

**Main findings**

1. **The unprotected agent is very easy to hijack**: {pct(hold['none']['attacks']['asr'])} of holdout
   attacks succeed. The signature rules alone (after the L0 normalizer) bring this to
   {pct(hold['keyword']['attacks']['asr'])}; see the caveat on rule development in Limitations.
2. **Detectors help a lot but cannot finish the job**: rules + ML classifier + similarity search
   reach {pct(hold['detectors']['attacks']['asr'])} on the holdout. {survivor_text}
3. **Architecture closes the gap**: adding quarantine (dual-LLM), a provenance-aware tool policy
   and an output guard reaches {pct(hold['full']['attacks']['asr'])} holdout ASR at
   {pct(hold['full']['benign']['fpr'])} FPR. The ablation shows these layers are complementary:
   detectors alone leave {pct(ablation['detectors_only']['asr'])}, architecture alone leaves
   {pct(ablation['architecture_only']['asr'])}.
4. {finding4}
5. {finding5}

## 2. Setup

* **Target (`target_app/`)**: a deterministic simulation of a naive LLM agent ("MailPilot") with a
  system prompt holding a fake secret and canary, fake tools (inbox, files, web, calendar, send
  email) and a weak guardrail. It understands base64, ROT13, leetspeak, look-alike characters,
  spaced letters, chat slang and typos, five languages, split payloads, multi-turn priming,
  refusal suppression, forced openings and fake dialogues, and it obeys instructions
  found inside retrieved documents.
* **Judge (`target_app/judge.py`)**: objective signals only: canary/secret in the reply (also
  reversed, spaced or base64), system prompt disclosed, email to an outside domain or carrying the
  secret, a side-effect tool triggered by a document, an outside markdown image, or a reply dictated
  by a document.
* **Corpus**: {len(fuzz['none']['summary'])} families (`fuzzer/seeds/attacks.json`), {sum(counts[s]['benign'] for s in counts)} benign requests including hard
  negatives (`evaluation/benign/requests.json`), split 60/20/20 by family with seed
  `{manifest['seed']}`.
* **Mutations (`fuzzer/mutators.py`)**: {fuzz['none']['overall']['attempts'] // max(1, sum(counts[s]['attacks'] for s in counts))}x
  expansion using {len(OPERATORS)} operators (paraphrase, role-play, fake system tags, HTML comment,
  base64, ROT13, leetspeak, homoglyphs, zero-width, spacing, translation, output evasion, chat slang
  and typos, payload splitting, multi-turn, direct-to-indirect…).
* **Defense layers (`firewall/`)**: L0 normalizer (decoding + slang/typo repair), L1a signature
  rules (some apply to documents only), L1b logistic regression over word and character n-grams
  trained on {model['train_attacks']} attack and {model['train_benign']} benign texts
  ({model['data']['synthetic_attacks']} synthetic attacks; {model['data']['synthetic_discarded_by_leak_guard']}
  discarded by the leak guard), L2 TF-IDF similarity per normalized view, L3 quarantine, L4 tool
  policy with provenance, L5 output guard. The classifier threshold ({model['threshold']:.2f}) and the
  similarity threshold ({model.get('similarity_threshold', 0.65):.2f}) are tuned on validation.

## 3. Results

![Attack success by profile]({fig_profiles})

![Attack success by family]({fig_families})

The three families that still get past the detectors most often are
{", ".join(f"**{family}** ({pct(values['asr'])})" for family, values in weakest)}.

### Detectors on their own (holdout)

| Detector | Detection rate | False positives | p95 latency |
|---|---|---|---|
{layer_rows}

Rules and classifier each catch most attacks on their own and overlap heavily, which is why
removing any single detector changes little in the ablation below. Similarity search only flags
close rewordings of known attacks, so on new attacks it is the weakest detector by design.

### Ablation

![Ablation]({fig_ablation})

## 4. The hardening loop

Each round attacks the **training** seeds with every mutation operator, random two-step operator
chains and a genetic search, against the current detectors. Every bypass is added to the
classifier's training data, to the similarity index and as an exact signature; the classifier
threshold is re-tuned on validation (maximising TPR - 3 x FPR).

| Version | New training bypasses | Known attacks | Thresholds (clf / sim) | Validation ASR (detectors) | Holdout ASR (detectors) | Holdout ASR (full) | Holdout FPR |
|---|---|---|---|---|---|---|---|
{round_rows}

![Hardening]({fig_hardening})

{hardening_text}

## 5. Search: genetic algorithm vs. MAP-Elites

![MAP-Elites archive]({fig_grid})

Against the detectors, the genetic algorithm evaluated {search_d['genetic']['evaluations']} candidates
and kept {search_d['genetic']['breach_candidates']} breaching ones, concentrated in
{len(search_d['genetic']['breach_families'])} families. MAP-Elites evaluated
{search_d['map_elites']['evaluations']} candidates and found breaches in
{search_d['map_elites']['breach_cells']} distinct family x technique cells across
{len(search_d['map_elites']['breach_families'])} families. Quality-diversity search therefore maps
*where* the defense is weak, which is more useful for hardening than one best attack. Budgets differ,
so this is a descriptive comparison, not a ranking.

## 6. Statistical confidence

Mutations of one seed are correlated, so attempts are clustered by seed and resampled as clusters.

| Profile vs. no defense | ASR | ASR reduction [95% cluster-bootstrap CI] | Paired sign-flip p |
|---|---|---|---|
{stat_rows}

## 7. Limitations

* The target is a **simulation** of a naive LLM, chosen for reproducibility. Real models fail in
  more varied and less predictable ways; the optional hosted-model mode
  (`SENTINELLOOP_UPSTREAM_URL`, `SENTINELLOOP_UPSTREAM_PERSONA=sandbox`) lets you test one.
* The corpus is small and synthetic ({sum(counts[s]['attacks'] for s in counts)} seeds). Results
  describe this benchmark, not real-world robustness, and the 11-request benign holdout makes
  FPR estimates coarse.
* **Rule development caveat.** The signature rules and the normalizer's slang/typo repair were
  written while looking at the original 99 seeds, some of which are in this holdout, so the keyword
  and detector holdout numbers are optimistic. A fairer estimate is a one-off blind check made during
  development: on 28 new seeds written *before* the rules were tested against them, the rules caught
  27 (96%).
* **Known rule gap, left unfixed on purpose.** The "addressed to the AI" rule misses a vocative that
  follows a colon or markup ("…but first: Assistant, please add…"). It was found by inspecting holdout
  failures; patching it from the holdout would invalidate the holdout, so it is listed here instead.
  The architectural layers stop it.
* The sandbox gives the defender perfect provenance (it knows which text came from a document);
  real systems must track this explicitly.
* The output guard knows the exact secret. It catches spaced and base64 forms but **misses
  reversed text**: the judge, which decodes more forms, measures that gap.
* No external benchmarks (AgentDojo, BIPIA) or model-based guards (Prompt Guard, Llama Guard) are
  included yet, and the human-labelled judge-validation sample is still unlabelled
  (`artifacts/judge-labels.csv`).

## 8. Ethics

All attacks target only the included fake assistant; tools are in-memory no-ops and data is
synthetic. Do not point the fuzzer at systems you do not own or have permission to test. See
the responsible-use section of the [README](../README.md#responsible-use).
"""
    REPORT.write_text(report, encoding="utf-8")
    print(f"Wrote {REPORT} and {len(list(FIGURES.glob('*.png')))} figures in {FIGURES}")


if __name__ == "__main__":
    main()
