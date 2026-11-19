"""Statistics for the fuzzer runs: confidence intervals and a paired significance test.

Mutations of the same seed are not independent, so attempts are *clustered by
source seed* and resampled as whole clusters (cluster bootstrap). The paired
sign-flip test asks whether the per-seed ASR reduction could be chance.

    python -m evaluation.benchmark_stats
"""

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path
from typing import Any


def load_attempts(path: Path) -> dict[tuple[str, str, str], dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {(str(row["index"]), row["id"], row["technique"]): row for row in data.get("attempts", [])}


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def interval(values: list[float]) -> list[float]:
    return [percentile(values, 0.025), percentile(values, 0.975)]


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> list[float]:
    if total == 0:
        return [0.0, 0.0]
    rate = successes / total
    scale = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / scale
    margin = z * ((rate * (1 - rate) / total + z * z / (4 * total * total)) ** 0.5) / scale
    return [max(0.0, center - margin), min(1.0, center + margin)]


def analyze(
    baseline: dict,
    firewall: dict,
    bootstrap_samples: int = 10000,
    permutation_samples: int = 20000,
    seed: int = 42,
) -> dict[str, Any]:
    shared = sorted(baseline.keys() & firewall.keys())
    if not shared:
        raise ValueError("No paired attack attempts were found")
    clusters: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for key in shared:
        base_breach = int(baseline[key]["outcome"] == "breach")
        firewall_breach = int(firewall[key]["outcome"] == "breach")
        clusters[baseline[key]["id"]].append((base_breach, firewall_breach))

    def rates(rows: list[tuple[int, int]]) -> tuple[float, float, float]:
        count = max(1, len(rows))
        base_rate = sum(pair[0] for pair in rows) / count
        firewall_rate = sum(pair[1] for pair in rows) / count
        return base_rate, firewall_rate, base_rate - firewall_rate

    paired = [row for cluster_rows in clusters.values() for row in cluster_rows]
    base, protected, delta = rates(paired)
    cluster_values = list(clusters.values())
    rng = random.Random(seed)
    base_boot, firewall_boot, delta_boot = [], [], []
    for _ in range(bootstrap_samples):
        sample = [rng.choice(cluster_values) for _ in cluster_values]
        sampled_rows = [row for cluster_rows in sample for row in cluster_rows]
        sample_rates = rates(sampled_rows)
        base_boot.append(sample_rates[0])
        firewall_boot.append(sample_rates[1])
        delta_boot.append(sample_rates[2])

    clusters_with_firewall_breach = sum(
        any(firewall_hit for _, firewall_hit in rows) for rows in cluster_values
    )
    firewall_cluster_rate = clusters_with_firewall_breach / len(cluster_values)
    cluster_deltas = [rates(rows)[2] for rows in cluster_values]
    observed = sum(cluster_deltas) / len(cluster_deltas)
    extreme = 0
    for _ in range(permutation_samples):
        permuted = sum(value if rng.getrandbits(1) else -value for value in cluster_deltas) / len(
            cluster_deltas
        )
        extreme += abs(permuted) >= abs(observed)
    p_value = (extreme + 1) / (permutation_samples + 1)
    return {
        "pairing": "attempt index + seed id + technique",
        "cluster": "source seed prompt (all deterministic mutations stay together)",
        "paired_attempts": len(shared),
        "seed_clusters": len(clusters),
        "baseline_asr": base,
        "baseline_asr_ci95": interval(base_boot),
        "firewall_asr": protected,
        "firewall_asr_ci95": interval(firewall_boot) if protected > 0 else None,
        "firewall_seed_clusters_with_breach": clusters_with_firewall_breach,
        "firewall_seed_cluster_breach_rate": firewall_cluster_rate,
        "firewall_seed_cluster_breach_rate_ci95_wilson": wilson_interval(
            clusters_with_firewall_breach, len(cluster_values)
        ),
        "asr_reduction": delta,
        "asr_reduction_ci95": interval(delta_boot),
        "cluster_permutation": {
            "estimand": "mean per-seed ASR reduction",
            "two_sided_p_value": p_value,
            "permutations": permutation_samples,
            "seed": seed,
        },
        "limitations": "Synthetic mutations are clustered by seed parent; uncertainty applies only to this corpus and does not establish generalization.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fuzz-dir", type=Path, default=Path("artifacts/fuzz"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/evaluation/stats.json"))
    parser.add_argument("--bootstrap-samples", type=int, default=5000)
    parser.add_argument("--permutation-samples", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.bootstrap_samples < 100 or args.permutation_samples < 100:
        raise SystemExit("Use at least 100 resamples for each statistical estimate")
    baseline = load_attempts(args.fuzz_dir / "none.json")
    result = {"baseline_profile": "none", "comparisons": {}}
    for profile in ("keyword", "detectors", "full"):
        path = args.fuzz_dir / f"{profile}.json"
        if not path.is_file():
            continue
        stats = analyze(
            baseline, load_attempts(path), args.bootstrap_samples, args.permutation_samples, args.seed
        )
        result["comparisons"][profile] = stats
        low, high = stats["baseline_asr_ci95"]
        print(
            f"none vs {profile:<9}: {stats['baseline_asr']:.1%} [{low:.1%}-{high:.1%}] -> "
            f"{stats['firewall_asr']:.1%}; reduction {stats['asr_reduction']:.1%}; "
            f"p={stats['cluster_permutation']['two_sided_p_value']:.2g} "
            f"({stats['paired_attempts']} attempts, {stats['seed_clusters']} seed clusters)"
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
