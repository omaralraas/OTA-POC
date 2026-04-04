"""
Monte Carlo scenario and ablation study runners.

Produces simulation_metrics.csv, ablation_results.csv, and visualization charts.

Usage:
    python -m ota_poc.metrics [--runs N] [--fleet-size N] [--seed N] [--ablation]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from tqdm import tqdm

from ota_poc.config import (
    CDF_ALPHA,
    CDF_BINS,
    CDF_DPI,
    CDF_LINEWIDTH,
    CI_Z_SCORE,
    CONVERGENCE_THRESHOLD,
    CONVERGENCE_WINDOW,
    DEFAULT_FLEET_SIZE,
    DEFAULT_RUNS,
    DEFAULT_SEED,
    MAX_SIMULATION_HOURS,
    MIN_RUNS_FOR_CONVERGENCE,
    P0_ROLLBACK_FAILURE_PROB,
    P1_ROLLBACK_FAILURE_PROB,
    P2_ROLLBACK_FAILURE_PROB,
    PLOT_FIGSIZE,
)
from ota_poc.simulator import OTASimulator

MALICIOUS_ARTIFACT: dict[str, Any] = {
    "version": "v1.1_malicious",
    "hash_ok": True,
    "metadata_valid": True,
    "unsafe_payload": True,
}


def check_convergence(
    series: Sequence[float],
    window: int = CONVERGENCE_WINDOW,
    threshold: float = CONVERGENCE_THRESHOLD,
) -> bool:
    """Check if the rolling P95 has stabilised within threshold %.

    Args:
        series: List of impact values from simulation runs.
        window: Number of runs for the rolling window.
        threshold: Maximum relative change to consider converged.

    Returns:
        True if the series has converged.
    """
    if len(series) < window * 2:
        return False
    recent = float(pd.Series(series[-window:]).quantile(0.95))
    prior = float(pd.Series(series[-window * 2 : -window]).quantile(0.95))
    if prior == 0:
        return False
    return bool(abs(recent - prior) / prior < threshold)


def _compute_bypass_pct(fleet: list[Any], fleet_size: int) -> float:
    """Compute the percentage of the entire fleet that was compromised.

    This measures fleet-wide blast radius, not just among deployed ECUs.

    Args:
        fleet: List of ECU objects.
        fleet_size: Total fleet size (denominator).

    Returns:
        Bypass percentage (0.0-100.0).
    """
    compromised = sum(1 for ecu in fleet if ecu.compromised)
    if fleet_size == 0:
        return 0.0
    return compromised / fleet_size * 100


_ROLLBACK_FAILURE_PROBS: dict[str, float] = {
    "P0_Minimal": P0_ROLLBACK_FAILURE_PROB,
    "P1_Secure_OTA": P1_ROLLBACK_FAILURE_PROB,
    "P2_Layered_Fleet": P2_ROLLBACK_FAILURE_PROB,
}


def _compute_rollback_rate(fleet: list[Any], policy: str, rng: random.Random) -> float:
    """Compute the percentage of compromised ECUs that can be safely rolled back.

    Uses per-policy stochastic failure probabilities to model real-world
    rollback reliability differences (dual-partition, Uptane verification, etc.).

    Args:
        fleet: List of ECU objects.
        policy: Policy identifier for failure probability lookup.
        rng: Random generator for stochastic rollback outcomes.

    Returns:
        Rollback safety percentage (0.0-100.0).
    """
    compromised = [ecu for ecu in fleet if ecu.compromised]
    if not compromised:
        return 100.0
    failure_prob = _ROLLBACK_FAILURE_PROBS.get(policy, P0_ROLLBACK_FAILURE_PROB)
    successes = sum(1 for ecu in compromised if ecu.rollback(rng, failure_prob))
    return successes / len(compromised) * 100


def _compute_confidence_interval(values: list[float]) -> tuple[float, float]:
    """Compute 95% confidence interval for a list of values.

    Args:
        values: List of numeric values.

    Returns:
        Tuple of (lower_bound, upper_bound).
    """
    if len(values) < 2:
        mean_val = float(np.mean(values)) if values else 0.0
        return (float(mean_val), float(mean_val))
    mean_val = float(np.mean(values))
    std_err = float(np.std(values, ddof=1) / np.sqrt(len(values)))
    margin = CI_Z_SCORE * std_err
    return (float(round(mean_val - margin, 1)), float(round(mean_val + margin, 1)))


def run_scenarios(
    fleet_size: int = DEFAULT_FLEET_SIZE,
    runs: int = DEFAULT_RUNS,
    master_seed: int = DEFAULT_SEED,
    min_runs: int = MIN_RUNS_FOR_CONVERGENCE,
) -> None:
    """Run the three-policy Monte Carlo comparison simulation.

    Args:
        fleet_size: Number of ECUs in the simulated fleet.
        runs: Maximum Monte Carlo iterations per policy.
        master_seed: Master random seed for reproducibility.
        min_runs: Minimum runs before convergence check activates.
    """
    policies = ["P0_Minimal", "P1_Secure_OTA", "P2_Layered_Fleet"]
    results: list[dict[str, Any]] = []

    print(
        f"Running Monte Carlo Simulation "
        f"(Fleet Size: {fleet_size}, up to {runs} iterations per policy, "
        f"master_seed={master_seed})..."
    )

    _, axes = plt.subplots(1, 2, figsize=PLOT_FIGSIZE)

    all_impacts: dict[str, list[float]] = {}

    for policy in policies:
        print(f"\nSimulating {policy}...")
        ttds: list[float] = []
        impacts: list[float] = []
        bypass_pcts: list[float] = []
        rollback_rates: list[float] = []

        for i in tqdm(range(runs), desc=f"{policy} Progress"):
            sim = OTASimulator(
                fleet_size=fleet_size,
                policy=policy,
                seed=master_seed + i,
            )
            stats = sim.run_simulation(MALICIOUS_ARTIFACT, max_hours=MAX_SIMULATION_HOURS)
            ttds.append(stats["ttd_hours"])
            impacts.append(stats["impacted_endpoints"])

            bypass_pcts.append(_compute_bypass_pct(sim.fleet, fleet_size))
            rollback_rates.append(_compute_rollback_rate(sim.fleet, sim.policy, sim.rng))

            if i == 0:
                with open(f"{policy}_sample_event_log.json", "w", encoding="utf-8") as f:
                    json.dump(sim.event_log.logs, f, indent=2)

            if i >= min_runs and check_convergence(impacts):
                print(f"  Converged after {i + 1} iterations.")
                break

        all_impacts[policy] = impacts
        ci_lower, ci_upper = _compute_confidence_interval(impacts)

        results.append(
            {
                "Policy": policy,
                "Bypass %": round(pd.Series(bypass_pcts).mean(), 2),
                "Median TTD (h)": round(pd.Series(ttds).median(), 1),
                "P95 TTD (h)": round(pd.Series(ttds).quantile(0.95), 1),
                "E[Impact]": round(pd.Series(impacts).mean()),
                "P95 Impact | Success": round(pd.Series(impacts).quantile(0.95)),
                "Rollback Safety %": round(pd.Series(rollback_rates).mean(), 1),
                "E[Impact] 95% CI": f"[{ci_lower}, {ci_upper}]",
            }
        )

        axes[0].hist(
            impacts,
            density=True,
            cumulative=True,
            label=policy,
            histtype="step",
            alpha=CDF_ALPHA,
            linewidth=CDF_LINEWIDTH,
            bins=CDF_BINS,
        )

    df = pd.DataFrame(results)
    print("\n--- Simulation Results (Aligns with Table III of Research) ---")
    print(df.to_string(index=False))

    axes[0].legend(loc="lower right")
    axes[0].set_xlabel("Number of Compromised Endpoints (Blast Radius)")
    axes[0].set_ylabel("Cumulative Distribution (CDF)")
    axes[0].set_title("Blast Radius by OTA Rollout Policy (Monte Carlo Sim)")
    axes[0].grid(True, linestyle="--", alpha=0.7)

    box_data = [all_impacts[p] for p in policies]
    axes[1].boxplot(box_data, tick_labels=policies, patch_artist=True)
    axes[1].set_ylabel("Blast Radius (Compromised Endpoints)")
    axes[1].set_title("Blast Radius Distribution by Policy")
    axes[1].grid(True, linestyle="--", alpha=0.7)

    plt.tight_layout()
    chart_path = "blast_radius_cdf.png"
    plt.savefig(chart_path, dpi=CDF_DPI)
    print(f"\nSaved chart to '{chart_path}'")

    csv_path = "simulation_metrics.csv"
    df.to_csv(csv_path, index=False)
    print(f"Saved metric results to '{csv_path}'")


@dataclass
class AblationConfig:
    """Configuration for a single ablation experiment."""

    name: str
    base_policy: str
    override_staging: bool = True
    override_monitoring: bool = True
    containment_delay: int = 3


ABLATIONS = [
    AblationConfig(
        "No Staging",
        "P2_Layered_Fleet",
        override_staging=False,
        override_monitoring=True,
        containment_delay=3,
    ),
    AblationConfig(
        "No Transparency Monitor",
        "P2_Layered_Fleet",
        override_staging=True,
        override_monitoring=False,
        containment_delay=3,
    ),
    AblationConfig(
        "Slow Containment (12h)",
        "P2_Layered_Fleet",
        override_staging=True,
        override_monitoring=True,
        containment_delay=12,
    ),
]


def run_ablations(
    fleet_size: int = DEFAULT_FLEET_SIZE,
    runs: int = DEFAULT_RUNS,
    master_seed: int = DEFAULT_SEED,
    min_runs: int = MIN_RUNS_FOR_CONVERGENCE,
) -> None:
    """Run three ablation experiments from Table IV of the research paper.

    Args:
        fleet_size: Number of ECUs in the simulated fleet.
        runs: Maximum Monte Carlo iterations per ablation.
        master_seed: Master random seed for reproducibility.
        min_runs: Minimum runs before convergence check activates.
    """
    print("\n--- Running Ablation Study (Table IV) ---")
    results: list[dict[str, Any]] = []

    for cfg in ABLATIONS:
        impacts: list[float] = []
        ttds: list[float] = []
        bypass_pcts: list[float] = []
        rollback_rates: list[float] = []

        for i in tqdm(range(runs), desc=cfg.name):
            sim = OTASimulator(
                fleet_size=fleet_size,
                policy=cfg.base_policy,
                seed=master_seed + i,
                override_staging=cfg.override_staging,
                override_monitoring=cfg.override_monitoring,
                containment_delay_override=cfg.containment_delay,
            )
            stats = sim.run_simulation(MALICIOUS_ARTIFACT, max_hours=MAX_SIMULATION_HOURS)
            impacts.append(stats["impacted_endpoints"])
            ttds.append(stats["ttd_hours"])

            bypass_pcts.append(_compute_bypass_pct(sim.fleet, fleet_size))
            rollback_rates.append(_compute_rollback_rate(sim.fleet, sim.policy, sim.rng))

            if i >= min_runs and check_convergence(impacts):
                print(f"  '{cfg.name}' converged after {i + 1} iterations.")
                break

        ci_lower, ci_upper = _compute_confidence_interval(impacts)

        results.append(
            {
                "Ablation": cfg.name,
                "Bypass %": round(pd.Series(bypass_pcts).mean(), 2),
                "Median TTD (h)": round(pd.Series(ttds).median(), 1),
                "E[Impact] (50k)": round(pd.Series(impacts).mean()),
                "P95 Impact | Success": round(pd.Series(impacts).quantile(0.95)),
                "Rollback Safety %": round(pd.Series(rollback_rates).mean(), 1),
                "E[Impact] 95% CI": f"[{ci_lower}, {ci_upper}]",
            }
        )

    df = pd.DataFrame(results)
    print(df.to_string(index=False))
    df.to_csv("ablation_results.csv", index=False)
    print("Saved ablation_results.csv")


def main() -> None:
    """CLI entry point for the OTA-POC Monte Carlo simulation."""
    parser = argparse.ArgumentParser(
        description="OTA-POC Monte Carlo Simulation Runner"
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
        help=f"Maximum Monte Carlo iterations per policy (default: {DEFAULT_RUNS})",
    )
    parser.add_argument(
        "--fleet-size",
        type=int,
        default=DEFAULT_FLEET_SIZE,
        help=f"Number of ECUs in the simulated fleet (default: {DEFAULT_FLEET_SIZE})",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help=f"Master random seed for reproducibility (default: {DEFAULT_SEED})",
    )
    parser.add_argument(
        "--ablation",
        action="store_true",
        help="Also run ablation study (Table IV)",
    )
    args = parser.parse_args()

    if args.runs <= 0:
        print("Error: --runs must be a positive integer.", file=sys.stderr)
        sys.exit(1)
    if args.fleet_size <= 0:
        print("Error: --fleet-size must be a positive integer.", file=sys.stderr)
        sys.exit(1)
    if args.seed < 0:
        print("Error: --seed must be a non-negative integer.", file=sys.stderr)
        sys.exit(1)

    run_scenarios(
        fleet_size=args.fleet_size,
        runs=args.runs,
        master_seed=args.seed,
    )

    if args.ablation:
        run_ablations(
            fleet_size=args.fleet_size,
            runs=args.runs,
            master_seed=args.seed,
        )


if __name__ == "__main__":
    main()
