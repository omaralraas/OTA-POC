"""
generate_metrics.py — Monte Carlo OTA Update Compromise Risk Simulator
Produces simulation_metrics.csv and ablation_results.csv for the research paper.

Usage:
    python generate_metrics.py [--runs N] [--fleet-size N] [--seed N]
"""

import argparse
import json
import os
from dataclasses import dataclass

import matplotlib.pyplot as plt
import pandas as pd
from tqdm import tqdm

from ota_simulator import OTASimulator


# ---------------------------------------------------------------------------
# Convergence Check (Fix 2)
# ---------------------------------------------------------------------------

def check_convergence(series: list, window: int = 50, threshold: float = 0.02) -> bool:
    """
    Returns True if the rolling P95 has stabilised within `threshold` %
    over the last `window` runs compared to the prior `window` runs.
    """
    if len(series) < window * 2:
        return False
    recent = pd.Series(series[-window:]).quantile(0.95)
    prior  = pd.Series(series[-window * 2:-window]).quantile(0.95)
    if prior == 0:
        return False
    return abs(recent - prior) / prior < threshold


# ---------------------------------------------------------------------------
# Main Scenario Runner (Fixes 2, 7)
# ---------------------------------------------------------------------------

def run_scenarios(fleet_size: int = 50000, runs: int = 500,
                  master_seed: int = 42, min_runs: int = 100):
    """
    Run the three-policy Monte Carlo comparison simulation.

    Fix 2: Default 500 iterations with adaptive P95 convergence stopping.
    Fix 7: CSV now includes Bypass % and Rollback Safety % columns.
    """
    policies = ['P0_Minimal', 'P1_Secure_OTA', 'P2_Layered_Fleet']
    results = []

    # ------------------------------------------------------------------
    # Safe PoC Failure Mode: "Policy-violating signing"
    # Mocks a mathematically successful bypass of hashes but introduces
    # runtime degradation (unsafe payload). Non-actionable by design.
    # ------------------------------------------------------------------
    malicious_artifact = {
        "version":          "v1.1_malicious",
        "hash_ok":          True,   # Crypto controls bypassed/intact
        "metadata_valid":   True,   # Authorised keys used (Key Control Threat)
        "unsafe_payload":   True,   # Introduces fleet-wide degradation
    }

    print(
        f"Running Monte Carlo Simulation "
        f"(Fleet Size: {fleet_size}, up to {runs} iterations per policy, "
        f"master_seed={master_seed})..."
    )

    plt.figure(figsize=(10, 6))

    for policy in policies:
        print(f"\nSimulating {policy}...")
        ttds          = []
        impacts       = []
        bypass_pcts   = []
        rollback_rates = []

        for i in tqdm(range(runs), desc=f"{policy} Progress"):
            sim = OTASimulator(
                fleet_size=fleet_size,
                policy=policy,
                seed=master_seed + i,   # Per-iteration seed (Fix 1)
            )
            stats = sim.run_simulation(malicious_artifact, max_hours=144)
            ttds.append(stats['ttd_hours'])
            impacts.append(stats['impacted_endpoints'])

            # --- Fix 7: Bypass % ----------------------------------------
            compromised    = [ecu for ecu in sim.fleet if ecu.compromised]
            total_deployed = sum(
                1 for ecu in sim.fleet
                if ecu.active_version == malicious_artifact['version']
                   or ecu.compromised
            )
            bypass_pct = (
                len(compromised) / total_deployed * 100
                if total_deployed > 0 else 0.0
            )
            bypass_pcts.append(bypass_pct)

            # --- Fix 7: Rollback Safety % --------------------------------
            attempted_rollbacks = sum(1 for ecu in compromised if ecu.rollback())
            rollback_rate = (
                attempted_rollbacks / len(compromised) * 100
                if compromised else 100.0
            )
            rollback_rates.append(rollback_rate)

            # Save event log for first run only
            if i == 0:
                with open(f"{policy}_sample_event_log.json", "w") as f:
                    json.dump(sim.event_log.logs, f, indent=2)

            # Fix 2: adaptive convergence check
            if i >= min_runs and check_convergence(impacts):
                print(f"  Converged after {i + 1} iterations.")
                break

        # Calculate statistics
        median_ttd     = pd.Series(ttds).median()
        p95_ttd        = pd.Series(ttds).quantile(0.95)
        expected_impact = pd.Series(impacts).mean()
        p95_impact     = pd.Series(impacts).quantile(0.95)

        results.append({
            "Policy":               policy,
            "Bypass %":             round(pd.Series(bypass_pcts).mean(), 2),
            "Median TTD (h)":       round(median_ttd, 1),
            "P95 TTD (h)":          round(p95_ttd, 1),
            "E[Impact]":            round(expected_impact),
            "P95 Impact | Success": round(p95_impact),
            "Rollback Safety %":    round(pd.Series(rollback_rates).mean(), 1),
        })

        # CDF plot
        plt.hist(
            impacts, density=True, cumulative=True,
            label=policy, histtype='step', alpha=0.9, linewidth=2, bins=30,
        )

    df = pd.DataFrame(results)
    print("\n--- Simulation Results (Aligns with Table III of Research) ---")
    print(df.to_string(index=False))

    # Finalise and save CDF chart
    plt.legend(loc='lower right')
    plt.xlabel('Number of Compromised Endpoints (Blast Radius)')
    plt.ylabel('Cumulative Distribution (CDF)')
    plt.title('Blast Radius by OTA Rollout Policy (Monte Carlo Sim)')
    plt.grid(True, linestyle='--', alpha=0.7)
    chart_path = 'blast_radius_cdf.png'
    plt.savefig(chart_path, dpi=300)
    print(f"\nSaved CDF chart to '{chart_path}'")

    # Save Metrics CSV
    csv_path = 'simulation_metrics.csv'
    df.to_csv(csv_path, index=False)
    print(f"Saved metric results to '{csv_path}'")


# ---------------------------------------------------------------------------
# Ablation Study Runner (Fix 10)
# ---------------------------------------------------------------------------

@dataclass
class AblationConfig:
    """Configuration for a single ablation experiment (Fix 10)."""
    name:                 str
    base_policy:          str
    override_staging:     bool = True   # False → use P0 rollout curve
    override_monitoring:  bool = True   # False → use P0 detection prob
    containment_delay:    int  = 3      # hours


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


def run_ablations(fleet_size: int = 50000, runs: int = 500,
                  master_seed: int = 42, min_runs: int = 100):
    """
    Run three ablation experiments from Table IV of the research paper.
    Results saved to ablation_results.csv.
    """
    malicious_artifact = {
        "version":        "v1.1_malicious",
        "hash_ok":        True,
        "metadata_valid": True,
        "unsafe_payload": True,
    }

    print("\n--- Running Ablation Study (Table IV) ---")
    results = []

    for cfg in ABLATIONS:
        impacts = []
        ttds    = []
        bypass_pcts = []

        for i in tqdm(range(runs), desc=cfg.name):
            sim = OTASimulator(
                fleet_size=fleet_size,
                policy=cfg.base_policy,
                seed=master_seed + i,
                override_staging=cfg.override_staging,
                override_monitoring=cfg.override_monitoring,
                containment_delay_override=cfg.containment_delay,
            )
            stats = sim.run_simulation(malicious_artifact, max_hours=144)
            impacts.append(stats['impacted_endpoints'])
            ttds.append(stats['ttd_hours'])

            compromised    = [ecu for ecu in sim.fleet if ecu.compromised]
            total_deployed = sum(
                1 for ecu in sim.fleet
                if ecu.active_version == malicious_artifact['version']
                   or ecu.compromised
            )
            bypass_pct = (
                len(compromised) / total_deployed * 100
                if total_deployed > 0 else 0.0
            )
            bypass_pcts.append(bypass_pct)

            if i >= min_runs and check_convergence(impacts):
                print(f"  '{cfg.name}' converged after {i + 1} iterations.")
                break

        results.append({
            "Ablation":           cfg.name,
            "Bypass %":           round(pd.Series(bypass_pcts).mean(), 2),
            "Median TTD (h)":     round(pd.Series(ttds).median(), 1),
            "E[Impact] (50k)":    round(pd.Series(impacts).mean()),
            "P95 Impact | Success": round(pd.Series(impacts).quantile(0.95)),
        })

    df = pd.DataFrame(results)
    print(df.to_string(index=False))
    df.to_csv("ablation_results.csv", index=False)
    print("Saved ablation_results.csv")


# ---------------------------------------------------------------------------
# CLI Entry Point (Fix 2: --runs, --fleet-size, --seed arguments)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="OTA-POC Monte Carlo Simulation Runner"
    )
    parser.add_argument(
        "--runs", type=int, default=500,
        help="Maximum Monte Carlo iterations per policy (default: 500)"
    )
    parser.add_argument(
        "--fleet-size", type=int, default=50000,
        help="Number of ECUs in the simulated fleet (default: 50000)"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Master random seed for reproducibility (default: 42)"
    )
    parser.add_argument(
        "--ablation", action="store_true",
        help="Also run ablation study (Table IV)"
    )
    args = parser.parse_args()

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
