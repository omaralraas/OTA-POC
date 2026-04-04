"""
tests/test_ablation.py — Unit tests for the ablation study logic.
"""

from pathlib import Path

from ota_poc.metrics import run_ablations
from ota_poc.simulator import OTASimulator


def make_artifact() -> dict[str, bool | str]:
    """Create a test artifact for ablation studies.

    Returns:
        Artifact dict with unsafe payload enabled.
    """
    return {
        "version": "v1.1_test",
        "hash_ok": True,
        "metadata_valid": True,
        "unsafe_payload": True,
    }


def test_ablation_no_staging_higher_blast_radius() -> None:
    """Removing staging should increase blast radius."""
    artifact = make_artifact()

    sim_baseline = OTASimulator(
        fleet_size=1000, policy="P2_Layered_Fleet", seed=42
    )
    sim_baseline.canary_fraction = 0.01
    stats_baseline = sim_baseline.run_simulation(artifact, max_hours=144)

    sim_no_staging = OTASimulator(
        fleet_size=1000,
        policy="P2_Layered_Fleet",
        seed=42,
        override_staging=False,
    )
    stats_no_staging = sim_no_staging.run_simulation(artifact, max_hours=144)

    assert stats_no_staging["impacted_endpoints"] > stats_baseline["impacted_endpoints"], (
        "Removing staging should increase blast radius (E[Impact])."
    )


def test_ablation_no_monitoring_higher_ttd() -> None:
    """Removing monitoring should increase median TTD."""
    artifact = make_artifact()

    sim_baseline = OTASimulator(
        fleet_size=1000, policy="P2_Layered_Fleet", seed=42
    )
    stats_baseline = sim_baseline.run_simulation(artifact, max_hours=144)

    sim_no_monitoring = OTASimulator(
        fleet_size=1000,
        policy="P2_Layered_Fleet",
        seed=42,
        override_monitoring=False,
    )
    stats_no_monitoring = sim_no_monitoring.run_simulation(artifact, max_hours=144)

    assert stats_no_monitoring["ttd_hours"] > stats_baseline["ttd_hours"], (
        "Removing monitoring should increase median TTD."
    )


def test_ablation_runner_completes() -> None:
    """run_ablations() should complete without raising exceptions."""
    run_ablations(fleet_size=200, runs=5, master_seed=42, min_runs=5)

    csv_path = Path("ablation_results.csv")
    assert csv_path.exists(), "ablation_results.csv should be saved."
    csv_path.unlink()


def test_ablation_slow_containment_higher_impact() -> None:
    """Slower containment should result in higher impact."""
    artifact = make_artifact()

    sim_fast = OTASimulator(
        fleet_size=1000,
        policy="P2_Layered_Fleet",
        seed=42,
        containment_delay_override=3,
    )
    stats_fast = sim_fast.run_simulation(artifact, max_hours=144)

    sim_slow = OTASimulator(
        fleet_size=1000,
        policy="P2_Layered_Fleet",
        seed=42,
        containment_delay_override=12,
    )
    stats_slow = sim_slow.run_simulation(artifact, max_hours=144)

    assert stats_slow["impacted_endpoints"] > stats_fast["impacted_endpoints"], (
        "Slower containment should result in higher impact."
    )
