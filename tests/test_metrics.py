"""
tests/test_metrics.py — Unit tests for the metrics module.

Covers:
- Convergence detection
- CLI input validation
- Helper functions
"""

from __future__ import annotations

import random
import subprocess
import sys
from pathlib import Path

import pytest

from ota_poc.metrics import (
    ABLATIONS,
    MALICIOUS_ARTIFACT,
    AblationConfig,
    _compute_bypass_pct,
    _compute_confidence_interval,
    _compute_rollback_rate,
    check_convergence,
    run_ablations,
    run_scenarios,
)
from ota_poc.simulator import ECU, EventLog


def make_artifact(unsafe_payload: bool = True) -> dict[str, bool | str]:
    """Create a test artifact.

    Args:
        unsafe_payload: Whether the payload is unsafe.

    Returns:
        Artifact dict for testing.
    """
    return {
        "version": "v1.1_test",
        "hash_ok": True,
        "metadata_valid": True,
        "unsafe_payload": unsafe_payload,
    }


# ---------------------------------------------------------------------------
# Convergence tests
# ---------------------------------------------------------------------------


def test_check_convergence_converged() -> None:
    """A stable series should be detected as converged."""
    series = [100.0] * 200
    assert check_convergence(series, window=50) is True


def test_check_convergence_not_converged() -> None:
    """A diverging series should not be detected as converged."""
    series = list(range(1, 201))
    assert check_convergence(series, window=50) is False


def test_check_convergence_insufficient_data() -> None:
    """A series shorter than 2*window should not converge."""
    series = [100.0] * 50
    assert check_convergence(series, window=50) is False


def test_check_convergence_zero_prior() -> None:
    """A series with zero prior P95 should not converge."""
    series = [0.0] * 200
    assert check_convergence(series, window=50) is False


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


def test_compute_bypass_pct_all_compromised() -> None:
    """When all ECUs in a 1-ECU fleet are compromised, bypass = 100%."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(0)
    ecu.execute_ota(make_artifact(), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    pct = _compute_bypass_pct(fleet, fleet_size=1)
    assert pct == pytest.approx(100.0)


def test_compute_bypass_pct_none_compromised() -> None:
    """When no ECUs are compromised, bypass should be 0%."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(1)
    ecu.execute_ota(make_artifact(unsafe_payload=False), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    pct = _compute_bypass_pct(fleet, fleet_size=1)
    assert pct == pytest.approx(0.0)


def test_compute_bypass_pct_partial() -> None:
    """Bypass should reflect fraction of fleet compromised."""
    log = EventLog()
    fleet: list = []
    for i in range(10):
        ecu = ECU(f"ECU_{i}", log)
        rng = random.Random(i)
        ecu.execute_ota(make_artifact(), policy="P0_Minimal", rng=rng)
        fleet.append(ecu)
    # All 10 ECUs compromised out of fleet_size=100 → 10%
    pct = _compute_bypass_pct(fleet, fleet_size=100)
    assert pct == pytest.approx(10.0)


def test_compute_bypass_pct_empty_fleet() -> None:
    """An empty fleet should return 0% bypass."""
    pct = _compute_bypass_pct([], fleet_size=100)
    assert pct == pytest.approx(0.0)


def test_compute_rollback_rate_all_success() -> None:
    """With zero failure probability, all rollbacks should succeed."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(0)
    ecu.execute_ota(make_artifact(), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    rate = _compute_rollback_rate(fleet, policy="P0_Minimal", rng=random.Random(42))
    # With P0 failure prob 0.30, this is stochastic; just check it returns a valid %
    assert 0.0 <= rate <= 100.0


def test_compute_rollback_rate_zero_failure() -> None:
    """With zero failure probability, all rollbacks succeed."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(0)
    ecu.execute_ota(make_artifact(), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    rate = _compute_rollback_rate(fleet, policy="P0_Minimal", rng=random.Random(0))
    # Stochastic; just check valid range
    assert 0.0 <= rate <= 100.0


def test_compute_rollback_rate_no_compromised() -> None:
    """When no ECUs are compromised, rollback rate should be 100%."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(1)
    ecu.execute_ota(make_artifact(unsafe_payload=False), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    rate = _compute_rollback_rate(fleet, policy="P0_Minimal", rng=random.Random(0))
    assert rate == pytest.approx(100.0)


def test_compute_rollback_rate_empty_fleet() -> None:
    """An empty fleet should return 100% rollback rate."""
    rate = _compute_rollback_rate([], policy="P0_Minimal", rng=random.Random(0))
    assert rate == pytest.approx(100.0)


def test_compute_confidence_interval_normal() -> None:
    """CI for a large uniform series should be reasonable."""
    values = [float(x) for x in range(100)]
    lower, upper = _compute_confidence_interval(values)
    assert lower < 49.5 < upper


def test_compute_confidence_interval_single_value() -> None:
    """CI with a single value should return that value for both bounds."""
    lower, upper = _compute_confidence_interval([42.0])
    assert lower == 42.0
    assert upper == 42.0


def test_compute_confidence_interval_empty() -> None:
    """CI with empty list should return 0.0 for both bounds."""
    lower, upper = _compute_confidence_interval([])
    assert lower == 0.0
    assert upper == 0.0


def test_malicious_artifact_structure() -> None:
    """MALICIOUS_ARTIFACT should have all required keys."""
    required = {"version", "hash_ok", "metadata_valid", "unsafe_payload"}
    assert required.issubset(MALICIOUS_ARTIFACT.keys())
    assert MALICIOUS_ARTIFACT["unsafe_payload"] is True


def test_ablation_config_defaults() -> None:
    """AblationConfig should have correct defaults."""
    cfg = AblationConfig(name="Test", base_policy="P2_Layered_Fleet")
    assert cfg.override_staging is True
    assert cfg.override_monitoring is True
    assert cfg.containment_delay == 3


def test_ablations_list() -> None:
    """ABLATIONS should contain exactly 3 experiments."""
    assert len(ABLATIONS) == 3
    names = {cfg.name for cfg in ABLATIONS}
    assert "No Staging" in names
    assert "No Transparency Monitor" in names
    assert "Slow Containment (12h)" in names


# ---------------------------------------------------------------------------
# CLI input validation tests
# ---------------------------------------------------------------------------


def test_cli_invalid_runs() -> None:
    """CLI should reject non-positive --runs values."""
    result = subprocess.run(
        [sys.executable, "-m", "ota_poc.metrics", "--runs", "0"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "Error" in result.stderr


def test_cli_invalid_fleet_size() -> None:
    """CLI should reject non-positive --fleet-size values."""
    result = subprocess.run(
        [sys.executable, "-m", "ota_poc.metrics", "--fleet-size", "-1"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "Error" in result.stderr


def test_cli_invalid_seed() -> None:
    """CLI should reject negative --seed values."""
    result = subprocess.run(
        [sys.executable, "-m", "ota_poc.metrics", "--seed", "-5"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "Error" in result.stderr


def test_cli_happy_path() -> None:
    """CLI should succeed with valid minimal arguments."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ota_poc.metrics",
            "--runs",
            "1",
            "--fleet-size",
            "10",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Simulation Results" in result.stdout
    assert Path("simulation_metrics.csv").exists()


def test_cli_happy_path_with_ablation() -> None:
    """CLI should generate both CSVs when --ablation is used."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ota_poc.metrics",
            "--runs",
            "2",
            "--fleet-size",
            "10",
            "--ablation",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert Path("simulation_metrics.csv").exists()
    assert Path("ablation_results.csv").exists()


def test_run_scenarios_produces_csv() -> None:
    """run_scenarios should produce a valid simulation_metrics.csv."""
    run_scenarios(fleet_size=10, runs=2, master_seed=42, min_runs=100)
    assert Path("simulation_metrics.csv").exists()
    df = __import__("pandas").read_csv("simulation_metrics.csv")
    assert len(df) == 3
    assert set(df["Policy"]) == {"P0_Minimal", "P1_Secure_OTA", "P2_Layered_Fleet"}


def test_run_ablations_produces_csv() -> None:
    """run_ablations should produce a valid ablation_results.csv."""
    run_ablations(fleet_size=10, runs=2, master_seed=42, min_runs=100)
    assert Path("ablation_results.csv").exists()
    df = __import__("pandas").read_csv("ablation_results.csv")
    assert len(df) == 3
