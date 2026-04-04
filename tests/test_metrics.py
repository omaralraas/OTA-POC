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
    _can_rollback,
    _compute_bypass_pct,
    _compute_confidence_interval,
    _compute_rollback_rate,
    check_convergence,
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
    """When all deployed ECUs are compromised, bypass should be 100%."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(0)
    ecu.execute_ota(make_artifact(), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    artifact = make_artifact()
    pct = _compute_bypass_pct(fleet, artifact)
    assert pct == pytest.approx(100.0)


def test_compute_bypass_pct_none_compromised() -> None:
    """When no ECUs are compromised, bypass should be 0%."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(1)
    ecu.execute_ota(make_artifact(unsafe_payload=False), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    artifact = make_artifact()
    pct = _compute_bypass_pct(fleet, artifact)
    assert pct == pytest.approx(0.0)


def test_compute_bypass_pct_empty_fleet() -> None:
    """An empty fleet should return 0% bypass."""
    pct = _compute_bypass_pct([], make_artifact())
    assert pct == pytest.approx(0.0)


def test_compute_rollback_rate_all_success() -> None:
    """When all compromised ECUs can rollback, rate should be 100%."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(0)
    ecu.execute_ota(make_artifact(), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    rate = _compute_rollback_rate(fleet)
    assert rate == pytest.approx(100.0)


def test_compute_rollback_rate_no_compromised() -> None:
    """When no ECUs are compromised, rollback rate should be 100%."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(1)
    ecu.execute_ota(make_artifact(unsafe_payload=False), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    rate = _compute_rollback_rate(fleet)
    assert rate == pytest.approx(100.0)


def test_compute_rollback_rate_empty_fleet() -> None:
    """An empty fleet should return 100% rollback rate."""
    rate = _compute_rollback_rate([])
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


def test_can_rollback_degraded() -> None:
    """A degraded ECU with LKG should be rollback-eligible."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(0)
    ecu.execute_ota(make_artifact(), policy="P0_Minimal", rng=rng)
    assert _can_rollback(ecu) is True


def test_can_rollback_healthy() -> None:
    """A healthy ECU should not be rollback-eligible."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    assert _can_rollback(ecu) is False


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
