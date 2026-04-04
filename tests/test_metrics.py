"""
tests/test_metrics.py — Unit tests for the metrics module.

Covers:
- Convergence detection
- CLI input validation
- Helper functions
"""

import subprocess
import sys

import pytest

from ota_poc.metrics import check_convergence, _compute_bypass_pct, _compute_rollback_rate
from ota_poc.simulator import ECU, EventLog, OTASimulator


def make_artifact(unsafe_payload: bool = True) -> dict:
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
    rng = __import__("random").Random(0)
    ecu.execute_ota(make_artifact(), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    artifact = make_artifact()
    pct = _compute_bypass_pct(fleet, artifact)
    assert pct == 100.0


def test_compute_bypass_pct_none_compromised() -> None:
    """When no ECUs are compromised, bypass should be 0%."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = __import__("random").Random(1)
    ecu.execute_ota(make_artifact(unsafe_payload=False), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    artifact = make_artifact()
    pct = _compute_bypass_pct(fleet, artifact)
    assert pct == 0.0


def test_compute_bypass_pct_empty_fleet() -> None:
    """An empty fleet should return 0% bypass."""
    pct = _compute_bypass_pct([], make_artifact())
    assert pct == 0.0


def test_compute_rollback_rate_all_success() -> None:
    """When all compromised ECUs can rollback, rate should be 100%."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = __import__("random").Random(0)
    ecu.execute_ota(make_artifact(), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    rate = _compute_rollback_rate(fleet)
    assert rate == 100.0


def test_compute_rollback_rate_no_compromised() -> None:
    """When no ECUs are compromised, rollback rate should be 100%."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = __import__("random").Random(1)
    ecu.execute_ota(make_artifact(unsafe_payload=False), policy="P0_Minimal", rng=rng)
    fleet = [ecu]
    rate = _compute_rollback_rate(fleet)
    assert rate == 100.0


def test_compute_rollback_rate_empty_fleet() -> None:
    """An empty fleet should return 100% rollback rate."""
    rate = _compute_rollback_rate([])
    assert rate == 100.0


# ---------------------------------------------------------------------------
# CLI input validation tests
# ---------------------------------------------------------------------------


def test_cli_invalid_runs() -> None:
    """CLI should reject non-positive --runs values."""
    result = subprocess.run(
        [sys.executable, "-m", "ota_poc.metrics", "--runs", "0"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Error" in result.stderr


def test_cli_invalid_fleet_size() -> None:
    """CLI should reject non-positive --fleet-size values."""
    result = subprocess.run(
        [sys.executable, "-m", "ota_poc.metrics", "--fleet-size", "-1"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Error" in result.stderr


def test_cli_invalid_seed() -> None:
    """CLI should reject negative --seed values."""
    result = subprocess.run(
        [sys.executable, "-m", "ota_poc.metrics", "--seed", "-5"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Error" in result.stderr
