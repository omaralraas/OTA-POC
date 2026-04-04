"""
tests/test_simulator.py — Unit tests for the OTA-POC simulation engine.

Covers:
- Healthy ECU update lifecycle
- Hash-failure blocking
- Rollback to last known good version
- P2 lower blast radius than P0
- Seed reproducibility
- Edge cases and boundary conditions
- EventLog schema compliance
"""

import random

import pytest

from ota_poc.config import (
    P0_CONTAINMENT_DELAY_HOURS,
    P0_ROLLOUT_HOURS,
    P2_CANARY_PHASE_HOURS,
    P2_POST_CANARY_ROLLOUT_HOURS,
)
from ota_poc.simulator import ECU, EventLog, OTASimulator

POLICIES = ["P0_Minimal", "P1_Secure_OTA", "P2_Layered_Fleet"]


def make_artifact(
    hash_ok: bool = True, metadata_valid: bool = True, unsafe_payload: bool = False
) -> dict:
    """Create a test artifact dict.

    Args:
        hash_ok: Whether the artifact hash is valid.
        metadata_valid: Whether the metadata is valid.
        unsafe_payload: Whether the payload is unsafe.

    Returns:
        Artifact dict for testing.
    """
    return {
        "version": "v1.1_test",
        "hash_ok": hash_ok,
        "metadata_valid": metadata_valid,
        "unsafe_payload": unsafe_payload,
    }


# ---------------------------------------------------------------------------
# ECU-level tests
# ---------------------------------------------------------------------------


def test_ecu_healthy_update() -> None:
    """A valid, safe artifact should be accepted and ECU remain healthy."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(1)
    result = ecu.execute_ota(make_artifact(), policy="P1_Secure_OTA", rng=rng)
    assert result is True
    assert ecu.status == "healthy"
    assert ecu.last_known_good_version == "v1.1_test", (
        "LKG should be updated on a successful healthy boot"
    )


def test_ecu_hash_fail_blocked_p1() -> None:
    """P1/P2 must reject artifacts with hash_ok=False."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(1)
    result = ecu.execute_ota(
        make_artifact(hash_ok=False), policy="P1_Secure_OTA", rng=rng
    )
    assert result is False
    assert ecu.status == "healthy", (
        "ECU should remain healthy when update is blocked"
    )
    assert ecu.compromised is False


def test_ecu_hash_fail_blocked_p2() -> None:
    """P2 must also reject artifacts with hash_ok=False."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(1)
    result = ecu.execute_ota(
        make_artifact(hash_ok=False), policy="P2_Layered_Fleet", rng=rng
    )
    assert result is False
    assert ecu.compromised is False


def test_p0_accepts_unsafe_payload() -> None:
    """P0 has no pre-install detection; unsafe payloads should always slip through."""
    log = EventLog()
    rng = random.Random(0)
    ecu = ECU("ECU_0", log)
    result = ecu.execute_ota(
        make_artifact(unsafe_payload=True), policy="P0_Minimal", rng=rng
    )
    assert result is True
    assert ecu.compromised is True
    assert ecu.status == "degraded"


def test_rollback_restores_lkg() -> None:
    """Rollback should restore to last_known_good_version, and ECU should recover."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(99)
    ecu.execute_ota(make_artifact(unsafe_payload=True), policy="P0_Minimal", rng=rng)

    if ecu.status == "degraded":
        initial_lkg = ecu.last_known_good_version
        success = ecu.rollback()
        assert success is True
        assert ecu.status == "healthy"
        assert ecu.active_version == initial_lkg
        assert ecu.compromised is False


def test_lkg_not_updated_on_degraded_boot() -> None:
    """last_known_good_version must NOT change when an unsafe payload is installed."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(0)
    original_lkg = ecu.last_known_good_version
    ecu.execute_ota(make_artifact(unsafe_payload=True), policy="P0_Minimal", rng=rng)
    assert ecu.last_known_good_version == original_lkg


def test_eventlog_schema_fields() -> None:
    """EventLog entries must include all Appendix B schema fields."""
    log = EventLog(campaign_id="TEST_CAMPAIGN")
    ecu = ECU("ECU_TEST", log)
    rng = random.Random(1)
    ecu.execute_ota(make_artifact(), policy="P1_Secure_OTA", rng=rng)

    required_fields = {
        "timestamp",
        "event_type",
        "endpoint_id",
        "component_id",
        "campaign_id",
        "version",
        "metadata_valid",
        "artifact_hash_ok",
        "install_result",
        "boot_result",
        "rollback_invoked",
        "rollback_result",
        "detection_flags",
    }
    for entry in log.logs:
        for field in required_fields:
            assert field in entry, f"Missing Appendix B field '{field}' in log entry"
        assert entry["campaign_id"] == "TEST_CAMPAIGN"
        assert isinstance(entry["timestamp"], str)
        assert entry["timestamp"].endswith("Z")


def test_eventlog_log_directly() -> None:
    """EventLog.log() should create entries with correct schema when called directly."""
    log = EventLog(campaign_id="DIRECT_TEST")
    log.log(
        "CUSTOM_EVENT",
        "ECU_DIRECT",
        "v1.0",
        {"component_id": "ECU_CUSTOM", "hash_ok": True},
    )
    assert len(log.logs) == 1
    entry = log.logs[0]
    assert entry["event_type"] == "CUSTOM_EVENT"
    assert entry["endpoint_id"] == "ECU_DIRECT"
    assert entry["artifact_hash_ok"] is True
    assert entry["campaign_id"] == "DIRECT_TEST"
    assert entry["timestamp"].endswith("Z")


def test_rollback_not_degraded_returns_false() -> None:
    """Rollback on a healthy ECU should return False and not change state."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    original_version = ecu.active_version
    result = ecu.rollback()
    assert result is False
    assert ecu.active_version == original_version
    assert ecu.status == "healthy"
    assert ecu.compromised is False


def test_p0_accepts_hash_fail() -> None:
    """P0 has no hash check; unsafe payloads with hash_ok=False should still install."""
    log = EventLog()
    rng = random.Random(0)
    ecu = ECU("ECU_0", log)
    result = ecu.execute_ota(
        make_artifact(hash_ok=False, unsafe_payload=True), policy="P0_Minimal", rng=rng
    )
    assert result is True
    assert ecu.compromised is True
    assert ecu.status == "degraded"


# ---------------------------------------------------------------------------
# Simulator-level tests
# ---------------------------------------------------------------------------


def test_seed_reproducibility() -> None:
    """Identical seeds must produce identical simulation results."""
    artifact = make_artifact(unsafe_payload=True)
    sim_a = OTASimulator(fleet_size=100, policy="P1_Secure_OTA", seed=42)
    sim_b = OTASimulator(fleet_size=100, policy="P1_Secure_OTA", seed=42)
    r_a = sim_a.run_simulation(artifact)
    r_b = sim_b.run_simulation(artifact)
    assert r_a["impacted_endpoints"] == r_b["impacted_endpoints"], (
        "Same seed must produce identical impacted_endpoints"
    )
    assert r_a["ttd_hours"] == r_b["ttd_hours"], (
        "Same seed must produce identical ttd_hours"
    )


def test_different_seeds_vary() -> None:
    """Different seeds should produce different results."""
    artifact = make_artifact(unsafe_payload=True)
    results: set[int] = set()
    for seed in range(10):
        sim = OTASimulator(fleet_size=500, policy="P0_Minimal", seed=seed)
        stats = sim.run_simulation(artifact)
        results.add(stats["impacted_endpoints"])
    assert len(results) > 1, "Different seeds should produce varied results"


def test_p2_lower_blast_radius_than_p0() -> None:
    """P2's staged rollout must produce a lower or equal blast radius than P0."""
    artifact = make_artifact(unsafe_payload=True)
    results: dict[str, int] = {}
    for policy in POLICIES:
        sim = OTASimulator(fleet_size=1000, policy=policy, seed=42)
        stats = sim.run_simulation(artifact, max_hours=144)
        results[policy] = stats["impacted_endpoints"]

    assert results["P2_Layered_Fleet"] <= results["P0_Minimal"], (
        f"P2 blast radius ({results['P2_Layered_Fleet']}) should be <= "
        f"P0 ({results['P0_Minimal']})"
    )


def test_hash_fail_zero_impact_p1() -> None:
    """With hash_ok=False, P1 should produce zero compromised ECUs."""
    artifact = make_artifact(hash_ok=False, unsafe_payload=True)
    sim = OTASimulator(fleet_size=200, policy="P1_Secure_OTA", seed=42)
    stats = sim.run_simulation(artifact, max_hours=144)
    assert stats["impacted_endpoints"] == 0, (
        "P1 must block all installs when hash check fails"
    )


def test_hash_fail_zero_impact_p2() -> None:
    """With hash_ok=False, P2 should produce zero compromised ECUs."""
    artifact = make_artifact(hash_ok=False, unsafe_payload=True)
    sim = OTASimulator(fleet_size=200, policy="P2_Layered_Fleet", seed=42)
    stats = sim.run_simulation(artifact, max_hours=144)
    assert stats["impacted_endpoints"] == 0, (
        "P2 must block all installs when hash check fails"
    )


def test_fleet_size_one() -> None:
    """A fleet of one ECU should not cause errors."""
    artifact = make_artifact(unsafe_payload=True)
    sim = OTASimulator(fleet_size=1, policy="P0_Minimal", seed=42)
    stats = sim.run_simulation(artifact, max_hours=144)
    assert "impacted_endpoints" in stats
    assert "ttd_hours" in stats


def test_max_hours_zero() -> None:
    """Zero simulation hours should return immediately with no impact."""
    artifact = make_artifact(unsafe_payload=True)
    sim = OTASimulator(fleet_size=100, policy="P0_Minimal", seed=42)
    stats = sim.run_simulation(artifact, max_hours=0)
    assert stats["impacted_endpoints"] == 0
    assert stats["ttd_hours"] == 0


def test_containment_time_value() -> None:
    """containment_time should be positive when detection occurs."""
    artifact = make_artifact(unsafe_payload=True)
    sim = OTASimulator(fleet_size=500, policy="P0_Minimal", seed=42)
    stats = sim.run_simulation(artifact, max_hours=144)
    if stats["ttd_hours"] < 144:
        assert stats["containment_time"] > 0, (
            "containment_time should be positive when detection occurs"
        )
        expected = (
            P0_CONTAINMENT_DELAY_HOURS
            if sim.policy in ("P0_Minimal", "P1_Secure_OTA")
            else 3
        )
        assert stats["containment_time"] == expected


def test_get_rollout_curve_p0() -> None:
    """P0 rollout curve should reach 100% at P0_ROLLOUT_HOURS."""
    sim = OTASimulator(fleet_size=100, policy="P0_Minimal", seed=42)
    assert sim.get_rollout_curve(0.0, "P0_Minimal") == 0.0
    assert sim.get_rollout_curve(P0_ROLLOUT_HOURS / 2, "P0_Minimal") == pytest.approx(
        0.5, abs=0.01
    )
    assert sim.get_rollout_curve(P0_ROLLOUT_HOURS, "P0_Minimal") == 1.0
    assert sim.get_rollout_curve(P0_ROLLOUT_HOURS * 2, "P0_Minimal") == 1.0


def test_get_rollout_curve_p2() -> None:
    """P2 rollout curve should hold at canary fraction during canary phase."""
    sim = OTASimulator(fleet_size=1000, policy="P2_Layered_Fleet", seed=42)
    sim.canary_fraction = 0.01
    assert sim.get_rollout_curve(0.0, "P2_Layered_Fleet") == 0.01
    assert (
        sim.get_rollout_curve(P2_CANARY_PHASE_HOURS - 0.1, "P2_Layered_Fleet") == 0.01
    )
    after_canary = sim.get_rollout_curve(
        P2_CANARY_PHASE_HOURS + P2_POST_CANARY_ROLLOUT_HOURS, "P2_Layered_Fleet"
    )
    assert after_canary == pytest.approx(1.0, abs=0.02)


def test_get_rollout_curve_no_staging_override() -> None:
    """With override_staging=False, P2 should use P0 rollout curve."""
    sim = OTASimulator(
        fleet_size=100, policy="P2_Layered_Fleet", seed=42, override_staging=False
    )
    assert sim.get_rollout_curve(P0_ROLLOUT_HOURS, "P2_Layered_Fleet") == 1.0


def test_get_detection_probability_all_policies() -> None:
    """Detection probability should match policy configuration."""
    sim = OTASimulator(fleet_size=100, policy="P0_Minimal", seed=42)
    assert sim.get_detection_probability("P0_Minimal") == pytest.approx(0.05)
    assert sim.get_detection_probability("P1_Secure_OTA") == pytest.approx(0.15)
    assert sim.get_detection_probability("P2_Layered_Fleet") == pytest.approx(0.90)


def test_get_detection_probability_no_monitoring_override() -> None:
    """With override_monitoring=False, detection should fall to P0 level."""
    sim = OTASimulator(
        fleet_size=100, policy="P2_Layered_Fleet", seed=42, override_monitoring=False
    )
    assert sim.get_detection_probability("P2_Layered_Fleet") == pytest.approx(0.05)
