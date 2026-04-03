"""
tests/test_simulator.py — Unit tests for the OTA-POC simulation engine.

Covers:
- Healthy ECU update lifecycle
- Hash-failure blocking
- Rollback to last known good version
- P2 lower blast radius than P0
- Seed reproducibility
"""

import random
import pytest

from ota_simulator import ECU, OTASimulator, EventLog


POLICIES = ['P0_Minimal', 'P1_Secure_OTA', 'P2_Layered_Fleet']


def make_artifact(hash_ok: bool = True, metadata_valid: bool = True,
                  unsafe_payload: bool = False) -> dict:
    return {
        "version":        "v1.1_test",
        "hash_ok":        hash_ok,
        "metadata_valid": metadata_valid,
        "unsafe_payload": unsafe_payload,
    }


# ---------------------------------------------------------------------------
# ECU-level tests
# ---------------------------------------------------------------------------

def test_ecu_healthy_update():
    """A valid, safe artifact should be accepted and ECU remain healthy."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(1)
    result = ecu.execute_ota(make_artifact(), policy='P1_Secure_OTA', rng=rng)
    assert result is True
    assert ecu.status == "healthy"
    assert ecu.last_known_good_version == "v1.1_test", \
        "LKG should be updated on a successful healthy boot"


def test_ecu_hash_fail_blocked_p1():
    """P1/P2 must reject artifacts with hash_ok=False."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(1)
    result = ecu.execute_ota(
        make_artifact(hash_ok=False), policy='P1_Secure_OTA', rng=rng
    )
    assert result is False
    assert ecu.status == "healthy", "ECU should remain healthy when update is blocked"
    assert ecu.compromised is False


def test_ecu_hash_fail_blocked_p2():
    """P2 must also reject artifacts with hash_ok=False."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(1)
    result = ecu.execute_ota(
        make_artifact(hash_ok=False), policy='P2_Layered_Fleet', rng=rng
    )
    assert result is False
    assert ecu.compromised is False


def test_p0_accepts_unsafe_payload():
    """P0 has no pre-install detection; unsafe payloads should always slip through."""
    log = EventLog()
    # Force rng to always return > detection chance (0.0 for P0, so all pass)
    rng = random.Random(0)
    ecu = ECU("ECU_0", log)
    result = ecu.execute_ota(
        make_artifact(unsafe_payload=True), policy='P0_Minimal', rng=rng
    )
    assert result is True
    assert ecu.compromised is True
    assert ecu.status == "degraded"


def test_rollback_restores_lkg():
    """Rollback should restore to last_known_good_version, and ECU should recover."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(99)
    # Force compromised state via P0 (no pre-install detection)
    ecu.execute_ota(make_artifact(unsafe_payload=True), policy='P0_Minimal', rng=rng)

    if ecu.status == "degraded":
        initial_lkg = ecu.last_known_good_version
        success = ecu.rollback()
        assert success is True
        assert ecu.status == "healthy"
        assert ecu.active_version == initial_lkg
        assert ecu.compromised is False


def test_lkg_not_updated_on_degraded_boot():
    """last_known_good_version must NOT change when an unsafe payload is installed."""
    log = EventLog()
    ecu = ECU("ECU_0", log)
    rng = random.Random(0)
    original_lkg = ecu.last_known_good_version  # "v1.0"
    ecu.execute_ota(make_artifact(unsafe_payload=True), policy='P0_Minimal', rng=rng)
    # LKG should still be v1.0 because the boot was degraded
    assert ecu.last_known_good_version == original_lkg


def test_eventlog_schema_fields():
    """EventLog entries must include all Appendix B schema fields."""
    log = EventLog(campaign_id="TEST_CAMPAIGN")
    ecu = ECU("ECU_TEST", log)
    rng = random.Random(1)
    ecu.execute_ota(make_artifact(), policy='P1_Secure_OTA', rng=rng)

    required_fields = {
        "timestamp", "event_type", "endpoint_id", "component_id",
        "campaign_id", "version", "metadata_valid", "artifact_hash_ok",
        "install_result", "boot_result", "rollback_invoked",
        "rollback_result", "detection_flags",
    }
    for entry in log.logs:
        for field in required_fields:
            assert field in entry, f"Missing Appendix B field '{field}' in log entry"
        assert entry["campaign_id"] == "TEST_CAMPAIGN"
        # Timestamps must be ISO-8601 strings, not Unix floats
        assert isinstance(entry["timestamp"], str)
        assert entry["timestamp"].endswith("Z")


# ---------------------------------------------------------------------------
# Simulator-level tests
# ---------------------------------------------------------------------------

def test_seed_reproducibility():
    """Identical seeds must produce identical simulation results."""
    artifact = make_artifact(unsafe_payload=True)
    sim_a = OTASimulator(fleet_size=100, policy='P1_Secure_OTA', seed=42)
    sim_b = OTASimulator(fleet_size=100, policy='P1_Secure_OTA', seed=42)
    r_a = sim_a.run_simulation(artifact)
    r_b = sim_b.run_simulation(artifact)
    assert r_a['impacted_endpoints'] == r_b['impacted_endpoints'], \
        "Same seed must produce identical impacted_endpoints"
    assert r_a['ttd_hours'] == r_b['ttd_hours'], \
        "Same seed must produce identical ttd_hours"


def test_different_seeds_vary():
    """Different seeds should (with very high probability) produce different results."""
    artifact = make_artifact(unsafe_payload=True)
    results = set()
    for seed in range(10):
        sim = OTASimulator(fleet_size=500, policy='P0_Minimal', seed=seed)
        stats = sim.run_simulation(artifact)
        results.add(stats['impacted_endpoints'])
    # At least two different outcomes across 10 seeds
    assert len(results) > 1, "Different seeds should produce varied results"


def test_p2_lower_blast_radius_than_p0():
    """P2's staged rollout must produce a lower or equal blast radius than P0."""
    artifact = make_artifact(unsafe_payload=True)
    results = {}
    for policy in POLICIES:
        sim = OTASimulator(fleet_size=1000, policy=policy, seed=42)
        stats = sim.run_simulation(artifact, max_hours=144)
        results[policy] = stats['impacted_endpoints']

    assert results['P2_Layered_Fleet'] <= results['P0_Minimal'], (
        f"P2 blast radius ({results['P2_Layered_Fleet']}) should be ≤ "
        f"P0 ({results['P0_Minimal']})"
    )


def test_hash_fail_zero_impact_p1():
    """With hash_ok=False, P1 should produce zero compromised ECUs."""
    artifact = make_artifact(hash_ok=False, unsafe_payload=True)
    sim = OTASimulator(fleet_size=200, policy='P1_Secure_OTA', seed=42)
    stats = sim.run_simulation(artifact, max_hours=144)
    assert stats['impacted_endpoints'] == 0, \
        "P1 must block all installs when hash check fails"


def test_hash_fail_zero_impact_p2():
    """With hash_ok=False, P2 should produce zero compromised ECUs."""
    artifact = make_artifact(hash_ok=False, unsafe_payload=True)
    sim = OTASimulator(fleet_size=200, policy='P2_Layered_Fleet', seed=42)
    stats = sim.run_simulation(artifact, max_hours=144)
    assert stats['impacted_endpoints'] == 0, \
        "P2 must block all installs when hash check fails"
