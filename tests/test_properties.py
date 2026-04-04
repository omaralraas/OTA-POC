"""Property-based tests for simulation invariants."""

from hypothesis import given, settings
from hypothesis import strategies as st

from ota_poc.simulator import OTASimulator

POLICIES = ["P0_Minimal", "P1_Secure_OTA", "P2_Layered_Fleet"]

MALICIOUS = {
    "version": "v1.1_malicious",
    "hash_ok": True,
    "metadata_valid": True,
    "unsafe_payload": True,
}


@given(
    seed=st.integers(min_value=0, max_value=10000),
    fleet_size=st.integers(min_value=10, max_value=500),
)
@settings(max_examples=50)
def test_p2_never_exceeds_p0_blast_radius(seed: int, fleet_size: int) -> None:
    """For any seed and fleet size, P2 blast radius <= P0 blast radius."""
    sim_p0 = OTASimulator(fleet_size=fleet_size, policy="P0_Minimal", seed=seed)
    sim_p2 = OTASimulator(fleet_size=fleet_size, policy="P2_Layered_Fleet", seed=seed)
    r_p0 = sim_p0.run_simulation(MALICIOUS)
    r_p2 = sim_p2.run_simulation(MALICIOUS)
    assert r_p2["impacted_endpoints"] <= r_p0["impacted_endpoints"]


@given(seed=st.integers(min_value=0, max_value=10000))
@settings(max_examples=50)
def test_same_seed_always_identical(seed: int) -> None:
    """Identical seeds must always produce identical results."""
    artifact = MALICIOUS
    for policy in POLICIES:
        sim_a = OTASimulator(fleet_size=100, policy=policy, seed=seed)
        sim_b = OTASimulator(fleet_size=100, policy=policy, seed=seed)
        assert sim_a.run_simulation(artifact) == sim_b.run_simulation(artifact)


@given(seed=st.integers(min_value=0, max_value=10000))
@settings(max_examples=30)
def test_impacted_never_exceeds_fleet_size(seed: int) -> None:
    """Impacted endpoints can never exceed fleet size."""
    for policy in POLICIES:
        fleet_size = 200
        sim = OTASimulator(fleet_size=fleet_size, policy=policy, seed=seed)
        stats = sim.run_simulation(MALICIOUS)
        assert stats["impacted_endpoints"] <= fleet_size
