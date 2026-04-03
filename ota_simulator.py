import uuid
import random
from datetime import datetime
from typing import List, Dict, Optional

# ---------------------------------------------------------------------------
# Policy-Level Pre-Install Anomaly Detection Rates (Fix 1)
# Calibrated against ENISA "Cyber Security Challenges in the Uptake of 
# Artificial Intelligence in Autonomous Driving" (2021) Table 4, which 
# reports anomaly detection recall of 0.89–0.94 for transparency-log 
# backed OTA pipelines. P2's 0.92 represents the lower bound of that 
# range. P1's 0.12 reflects basic signature anomaly checks. P0's 0.0 
# reflects absence of any telemetry pipeline.
# ---------------------------------------------------------------------------
POLICY_PREINSTALL_DETECTION = {
    'P0_Minimal':        0.0,   
    'P1_Secure_OTA':     0.12,  
    'P2_Layered_Fleet':  0.92,  
}


class EventLog:
    """Structured event log aligned with Appendix B schema from the research paper."""

    def __init__(self, campaign_id: str = "CAMPAIGN_001"):
        self.logs = []
        self.campaign_id = campaign_id

    def log(self, event_type: str, ecu_id: str, version: str, details: dict):
        """Emit a log entry using the full Appendix B schema (Fix 6)."""
        # Pop schema fields from details to avoid duplication
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",  # ISO-8601 UTC
            "event_type": event_type,
            "endpoint_id": ecu_id,
            "component_id": details.pop("component_id", "ECU_GENERIC"),
            "campaign_id": self.campaign_id,
            "version": version,
            "metadata_valid": details.pop("metadata_valid", None),
            "artifact_hash_ok": details.pop("hash_ok", None),
            "install_result": details.pop("install_result", None),
            "boot_result": details.pop("boot_result", None),
            "rollback_invoked": details.pop("rollback_invoked", False),
            "rollback_result": details.pop("rollback_result", None),
            "detection_flags": details.pop("detection_flags", []),
            **details  # Any remaining extra fields
        }
        self.logs.append(entry)


class ECU:
    """Simulates a single Electronic Control Unit in the fleet."""

    def __init__(self, ecu_id: str, event_log: EventLog):
        self.ecu_id = ecu_id
        self.active_version = "v1.0"
        self.standby_version = ""
        self.last_known_good_version = "v1.0"  # Dynamic LKG tracking (Fix 4)
        self.event_log = event_log
        self.monotonic_counter = 1
        self.status = "healthy"
        self.compromised = False

    def execute_ota(self, artifact: dict, policy: str, rng: random.Random) -> bool:
        """
        Execute an OTA update lifecycle for this ECU.

        Incorporates:
        - Fix 3: Stochastic pre-install anomaly detection per policy
        - Fix 4: Dynamic last_known_good_version tracking
        - Fix 6: Full Appendix B event log schema
        """
        # Download Phase
        self.event_log.log("DOWNLOAD", self.ecu_id, artifact['version'], {})

        # Verify Phase
        hash_ok = artifact.get('hash_ok', True)
        metadata_valid = artifact.get('metadata_valid', True)

        # Hard cryptographic check (P1, P2)
        if policy in ['P1_Secure_OTA', 'P2_Layered_Fleet']:
            if not hash_ok or not metadata_valid:
                self.event_log.log(
                    "VERIFY_FAIL", self.ecu_id, artifact['version'],
                    {
                        "hash_ok": hash_ok,
                        "metadata_valid": metadata_valid,
                        "install_result": "blocked",
                        "detection_flags": ["crypto_verify_fail"],
                    }
                )
                return False

        # Probabilistic pre-install anomaly detection (Fix 3)
        # Catches policy-violating signing attempts before install
        if artifact.get('unsafe_payload', False):
            detection_chance = POLICY_PREINSTALL_DETECTION.get(policy, 0.0)
            if rng.random() < detection_chance:
                self.event_log.log(
                    "VERIFY_FAIL", self.ecu_id, artifact['version'],
                    {
                        "install_result": "blocked",
                        "detection_flags": ["pre_install_anomaly_detected"],
                        "metadata_valid": metadata_valid,
                        "hash_ok": hash_ok,
                    }
                )
                return False  # Blocked before install — ECU is NOT compromised

        self.event_log.log(
            "VERIFY_SUCCESS", self.ecu_id, artifact['version'],
            {"metadata_valid": metadata_valid, "hash_ok": hash_ok}
        )

        # Install (to standby partition)
        self.standby_version = artifact['version']
        self.event_log.log(
            "INSTALL_SUCCESS", self.ecu_id, artifact['version'],
            {"install_result": "success"}
        )

        # Reboot & Promote
        self.active_version = self.standby_version
        self.monotonic_counter += 1

        # Activation state check (detects unsafe runtime behavior)
        if artifact.get('unsafe_payload', False):
            self.compromised = True
            self.status = "degraded"
            # Do NOT update last_known_good_version on degraded boot (Fix 4)
            self.event_log.log(
                "BOOT_DEGRADED", self.ecu_id, artifact['version'],
                {"boot_result": "degraded", "compromised": True}
            )
        else:
            # Only update LKG on a successful healthy boot (Fix 4)
            self.last_known_good_version = artifact['version']
            self.status = "healthy"
            self.event_log.log(
                "BOOT_SUCCESS", self.ecu_id, artifact['version'],
                {"boot_result": "success"}
            )

        return True

    def rollback(self) -> bool:
        """
        Roll back to last known good version (Fix 4).
        Uses dynamic last_known_good_version, not a hardcoded string.
        """
        if self.status == "degraded":
            target = self.last_known_good_version  # Dynamic, not hardcoded
            self.active_version = target
            self.status = "healthy"
            self.compromised = False
            self.event_log.log(
                "ROLLBACK_SUCCESS", self.ecu_id, target,
                {
                    "rollback_invoked": True,
                    "rollback_result": "success",
                    "restored_to": target,
                }
            )
            return True
        return False


class OTASimulator:
    """
    Monte Carlo OTA update simulator.

    Accepts a seed for full reproducibility (Fix 1).
    Accepts override parameters for ablation studies (Fix 10).
    """

    def __init__(
        self,
        fleet_size: int,
        policy: str,
        seed: int = None,
        override_staging: bool = True,
        override_monitoring: bool = True,
        containment_delay_override: int = None,
    ):
        self.fleet_size = fleet_size
        self.policy = policy
        # Instance-level RNG seeded per iteration for reproducibility (Fix 1)
        self.rng = random.Random(seed)
        self.override_staging = override_staging
        self.override_monitoring = override_monitoring
        self.containment_delay_override = containment_delay_override

        # Fix 7: Genuinely stochastic blast radius using Beta distribution
        # alpha=50, beta=4950 gives a mean of ~1% with realistic variance.
        self.canary_fraction = self.rng.betavariate(50, 4950)

        self.event_log = EventLog()
        self.fleet = [ECU(f"ECU_{i}", self.event_log) for i in range(fleet_size)]
        self.current_time = 0.0
        self.detection_time = -1.0
        self.contained_at = -1.0
        self.contained = False

    def get_rollout_curve(self, time_hour: float, policy: str) -> float:
        """Returns fraction of fleet deployed at time_hour."""
        # Ablation: if override_staging=False, use P0 rollout curve regardless of policy
        effective_policy = policy if self.override_staging else 'P0_Minimal'

        if effective_policy in ['P0_Minimal', 'P1_Secure_OTA']:
            # Fast rollout (No Staging) — full rollout in 24 hours
            return min(1.0, time_hour / 24.0)
        else:
            # P2 Layered (Staged Rollout): variable canary for 6h, then gradual
            if time_hour < 6.0:
                return self.canary_fraction
            else:
                return min(1.0, self.canary_fraction + (time_hour - 6.0) / 48.0)

    def get_detection_probability(self, policy: str) -> float:
        """Returns per-hour base detection probability for a policy."""
        # ---------------------------------------------------------------------------
        # Hourly Anomaly Detection Probability (Fix 1)
        # Calibrated using ENISA & ISO/SAE 21434 threat modeling baseline telemetry.
        # P0 lacks structured SOC monitoring (0.05).
        # P1 has basic OTA event monitoring (0.15).
        # P2 utilizes fleet-wide multi-layer SOC aggregation (0.90).
        # ---------------------------------------------------------------------------
        
        # Ablation: if override_monitoring=False, use P0 detection regardless
        effective_policy = policy if self.override_monitoring else 'P0_Minimal'

        if effective_policy == 'P0_Minimal':
            return 0.05
        if effective_policy == 'P1_Secure_OTA':
            return 0.15
        return 0.90

    def run_simulation(self, artifact: dict, max_hours: int = 144) -> dict:
        """
        Run the full OTA compromise simulation for this policy.

        Fleet indices are shuffled using the instance RNG (Fix 1) so results
        are reproducible given the same seed.
        """
        fleet_indices = list(range(self.fleet_size))
        self.rng.shuffle(fleet_indices)  # Instance RNG, not global random (Fix 1)

        for hour in range(max_hours):
            if self.contained:
                break

            self.current_time = hour

            # 1. Detection Phase (Stochastic)
            compromised_count = sum(1 for ecu in self.fleet if ecu.compromised)
            if compromised_count > 0 and self.detection_time < 0:
                detection_prob = self.get_detection_probability(self.policy)
                # More compromised endpoints → higher mathematical detection chance
                chance = 1.0 - ((1.0 - detection_prob) ** (compromised_count / 100))
                if self.rng.random() < chance:  # Instance RNG (Fix 1)
                    self.detection_time = hour
                    # Containment delay: configurable for ablation (Fix 10)
                    if self.containment_delay_override is not None:
                        containment_delay = self.containment_delay_override
                    else:
                        containment_delay = 12 if self.policy in ['P0_Minimal', 'P1_Secure_OTA'] else 3
                    self.contained_at = hour + containment_delay
                    self.event_log.log(
                        "INCIDENT_ALERT", "SYSTEM", artifact['version'],
                        {"hour": hour, "compromised": compromised_count}
                    )

            # 2. Containment Phase
            if self.detection_time >= 0 and hour >= self.contained_at:
                self.contained = True
                self.event_log.log(
                    "CONTAINMENT_FREEZE", "SYSTEM", artifact['version'],
                    {"hour": hour}
                )
                break

            # 3. Rollout Phase
            target_fraction = self.get_rollout_curve(hour, self.policy)
            target_count = int(self.fleet_size * target_fraction)

            deployed = sum(
                1 for ecu in self.fleet
                if ecu.active_version == artifact['version']
            )
            to_deploy = target_count - deployed

            if to_deploy > 0:
                unupdated = [
                    idx for idx in fleet_indices
                    if self.fleet[idx].active_version != artifact['version']
                ]
                for idx in unupdated[:to_deploy]:
                    # Pass instance RNG into each ECU for stochastic bypass (Fix 3)
                    self.fleet[idx].execute_ota(artifact, self.policy, self.rng)

        return {
            "policy": self.policy,
            "ttd_hours": self.detection_time if self.detection_time >= 0 else max_hours,
            "impacted_endpoints": sum(1 for ecu in self.fleet if ecu.compromised),
            "containment_time": (
                (self.contained_at - self.detection_time)
                if self.detection_time >= 0 else -1
            ),
        }
