"""
Core OTA simulation engine.

Simulates Electronic Control Units (ECUs), OTA update lifecycles,
and fleet-level Monte Carlo compromise risk analysis.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Any

from ota_poc.config import (
    CANARY_BETA_ALPHA,
    CANARY_BETA_BETA,
    P0_CONTAINMENT_DELAY_HOURS,
    P0_DETECTION_PROB,
    P0_PREINSTALL_DETECTION,
    P0_ROLLOUT_HOURS,
    P1_CONTAINMENT_DELAY_HOURS,
    P1_DETECTION_PROB,
    P1_PREINSTALL_DETECTION,
    P2_CANARY_PHASE_HOURS,
    P2_CONTAINMENT_DELAY_HOURS,
    P2_DETECTION_PROB,
    P2_POST_CANARY_ROLLOUT_HOURS,
    P2_PREINSTALL_DETECTION,
    DETECTION_SCALING_FACTOR,
)


class EventLog:
    """Structured event log aligned with Appendix B schema from the research paper."""

    def __init__(self, campaign_id: str = "CAMPAIGN_001") -> None:
        self.logs: list[dict[str, Any]] = []
        self.campaign_id = campaign_id

    def log(
        self,
        event_type: str,
        ecu_id: str,
        version: str,
        details: dict[str, Any],
    ) -> None:
        """Emit a log entry using the full Appendix B schema.

        Args:
            event_type: Type of event (DOWNLOAD, VERIFY_SUCCESS, etc.).
            ecu_id: Identifier of the ECU.
            version: Firmware version being processed.
            details: Additional schema fields (component_id, hash_ok, etc.).
        """
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            "endpoint_id": ecu_id,
            "component_id": details.get("component_id", "ECU_GENERIC"),
            "campaign_id": self.campaign_id,
            "version": version,
            "metadata_valid": details.get("metadata_valid", None),
            "artifact_hash_ok": details.get("hash_ok", None),
            "install_result": details.get("install_result", None),
            "boot_result": details.get("boot_result", None),
            "rollback_invoked": details.get("rollback_invoked", False),
            "rollback_result": details.get("rollback_result", None),
            "detection_flags": details.get("detection_flags", []),
        }
        extra = {k: v for k, v in details.items() if k not in entry}
        entry.update(extra)
        self.logs.append(entry)


class ECU:
    """Simulates a single Electronic Control Unit in the fleet."""

    def __init__(self, ecu_id: str, event_log: EventLog) -> None:
        self.ecu_id = ecu_id
        self.active_version = "v1.0"
        self.standby_version = ""
        self.last_known_good_version = "v1.0"
        self.event_log = event_log
        self.monotonic_counter = 1
        self.status = "healthy"
        self.compromised = False

    def execute_ota(
        self,
        artifact: dict[str, Any],
        policy: str,
        rng: random.Random,
    ) -> bool:
        """Execute an OTA update lifecycle for this ECU.

        Args:
            artifact: The OTA artifact dict (version, hash_ok, metadata_valid, unsafe_payload).
            policy: Policy identifier (P0_Minimal, P1_Secure_OTA, P2_Layered_Fleet).
            rng: Instance-level random generator for reproducibility.

        Returns:
            True if the update was installed, False if blocked.
        """
        self.event_log.log("DOWNLOAD", self.ecu_id, artifact["version"], {})

        hash_ok = artifact.get("hash_ok", True)
        metadata_valid = artifact.get("metadata_valid", True)

        if policy in ("P1_Secure_OTA", "P2_Layered_Fleet"):
            if not hash_ok or not metadata_valid:
                self.event_log.log(
                    "VERIFY_FAIL",
                    self.ecu_id,
                    artifact["version"],
                    {
                        "hash_ok": hash_ok,
                        "metadata_valid": metadata_valid,
                        "install_result": "blocked",
                        "detection_flags": ["crypto_verify_fail"],
                    },
                )
                return False

        preinstall_detection = {
            "P0_Minimal": P0_PREINSTALL_DETECTION,
            "P1_Secure_OTA": P1_PREINSTALL_DETECTION,
            "P2_Layered_Fleet": P2_PREINSTALL_DETECTION,
        }.get(policy, 0.0)

        if artifact.get("unsafe_payload", False):
            if rng.random() < preinstall_detection:
                self.event_log.log(
                    "VERIFY_FAIL",
                    self.ecu_id,
                    artifact["version"],
                    {
                        "install_result": "blocked",
                        "detection_flags": ["pre_install_anomaly_detected"],
                        "metadata_valid": metadata_valid,
                        "hash_ok": hash_ok,
                    },
                )
                return False

        self.event_log.log(
            "VERIFY_SUCCESS",
            self.ecu_id,
            artifact["version"],
            {"metadata_valid": metadata_valid, "hash_ok": hash_ok},
        )

        self.standby_version = artifact["version"]
        self.event_log.log(
            "INSTALL_SUCCESS",
            self.ecu_id,
            artifact["version"],
            {"install_result": "success"},
        )

        self.active_version = self.standby_version
        self.monotonic_counter += 1

        if artifact.get("unsafe_payload", False):
            self.compromised = True
            self.status = "degraded"
            self.event_log.log(
                "BOOT_DEGRADED",
                self.ecu_id,
                artifact["version"],
                {"boot_result": "degraded", "compromised": True},
            )
        else:
            self.last_known_good_version = artifact["version"]
            self.status = "healthy"
            self.event_log.log(
                "BOOT_SUCCESS",
                self.ecu_id,
                artifact["version"],
                {"boot_result": "success"},
            )

        return True

    def rollback(self) -> bool:
        """Roll back to last known good version.

        Returns:
            True if rollback was performed, False if ECU was not degraded.
        """
        if self.status == "degraded":
            target = self.last_known_good_version
            self.active_version = target
            self.status = "healthy"
            self.compromised = False
            self.event_log.log(
                "ROLLBACK_SUCCESS",
                self.ecu_id,
                target,
                {
                    "rollback_invoked": True,
                    "rollback_result": "success",
                    "restored_to": target,
                },
            )
            return True
        return False


class OTASimulator:
    """Monte Carlo OTA update simulator.

    Accepts a seed for full reproducibility and override parameters
    for ablation studies.
    """

    def __init__(
        self,
        fleet_size: int,
        policy: str,
        seed: int | None = None,
        override_staging: bool = True,
        override_monitoring: bool = True,
        containment_delay_override: int | None = None,
    ) -> None:
        self.fleet_size = fleet_size
        self.policy = policy
        self.rng = random.Random(seed)
        self.override_staging = override_staging
        self.override_monitoring = override_monitoring
        self.containment_delay_override = containment_delay_override

        self.canary_fraction = self.rng.betavariate(CANARY_BETA_ALPHA, CANARY_BETA_BETA)

        self.event_log = EventLog()
        self.fleet = [ECU(f"ECU_{i}", self.event_log) for i in range(fleet_size)]
        self.current_time = 0.0
        self.detection_time = -1.0
        self.contained_at = -1.0
        self.contained = False

        self._compromised_count = 0
        self._deployed_count = 0

    def get_rollout_curve(self, time_hour: float, policy: str) -> float:
        """Return fraction of fleet deployed at the given hour.

        Args:
            time_hour: Simulation hour.
            policy: Policy identifier.

        Returns:
            Fraction of fleet that should have received the update.
        """
        effective_policy = policy if self.override_staging else "P0_Minimal"

        if effective_policy in ("P0_Minimal", "P1_Secure_OTA"):
            return min(1.0, time_hour / P0_ROLLOUT_HOURS)
        else:
            if time_hour < P2_CANARY_PHASE_HOURS:
                return self.canary_fraction
            return min(
                1.0,
                self.canary_fraction + (time_hour - P2_CANARY_PHASE_HOURS) / P2_POST_CANARY_ROLLOUT_HOURS,
            )

    def get_detection_probability(self, policy: str) -> float:
        """Return per-hour base detection probability for a policy.

        Args:
            policy: Policy identifier.

        Returns:
            Hourly detection probability (0.0 to 1.0).
        """
        effective_policy = policy if self.override_monitoring else "P0_Minimal"

        return {
            "P0_Minimal": P0_DETECTION_PROB,
            "P1_Secure_OTA": P1_DETECTION_PROB,
            "P2_Layered_Fleet": P2_DETECTION_PROB,
        }.get(effective_policy, P0_DETECTION_PROB)

    def _check_detection(self, hour: int, artifact: dict[str, Any]) -> None:
        """Check whether the incident is detected this hour."""
        if self.detection_time >= 0:
            return

        if self._compromised_count == 0:
            return

        detection_prob = self.get_detection_probability(self.policy)
        chance = 1.0 - ((1.0 - detection_prob) ** (self._compromised_count / DETECTION_SCALING_FACTOR))
        if self.rng.random() < chance:
            self.detection_time = hour
            if self.containment_delay_override is not None:
                containment_delay = self.containment_delay_override
            elif self.policy in ("P0_Minimal", "P1_Secure_OTA"):
                containment_delay = P0_CONTAINMENT_DELAY_HOURS
            else:
                containment_delay = P2_CONTAINMENT_DELAY_HOURS
            self.contained_at = hour + containment_delay
            self.event_log.log(
                "INCIDENT_ALERT",
                "SYSTEM",
                artifact["version"],
                {"hour": hour, "compromised": self._compromised_count},
            )

    def _check_containment(self, hour: int, artifact: dict[str, Any]) -> bool:
        """Check whether containment has been triggered.

        Returns:
            True if containment was triggered this hour.
        """
        if self.detection_time >= 0 and hour >= self.contained_at:
            self.contained = True
            self.event_log.log(
                "CONTAINMENT_FREEZE",
                "SYSTEM",
                artifact["version"],
                {"hour": hour},
            )
            return True
        return False

    def _deploy_updates(self, artifact: dict[str, Any], fleet_indices: list[int]) -> None:
        """Deploy OTA updates to the next batch of ECUs."""
        target_fraction = self.get_rollout_curve(self.current_time, self.policy)
        target_count = round(self.fleet_size * target_fraction)

        to_deploy = target_count - self._deployed_count
        if to_deploy <= 0:
            return

        unupdated = [
            idx for idx in fleet_indices
            if self.fleet[idx].active_version != artifact["version"]
        ]

        for idx in unupdated[:to_deploy]:
            ecu = self.fleet[idx]
            was_compromised = ecu.compromised
            was_deployed = ecu.active_version == artifact["version"]
            ecu.execute_ota(artifact, self.policy, self.rng)
            if ecu.compromised and not was_compromised:
                self._compromised_count += 1
            if ecu.active_version == artifact["version"] and not was_deployed:
                self._deployed_count += 1

    def run_simulation(
        self,
        artifact: dict[str, Any],
        max_hours: int = 144,
    ) -> dict[str, Any]:
        """Run the full OTA compromise simulation.

        Args:
            artifact: The malicious OTA artifact dict.
            max_hours: Maximum simulation hours.

        Returns:
            Dict with policy, ttd_hours, impacted_endpoints, containment_time.
        """
        fleet_indices = list(range(self.fleet_size))
        self.rng.shuffle(fleet_indices)

        for hour in range(max_hours):
            if self.contained:
                break

            self.current_time = hour

            self._check_detection(hour, artifact)

            if self._check_containment(hour, artifact):
                break

            self._deploy_updates(artifact, fleet_indices)

        return {
            "policy": self.policy,
            "ttd_hours": self.detection_time if self.detection_time >= 0 else max_hours,
            "impacted_endpoints": self._compromised_count,
            "containment_time": (
                (self.contained_at - self.detection_time)
                if self.detection_time >= 0
                else -1
            ),
        }
