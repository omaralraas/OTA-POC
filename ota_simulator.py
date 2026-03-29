import uuid
import time
from typing import List, Dict, Optional
import random

class EventLog:
    def __init__(self):
        self.logs = []
        
    def log(self, event_type: str, ecu_id: str, version: str, details: dict):
        self.logs.append({
            "timestamp": time.time(),
            "event_type": event_type,
            "endpoint_id": ecu_id,
            "version": version,
            **details
        })

class ECU:
    def __init__(self, ecu_id: str, event_log: EventLog):
        self.ecu_id = ecu_id
        self.active_version = "v1.0"
        self.standby_version = ""
        self.event_log = event_log
        self.monotonic_counter = 1
        self.status = "healthy"
        self.compromised = False
        
    def execute_ota(self, artifact: dict, policy: str) -> bool:
        # Download Phase
        self.event_log.log("DOWNLOAD", self.ecu_id, artifact['version'], {})
        
        # Verify Phase
        hash_ok = artifact.get('hash_ok', True)
        metadata_valid = artifact.get('metadata_valid', True)
        
        # Cryptographic Controls (P1 and P2 enforce this)
        if policy in ['P1_Secure_OTA', 'P2_Layered_Fleet']:
            if not hash_ok or not metadata_valid:
                self.event_log.log("VERIFY_FAIL", self.ecu_id, artifact['version'], {"hash_ok": hash_ok, "metadata_valid": metadata_valid})
                return False
                
        self.event_log.log("VERIFY_SUCCESS", self.ecu_id, artifact['version'], {})
        
        # Install (to standby partition)
        self.standby_version = artifact['version']
        self.event_log.log("INSTALL_SUCCESS", self.ecu_id, artifact['version'], {})
        
        # Reboot & Promote
        self.active_version = self.standby_version
        self.monotonic_counter += 1
        
        # Activation state check (Detects unsafe runtime behavior)
        if artifact.get('unsafe_payload', False):
            self.compromised = True
            self.status = "degraded"
            self.event_log.log("BOOT_DEGRADED", self.ecu_id, artifact['version'], {"compromised": True})
        else:
            self.status = "healthy"
            self.event_log.log("BOOT_SUCCESS", self.ecu_id, artifact['version'], {})
            
        return True
        
    def rollback(self):
        # Rollback recovers the system from a degraded state (Safe Fallback)
        if self.status == "degraded":
            self.active_version = "v1.0" # Mock last-known-good
            self.status = "healthy"
            self.compromised = False
            self.event_log.log("ROLLBACK_SUCCESS", self.ecu_id, "v1.0", {})
            return True
        return False

class OTASimulator:
    def __init__(self, fleet_size: int, policy: str):
        self.fleet_size = fleet_size
        self.policy = policy
        self.event_log = EventLog()
        self.fleet = [ECU(f"ECU_{i}", self.event_log) for i in range(fleet_size)]
        self.current_time = 0.0
        self.detection_time = -1.0
        self.contained_at = -1.0
        self.contained = False
        
    def get_rollout_curve(self, time_hour: float, policy: str) -> float:
        # Returns percentage of fleet deployed at time_hour
        if policy in ['P0_Minimal', 'P1_Secure_OTA']:
            # Fast rollout (No Staging)
            return min(1.0, time_hour / 24.0) # Full rollout expected in 24 hours
        else:
            # P2 Layered (Staged Rollout)
            if time_hour < 6.0:
                return 0.01 # 1% canary group held for a 6h observation window
            else:
                return min(1.0, 0.01 + (time_hour - 6.0) / 48.0) # Gradual rollout over the next 48h
                
    def get_detection_probability(self, policy: str) -> float:
        # P2 assumes robust transparency monitoring and anomaly-driven telemetry
        if policy == 'P0_Minimal': return 0.05
        if policy == 'P1_Secure_OTA': return 0.15
        return 0.90 
        
    def run_simulation(self, artifact: dict, max_hours: int = 144):
        fleet_indices = list(range(self.fleet_size))
        random.shuffle(fleet_indices)
        
        for hour in range(max_hours):
            if self.contained:
                break
                
            self.current_time = hour
            
            # 1. Detection Phase (Stochastic)
            compromised_count = sum(1 for ecu in self.fleet if ecu.compromised)
            if compromised_count > 0 and self.detection_time < 0:
                detection_prob = self.get_detection_probability(self.policy)
                # The more compromised, the higher the mathematical chance of detecting an anomaly
                chance = 1.0 - ((1.0 - detection_prob) ** (compromised_count / 100))
                if random.random() < chance:
                    self.detection_time = hour
                    # Incident Response constraints: Containment target is faster in P2
                    containment_delay = 12 if self.policy in ['P0_Minimal', 'P1_Secure_OTA'] else 3
                    self.contained_at = hour + containment_delay
                    self.event_log.log("INCIDENT_ALERT", "SYSTEM", artifact['version'], {"hour": hour, "compromised": compromised_count})
                    
            # 2. Containment Phase
            if self.detection_time >= 0 and hour >= self.contained_at:
                self.contained = True
                self.event_log.log("CONTAINMENT_FREEZE", "SYSTEM", artifact['version'], {"hour": hour})
                break
                
            # 3. Rollout Phase
            target_fraction = self.get_rollout_curve(hour, self.policy)
            target_count = int(self.fleet_size * target_fraction)
            
            deployed = sum(1 for ecu in self.fleet if ecu.active_version == artifact['version'])
            to_deploy = target_count - deployed
            
            if to_deploy > 0:
                unupdated = [idx for idx in fleet_indices if self.fleet[idx].active_version != artifact['version']]
                for idx in unupdated[:to_deploy]:
                    self.fleet[idx].execute_ota(artifact, self.policy)
                    
        return {
            "policy": self.policy,
            "ttd_hours": self.detection_time if self.detection_time >= 0 else max_hours,
            "impacted_endpoints": sum(1 for ecu in self.fleet if ecu.compromised),
            "containment_time": (self.contained_at - self.detection_time) if self.detection_time >= 0 else -1
        }
