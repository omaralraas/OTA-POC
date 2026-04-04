"""Backward-compatible shim: `from ota_simulator import ...` still works."""

from ota_poc.simulator import ECU, EventLog, OTASimulator

__all__ = ["ECU", "EventLog", "OTASimulator"]
