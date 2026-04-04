# Proof of Concept: OTA Update Channel Compromise Risk

[![CI](https://github.com/omaralraas/OTA-POC/actions/workflows/ci.yml/badge.svg)](https://github.com/omaralraas/OTA-POC/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

This repository contains the executable Proof of Concept (PoC) for the academic research paper:

> *"Measuring OTA Update-Channel Compromise Risk in Smart Mobility Ecosystems: A Safe Testbed and Governance to Engineering Controls."*
> **Omar Alraas & Mohammad Thabet** — Canadian University Dubai, 2025.

It implements a non-actionable, reproducible Monte Carlo simulation demonstrating how fleet-scale cryptographic engineering controls (P1) compare to Layered Fleet Governance (P2).

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Understanding the Policies](#understanding-the-policies)
- [Running the Simulation](#running-the-simulation)
- [Validating Results](#validating-results)
- [Alternative Scenarios](#alternative-scenarios)
- [Running Tests](#running-tests)
- [Development](#development)
- [Paper Citation](#paper-citation)
- [Future Work](#future-work)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Quick smoke test (10 runs, 1000 ECUs)
python -m ota_poc.metrics --runs 10 --fleet-size 1000

# Full simulation (500 runs, 50,000 ECUs)
python -m ota_poc.metrics --runs 500 --fleet-size 50000 --seed 42

# With ablation study
python -m ota_poc.metrics --runs 500 --fleet-size 50000 --seed 42 --ablation
```

## Architecture

```
ota_poc/
├── config.py      # Centralized simulation parameters
├── simulator.py   # Core engine: ECU, EventLog, OTASimulator
└── metrics.py     # Scenario runner, ablation studies, visualization
```

The simulation models three OTA rollout policies against a "Policy-Violating Signing Attack" — where a properly signed but unsafe configuration is pushed to the fleet. Instead of breaking cryptography, it measures how governance controls limit blast radius.

## Understanding the Policies

| Policy | Name | Description |
|--------|------|-------------|
| **P0** | Minimal Governance | Rapid rollout, weak telemetry, no staging |
| **P1** | Secure OTA | Cryptographic verification but no governance controls |
| **P2** | Layered Fleet | Staged 1% canary + transparency monitoring + incident response |

## Running the Simulation

### Full Monte Carlo Run

```bash
python -m ota_poc.metrics --runs 500 --fleet-size 50000 --seed 42
```

This executes up to **500 stochastic iterations** (with adaptive P95 convergence stopping) modeling a fleet of **50,000 ECUs**.

### What This Proves

1. **P0 (Minimal Governance)**: Rapid rollout with weak telemetry detects the incident too slowly. Blast radius compromises ~28,000 endpoints before containment.
2. **P1 (Secure OTA without Governance)**: Cryptography verifies the signature, but since the signed artifact is malicious, vehicles update successfully anyway. Blast radius remains catastrophically high.
3. **P2 (Layered Fleet)**: Staged 1% canary rollout + transparency monitoring + incident response detects the anomaly while limited to the initial cohort. **Median blast radius ~2,112 endpoints**, **P95 worst-case ~6,828 endpoints** — an 86% reduction relative to P1.

## Validating Results

After the script finishes, it generates:

### `simulation_metrics.csv`
Contains all columns from Table III: **Bypass %**, Median TTD, P95 TTD, E[Impact], P95 Impact | Success, **Rollback Safety %**, and **95% CI**.

### Event Log Files
JSON files (e.g., `P2_Layered_Fleet_sample_event_log.json`) with Appendix B compliant schema: `component_id`, `campaign_id`, `metadata_valid`, `artifact_hash_ok`, `install_result`, `boot_result`, `rollback_invoked`, `rollback_result`, `detection_flags` — with ISO-8601 UTC timestamps.

### `blast_radius_cdf.png`
CDF chart with box plot showing three clearly separated curves (P0, P1, P2).

### `ablation_results.csv`
Run with `--ablation` to produce Table IV reproductions:

```bash
python -m ota_poc.metrics --runs 500 --ablation
```

## Alternative Scenarios

Modify the `MALICIOUS_ARTIFACT` constant in `ota_poc/metrics.py`:

```python
MALICIOUS_ARTIFACT = {
    "version": "v1.1_malicious",
    "hash_ok": True,        # Set False to test supply chain path failure
    "metadata_valid": True,
    "unsafe_payload": True,
}
```

- **Supply Chain Path Failure**: Set `"hash_ok": False`. P1 and P2 drop to exactly `0` impact — blocked by cryptography alone.
- **Ablation Studies**: Pass `--ablation` for no staging / no monitoring / slow containment variants.

## Running Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov=ota_poc --cov-report=term-missing
```

Tests cover: healthy update lifecycle, hash-failure blocking (P1/P2), rollback LKG restore, P2 ≤ P0 blast radius ordering, seed reproducibility, convergence detection, CLI input validation, and Appendix B schema compliance.

## Development

### Setup

```bash
# Install with dev dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Or use pip install -e . for editable install
pip install -e ".[dev]"
```

### Code Quality

```bash
ruff check ota_poc/ tests/ scripts/
mypy ota_poc/ scripts/
bandit -r ota_poc/ -ll
```

### Docker

```bash
docker build -t ota-poc .
docker run ota-poc --runs 10 --fleet-size 1000
```

## Paper Citation

```
Omar Alraas and Mohammad Thabet, "Measuring OTA Update-Channel Compromise Risk in Smart
Mobility Ecosystems: A Safe Testbed and Governance to Engineering Controls,"
Canadian University Dubai, 2025.
```

## Future Work

- **Network-Level Adversaries**: Probability models for Wi-Fi/Cellular interception
- **Dynamic Policy Switching**: Upgrade policy (P1 to P2) mid-fleet rollout
- **Hardware-in-the-Loop (HIL)**: Interface with physical CAN bus hardware
- **ECU Heterogeneity**: Different hardware generations and connectivity profiles
- **Cost Model**: Economic impact simulation of different blast radii

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.
