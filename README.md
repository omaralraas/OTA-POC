# Proof of Concept: OTA Update Channel Compromise Risk

[![CI](https://github.com/omaralraas/OTA-POC/actions/workflows/ci.yml/badge.svg)](https://github.com/omaralraas/OTA-POC/actions/workflows/ci.yml)

This directory contains the executable Proof of Concept (PoC) for the academic research paper:

> *"Measuring OTA Update-Channel Compromise Risk in Smart Mobility Ecosystems:
> A Safe Testbed and Governance to Engineering Controls."*
> **Omar Alraas & Mohammad Thabet** — Canadian University Dubai, 2025.

It implements a non-actionable, reproducible Monte Carlo simulation demonstrating how fleet-scale cryptographic engineering controls (P1) compare to Layered Fleet Governance (P2).

## Prerequisites
Before running the simulation, ensure the statistical visualization libraries are installed:
```powershell
pip install -r requirements.txt
```

---

## Step 1: Run the Core Monte Carlo Simulation

**Command to run:**
```powershell
python generate_metrics.py --runs 500 --fleet-size 50000 --seed 42
```

For a quick smoke test:
```powershell
python generate_metrics.py --runs 10 --fleet-size 1000
```

### What is this step showcasing?
This script executes up to **500 stochastic iterations** (with adaptive P95 convergence stopping)
modeling a fleet of **50,000 Electric Control Units (ECUs)**.
Instead of testing how an attacker might theoretically break AES or ECDSA (which the paper assumes
is secure), it injects a "Policy-Violating Signing Attack" — a scenario where an insider threat or
supply-chain compromise pushes a *properly signed* but *unsafe* configuration file to the fleet.

### What does this prove?
This directly proves the central hypothesis of Table III from the research:
1. **P0 (Minimal Governance)**: A rapid rollout with weak telemetry detects the incident too
   slowly. The blast radius compromises ~28,000 endpoint vehicles before containment.
2. **P1 (Secure OTA without Governance)**: Cryptography correctly verifies the *signature*, but
   since the signed artifact is malicious, the vehicle updates successfully anyway. The blast radius
   remains catastrophically high.
3. **P2 (Layered Fleet)**: By combining cryptographic verification with a **staged 1% canary
   rollout**, transparency monitoring, and an Incident Response playbook, the anomaly is detected
   while limited to the initial rollout cohort. In Monte Carlo results (50,000-ECU fleet,
   500 iterations), the **median blast radius is ~2,112 endpoints** and the
   **P95 worst-case is ~6,828 endpoints** — an 86% reduction relative to P1's worst-case under
   the same compromise scenario. The 1% staging gate is the primary constraint; detection speed
   and containment time determine the remainder. See `simulation_metrics.csv` and
   `blast_radius_cdf.png` for the full distribution.

---

## Step 2: Validate the Metrics and Event Logs

After the script finishes, it generates the following outputs.

### 1. `simulation_metrics.csv`
Contains all columns from Table III: **Bypass %**, Median TTD, P95 TTD, E[Impact],
P95 Impact | Success, **Rollback Safety %**. Copy-paste directly into the research appendix.

### 2. Event Log Files (e.g., `P2_Layered_Fleet_sample_event_log.json`)
Open these JSON files to inspect the simulated lifecycle of an OTA update.
The telemetry structures map to all fields in Appendix B (Event Log Schema): `component_id`,
`campaign_id`, `metadata_valid`, `artifact_hash_ok`, `install_result`, `boot_result`,
`rollback_invoked`, `rollback_result`, `detection_flags` — with ISO-8601 UTC timestamps.

### 3. `blast_radius_cdf.png`
A data-science-grade CDF chart showing three clearly separated curves (P0, P1, P2),
providing empirical backing that metrics hold true across statistical variance, not just
single algebraic hypotheses.

### 4. `ablation_results.csv` (optional)
Run with `--ablation` to also produce Table IV reproductions:
```powershell
python generate_metrics.py --runs 500 --ablation
```

---

## Step 3: Tweak Variables to Demonstrate Alternative Scenarios (For Reviewers)

Open `generate_metrics.py` in your code editor and locate the `malicious_artifact` dict
(around **line 55**):

```python
malicious_artifact = {
    "version":        "v1.1_malicious",
    "hash_ok":        True,   # Crypto controls bypassed/intact
    "metadata_valid": True,   # Authorised keys used (Key Control Threat)
    "unsafe_payload": True,   # Introduces fleet-wide degradation
}
```

### Showcase alternative Failure Modes:
* **Supply Chain Path Failure**: Set `"hash_ok": False`. P1 and P2 drop to exactly `0` impact —
  blocked by cryptography alone.
* **Rollback Constraints**: In `ota_simulator.py` the `ECU.rollback()` method restores to
  `last_known_good_version`, dynamically tracked per ECU, modelling the A/B partition safety
  mechanism described in the paper.
* **Ablation Studies**: Pass `--ablation` to reproduce Table IV (no staging / no monitoring /
  slow containment variants).

---

## Running Tests

```powershell
pytest tests/ -v
```

Tests cover: healthy update lifecycle, hash-failure blocking (P1/P2), rollback LKG restore,
P2 ≤ P0 blast radius ordering, seed reproducibility, and Appendix B schema compliance.

---

## Paper Citation

```
Omar Alraas and Mohammad Thabet, "Measuring OTA Update-Channel Compromise Risk in Smart
Mobility Ecosystems: A Safe Testbed and Governance to Engineering Controls,"
Canadian University Dubai, 2025.
```

---

## Future Work & Extensibility

This Proof of Concept currently implements a static policy-violating signing scenario. Future enhancements to the testbed may include:

- **Network-Level Adversaries**: Incorporating probability models for Wi-Fi/Cellular interception prior to the OTA gateway.
- **Dynamic Policy Switching**: Allowing the simulator to upgrade its policy (e.g., P1 to P2) mid-fleet rollout.
- **Hardware-in-the-Loop (HIL) Integration**: Migrating the `ECU` class to interface with physical CAN bus hardware for hybrid simulations.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.
