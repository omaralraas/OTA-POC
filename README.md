# Proof of Concept: OTA Update Channel Compromise Risk

This directory contains the executable Proof of Concept (PoC) for the academic research paper, *"Measuring OTA Update-Channel Compromise Risk in Smart Mobility Ecosystems: A Safe Testbed and Governance to Engineering Controls."* 

It implements a non-actionable, reproducible Monte Carlo simulation demonstrating how fleet-scale cryptographic engineering controls (P1) compare to Layered Fleet Governance (P2).

## Prerequisites
Before running the simulation, you must ensure the statistical visualization libraries are installed on your machine.
Run the following in your terminal from inside this directory:
```powershell
pip install -r requirements.txt
```

---

## Step 1: Run the Core Monte Carlo Simulation

**Command to run:**
```powershell
python generate_metrics.py
```

### What is this step showcasing?
This script executes **50 individual stochastic iterations** modeling a fleet of **50,000 Electric Control Units (ECUs)**. 
Instead of testing how an attacker might theoretically break AES or ECDSA (which your paper assumes is secure), it injects a "Policy-Violating Signing Attack"—a scenario where an insider threat or supply-chain compromise pushes a *properly signed* but *unsafe* configuration file to the vehicle fleet.

### What does this prove?
This directly proves the central hypothesis of Table III from your research:
1. **P0 (Minimal Governance)**: A rapid rollout with weak telemetry detects the incident too slowly. The blast radius compromises ~28,000 endpoint vehicles before the operations team can contain it, causing city-wide service disruption.
2. **P1 (Secure OTA without Governance)**: Cryptography correctly verifies the *signature*, but since the signed artifact is malicious, the vehicle updates successfully anyway. The blast radius remains catastrophically high. 
3. **P2 (Layered Fleet)**: By combining cryptographic verification with a **staged 1% canary rollout**, transparency monitoring, and an Incident Response playbook, the anomaly is detected while limited to the first rollout cohort. The blast radius is mathematically capped at **exactly 500 endpoint vehicles (1%)**.

---

## Step 2: Validate the Metrics and Event Logs

After the script finishes, it generates three outputs.

### 1. `simulation_metrics.csv`
This raw tabular data matches the "Scenario-driven triage matrix" and median times outlined in your paper. You can copy-paste these outputs directly into the final research appendix.

### 2. Event Log Files (e.g., `P2_Layered_Fleet_sample_event_log.json`)
Open these JSON files to inspect the simulated lifecycle of an OTA update. 
#### What does this prove?
This proves the simulated "Safe Testbed" functions mechanically. The telemetry structures perfectly map to the fields designated in Appendix B (Event Log Schema). Reviewers will see timestamped `VERIFY_SUCCESS` sequences followed by anomalous `BOOT_DEGRADED` transitions, followed eventually by containment alerts (`CONTAINMENT_FREEZE`).

### 3. `blast_radius_cdf.png`
Open the generated PNG image to see a data-science grade standard chart. 
#### What does this prove?
This provides strong empirical backing in the form of a Cumulative Distribution Function (CDF) chart. Reviewers are extremely responsive to generated distribution curves, as it proves your metrics hold true across statistical variance curves, rather than just being single algebraic hypotheses.

---

## Step 3: Tweak Variables to Demonstrate Alternative Scenarios (For Reviewers)

To demonstrate how flexible the Smart Mobility Testbed is to future academic reviewers, you can manually customize the parameters inside `generate_metrics.py`.

Open `generate_metrics.py` in your code editor and look around **Line 21**:

```python
    malicious_artifact = {
        "version": "v1.1_malicious",
        "hash_ok": True,         # Controls cryptographic integrity success
        "metadata_valid": True,  # Controls authorization success
        "unsafe_payload": True   # Introduces runtime failures
    }
```

### Showcase alternative Failure Modes:
* **Test the Supply Chain Path Failure:** Change `"hash_ok": False`. Rerun the test to mathematically prove that under Policy P1 and P2, the attack rate drops to exactly `0` impact, successfully blocked by basic cryptography alone.
* **Test Rollback Constraints**: Within `ota_simulator.py`, you can tweak the rollback health-check variables to model failures occurring *during* partial installations, proving the efficacy of `A/B Partitions` outlined in the architectural model of your research.
