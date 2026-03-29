import pandas as pd
from ota_simulator import OTASimulator
import json
import os
import matplotlib.pyplot as plt

def run_scenarios(fleet_size=50000, runs=30):
    policies = ['P0_Minimal', 'P1_Secure_OTA', 'P2_Layered_Fleet']
    results = []
    
    # ----------------------------------------------------
    # Safe PoC Failure Mode: "Policy-violating signing" 
    # Mocks a mathematically successful bypass of hashes
    # but introduces runtime degradation (unsafe payload)
    # ----------------------------------------------------
    malicious_artifact = {
        "version": "v1.1_malicious",
        "hash_ok": True,         # Crypto controls bypassed/intact
        "metadata_valid": True,  # Authorized keys used (Key Control Threat)
        "unsafe_payload": True   # Introduces fleet-wide degradation
    }
    
    print(f"Running Monte Carlo Simulation (Fleet Size: {fleet_size}, {runs} iterations per policy)...")
    
    plt.figure(figsize=(10, 6))
    
    for policy in policies:
        print(f"\nSimulating {policy}...")
        ttds = []
        impacts = []
        
        from tqdm import tqdm
        for i in tqdm(range(runs), desc=f"{policy} Progress"):
            sim = OTASimulator(fleet_size=fleet_size, policy=policy)
            stats = sim.run_simulation(malicious_artifact, max_hours=144)
            ttds.append(stats['ttd_hours'])
            impacts.append(stats['impacted_endpoints'])
            
            # Just grab the event log of the first run as a sample for our datasets
            if i == 0:
                with open(f"{policy}_sample_event_log.json", "w") as f:
                    json.dump(sim.event_log.logs, f, indent=2)
            
        # Calculate statistics
        median_ttd = pd.Series(ttds).median()
        p95_ttd = pd.Series(ttds).quantile(0.95)
        expected_impact = pd.Series(impacts).mean()
        p95_impact = pd.Series(impacts).quantile(0.95)
        
        results.append({
            "Policy": policy,
            "Median TTD (h)": median_ttd,
            "P95 TTD (h)": p95_ttd,
            "E[Impact]": expected_impact,
            "P95 Impact | Success": p95_impact
        })
        
        # Plot CDF logic
        plt.hist(impacts, density=True, cumulative=True, label=policy, histtype='step', alpha=0.9, linewidth=2, bins=30)
        
    df = pd.DataFrame(results)
    print("\n--- Simulation Results (Aligns with Table III of Research) ---")
    print(df.to_string(index=False))
    
    # Finalize and Save CDF Chart
    plt.legend(loc='lower right')
    plt.xlabel('Number of Compromised Endpoints (Blast Radius)')
    plt.ylabel('Cumulative Distribution (CDF)')
    plt.title('Blast Radius by OTA Rolllout Policy (Monte Carlo Sim)')
    plt.grid(True, linestyle='--', alpha=0.7)
    
    chart_path = 'blast_radius_cdf.png'
    plt.savefig(chart_path, dpi=300)
    print(f"\nSaved CDF chart to '{chart_path}'")
    
    # Save Metrics CSV
    csv_path = 'simulation_metrics.csv'
    df.to_csv(csv_path, index=False)
    print(f"Saved metric results to '{csv_path}'")

if __name__ == "__main__":
    # 50,000 endpoint representation, 50 runs to create smooth distribution curves
    run_scenarios(fleet_size=50000, runs=50)
