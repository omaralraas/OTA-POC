"""Assert that simulation output CSVs contain required columns."""

import sys

import pandas as pd


def main() -> None:
    """Validate simulation_metrics.csv and ablation_results.csv."""
    df = pd.read_csv("simulation_metrics.csv")
    required = {
        "Policy",
        "Bypass %",
        "Median TTD (h)",
        "P95 TTD (h)",
        "E[Impact]",
        "P95 Impact | Success",
        "Rollback Safety %",
    }
    missing = required - set(df.columns)
    if missing:
        print(f"Missing columns in simulation_metrics.csv: {missing}", file=sys.stderr)
        sys.exit(1)
    print("simulation_metrics.csv OK")

    abl = pd.read_csv("ablation_results.csv")
    print("ablation_results.csv OK")


if __name__ == "__main__":
    main()
