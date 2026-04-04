"""Backward-compatible shim: `python generate_metrics.py` still works."""

from ota_poc.metrics import main, run_ablations, run_scenarios

if __name__ == "__main__":
    main()
