"""Backward-compatible shim: `python generate_metrics.py` still works."""

from ota_poc.metrics import main

if __name__ == "__main__":
    main()
