"""Assert that README.md P2 numbers match simulation_metrics.csv within ±5%."""

import csv
import re
import sys


def main() -> None:
    """Validate README P2 numbers against committed CSV."""
    with open("simulation_metrics.csv", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = {row["Policy"]: row for row in reader}

    p2 = rows.get("P2_Layered_Fleet")
    if not p2:
        print("Error: P2_Layered_Fleet not found in simulation_metrics.csv", file=sys.stderr)
        sys.exit(1)

    csv_e_impact = float(p2["E[Impact]"])
    csv_p95_impact = float(p2["P95 Impact | Success"])

    with open("README.md", encoding="utf-8") as f:
        readme = f.read()

    median_match = re.search(r"Median blast radius ~([\d,]+)", readme)
    p95_match = re.search(r"P95 worst-case ~([\d,]+)", readme)

    if not median_match or not p95_match:
        print(
            "Error: Could not find P2 numbers in README.md. "
            "Expected 'Median blast radius ~X' and 'P95 worst-case ~Y'.",
            file=sys.stderr,
        )
        sys.exit(1)

    readme_median = int(median_match.group(1).replace(",", ""))
    readme_p95 = int(p95_match.group(1).replace(",", ""))

    tolerance = 0.05
    median_ok = abs(readme_median - csv_e_impact) / csv_e_impact <= tolerance
    p95_ok = abs(readme_p95 - csv_p95_impact) / csv_p95_impact <= tolerance

    errors = []
    if not median_ok:
        errors.append(
            f"README P2 median ({readme_median}) != CSV E[Impact] ({csv_e_impact:.0f})"
        )
    if not p95_ok:
        errors.append(
            f"README P2 P95 ({readme_p95}) != CSV P95 Impact ({csv_p95_impact:.0f})"
        )

    if errors:
        print("Error: README numbers do not match CSV within ±5%:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    print("README numbers match simulation_metrics.csv within ±5%.")


if __name__ == "__main__":
    main()
