"""Assert that README.md numbers match committed CSVs within ±5%."""

import csv
import re
import sys


def main() -> None:
    """Validate README P2 and ablation numbers against committed CSVs."""
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
    errors = []

    if abs(readme_median - csv_e_impact) / csv_e_impact > tolerance:
        errors.append(
            f"README P2 median ({readme_median}) != CSV E[Impact] ({csv_e_impact:.0f})"
        )
    if abs(readme_p95 - csv_p95_impact) / csv_p95_impact > tolerance:
        errors.append(
            f"README P2 P95 ({readme_p95}) != CSV P95 Impact ({csv_p95_impact:.0f})"
        )

    # --- Validate ablation table ---
    with open("ablation_results.csv", newline="", encoding="utf-8") as f:
        abl_rows = {row["Ablation"]: row for row in csv.DictReader(f)}

    ablation_checks = [
        ("No Staging", "No Staging"),
        ("No Transparency Monitor", "No Transparency Monitor"),
        ("Slow Containment (12h)", "Slow Containment (12h)"),
    ]

    for readme_label, csv_key in ablation_checks:
        csv_row = abl_rows.get(csv_key)
        if not csv_row:
            print(f"Error: '{csv_key}' not found in ablation_results.csv", file=sys.stderr)
            sys.exit(1)
        csv_impact = float(csv_row["E[Impact] (50k)"])
        pattern = rf"\|\s*{re.escape(readme_label)}\s*\|[^|]+\|[^|]+\|\s*([\d,]+)"
        match = re.search(pattern, readme)
        if not match:
            print(
                f"Error: Could not find '{readme_label}' row in README ablation table",
                file=sys.stderr,
            )
            sys.exit(1)
        readme_impact = int(match.group(1).replace(",", ""))
        if abs(readme_impact - csv_impact) / max(csv_impact, 1) > tolerance:
            errors.append(
                f"README ablation '{readme_label}' E[Impact] ({readme_impact}) "
                f"!= CSV ({csv_impact:.0f})"
            )

    if errors:
        print("Error: README numbers do not match CSVs within ±5%:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    print("README numbers match committed CSVs within ±5%.")


if __name__ == "__main__":
    main()
