# Contributing to OTA-POC

This repository is the PoC testbed for an academic research paper:
> *"Measuring OTA Update-Channel Compromise Risk in Smart Mobility Ecosystems:
> A Safe Testbed and Governance to Engineering Controls."*

Contributions that improve simulation fidelity, reproducibility, or documentation are welcome.

## How to Contribute

1. Fork the repository and create a feature branch from `main`.
2. Set up a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```
3. Make your changes with clear commit messages following the format used in this repo.
4. Run the quality checks:
   ```bash
   ruff check ota_poc/ tests/ scripts/
   mypy ota_poc/ scripts/
   pytest tests/ -v --cov=ota_poc --cov-fail-under=90
   ```
5. Run a smoke simulation to confirm no regressions:
   ```bash
   python -m ota_poc.metrics --runs 10 --fleet-size 1000
   ```
6. Open a pull request describing what you changed and why.

## Code Standards

- All simulation logic must remain **non-actionable**: no real credentials, no production
  firmware, no live attack techniques.
- The `unsafe_payload` flag is the **only** mechanism for simulating compromise — do not
  implement actual exploit code.
- New parameters should be added to `ota_poc/config.py` with rationale in comments.
- Maintain the Appendix B event log schema for all new event types.
- Use `self.rng` (the instance-level `random.Random`) — never the global `random` module
  inside simulator classes.
- All new functions must have type hints and docstrings.
- Minimum test coverage: **90%**.

## Running Quality Checks

```bash
# Linting
ruff check ota_poc/ tests/ scripts/

# Type checking
mypy ota_poc/ scripts/

# Security scanning
bandit -r ota_poc/ -ll

# Tests with coverage
pytest tests/ -v --cov=ota_poc --cov-report=term-missing --cov-fail-under=90
```

## Commit Message Format

Follow the [Conventional Commits](https://www.conventionalcommits.org/) style used throughout:

```
<type>(<scope>): <short description>

<body — optional>

Author: GitHubUsername <email>
```

Types: `fix`, `feat`, `docs`, `test`, `refactor`, `ci`.

## Project Structure

```
ota_poc/
├── config.py      # All simulation parameters (add new constants here)
├── simulator.py   # Core engine: ECU, EventLog, OTASimulator
└── metrics.py     # Scenario runner, ablation studies, visualization
tests/
├── test_simulator.py  # ECU and simulator tests
├── test_ablation.py   # Ablation study tests
└── test_metrics.py    # Metrics module and CLI tests
```

## Authors

- **Omar Alraas** ([@omaralraas](https://github.com/omaralraas)) — repo owner,
  metrics, documentation, CI
- **Mohammad Thabet** ([@MohammadThabetHassan](https://github.com/MohammadThabetHassan)) —
  simulation engine, statistical testing

## License

MIT — see the [LICENSE](LICENSE) file.
