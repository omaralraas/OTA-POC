# Contributing to OTA-POC

This repository is the PoC testbed for an academic research paper:
> *"Measuring OTA Update-Channel Compromise Risk in Smart Mobility Ecosystems:
> A Safe Testbed and Governance to Engineering Controls."*

Contributions that improve simulation fidelity, reproducibility, or documentation are welcome.

## How to Contribute

1. Fork the repository and create a feature branch from `main`.
2. Make your changes with clear commit messages following the format used in this repo.
3. Run the test suite:
   ```bash
   pytest tests/ -v
   ```
4. Run a smoke simulation to confirm no regressions:
   ```bash
   python generate_metrics.py --runs 10 --fleet-size 1000
   ```
5. Open a pull request describing what you changed and why.

## Code Standards

- All simulation logic must remain **non-actionable**: no real credentials, no production
  firmware, no live attack techniques.
- The `unsafe_payload` flag is the **only** mechanism for simulating compromise — do not
  implement actual exploit code.
- New parameters should be documented with rationale in comments.
- Maintain the Appendix B event log schema for all new event types.
- Use `self.rng` (the instance-level `random.Random`) — never the global `random` module
  inside simulator classes.

## Commit Message Format

Follow the [Conventional Commits](https://www.conventionalcommits.org/) style used throughout:

```
<type>(<scope>): <short description>

<body — optional>

Author: GitHubUsername <email>
```

Types: `fix`, `feat`, `docs`, `test`, `refactor`, `ci`.

## Authors

- **Omar Alraas** ([@omaralraas](https://github.com/omaralraas)) — repo owner,
  metrics, documentation, CI
- **Mohammad Thabet** ([@MohammadThabetHassan](https://github.com/MohammadThabetHassan)) —
  simulation engine, statistical testing

## License

MIT — see the [LICENSE](LICENSE) file.
