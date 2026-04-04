# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

This repository contains a **non-actionable** academic research PoC. It does not include:
- Real credentials or production firmware
- Live attack techniques or exploit code
- Network-level adversary simulations

The `unsafe_payload` flag is the only mechanism for simulating compromise.

If you discover a security concern related to the research methodology or simulation assumptions, please:

1. **Do not** open a public issue for sensitive matters
2. Email the authors directly (see [README.md](README.md) for contact information)
3. Allow up to 14 days for a response

## Research Ethics

This PoC is designed as a safe testbed for academic research. All simulation logic is:
- **Non-actionable**: No real-world attack vectors are implemented
- **Reproducible**: Seeded RNG ensures deterministic results
- **Transparent**: All parameters are documented in `ota_poc/config.py`
