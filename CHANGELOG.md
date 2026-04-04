# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-04

### Added
- Monte Carlo simulation engine with three OTA rollout policies (P0, P1, P2)
- Appendix B compliant event log schema
- Ablation study framework (Table IV reproduction)
- CDF visualization for blast radius comparison
- Box plot visualization for policy comparison
- 95% confidence intervals for impact metrics
- Input validation for CLI arguments
- Backward-compatible shims for legacy imports
- Dockerfile for reproducible environments
- Comprehensive test suite (40 tests, 90%+ coverage)
- CI/CD pipeline with linting, type checking, and security scanning

### Changed
- Refactored simulation engine with incremental tracking (O(1) per hour)
- Extracted all magic numbers to centralized config module
- Added full type hints and docstrings across all modules
- Fixed `datetime.utcnow()` deprecation (Python 3.12+ compatible)
- Fixed `details.pop()` mutation bug in EventLog
- Added rollback safety % to ablation CSV output
- Improved rollout fairness with `round()` instead of `int()` truncation

### Fixed
- 177K deprecation warnings from `datetime.utcnow()`
- Inconsistent ablation CSV (missing Rollback Safety % column)
- Unused imports (`uuid`, `os`)
- Dict mutation side effect in `EventLog.log()`
