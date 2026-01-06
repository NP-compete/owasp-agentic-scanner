# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Comprehensive pre-commit hooks (bandit, gitleaks, ruff, mypy)
- Split CI workflows (lint, type-check, test, security)
- SARIF output for GitHub Code Scanning
- Inline suppression via `# noqa: AA01` comments
- Parallel scanning support

### Changed
- Streamlined README documentation

## [0.1.0] - 2025-01-06

### Added
- Initial release
- 10 detection rules covering OWASP Agentic AI Top 10
- 85+ detection patterns
- Console, JSON, and SARIF output formats
- CLI with typer and rich
- Rule filtering by name, ID, and severity
- Unit tests with 85%+ coverage
