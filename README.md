# OWASP Agentic AI Top 10 Scanner

[![CI](https://github.com/NP-compete/owasp-agentic-ai-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/NP-compete/owasp-agentic-ai-security-scanner/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A static analysis tool that scans codebases for security risks defined in the **OWASP Top 10 for Agentic AI Applications** (December 2025).

## Features

- **10 Detection Rules** covering all OWASP Agentic AI risks
- **85+ Detection Patterns** for comprehensive scanning
- **Multiple Output Formats**: Console (rich), JSON, SARIF
- **Parallel Scanning** for performance
- **Inline Suppression** via `# noqa: AA01` comments
- **CI/CD Integration** with SARIF output for GitHub Code Scanning
- **Severity Filtering** to focus on critical issues

## OWASP Agentic AI Top 10

| ID | Risk | Description |
|----|------|-------------|
| AA01 | Agent Goal Hijack | Attackers manipulate agent objectives |
| AA02 | Tool Misuse & Exploitation | Agent tricked into misusing tools |
| AA03 | Identity & Privilege Abuse | Compromised credentials or excessive permissions |
| AA04 | Agentic Supply Chain | Malicious tools, models, or agent personas |
| AA05 | Unexpected Code Execution | Agent generates or executes attacker-controlled code |
| AA06 | Memory Poisoning | Malicious data injected into agent memory |
| AA07 | Excessive Agency | Agent operates without adequate oversight |
| AA08 | Insecure Plugin Design | Vulnerabilities in plugins/extensions |
| AA09 | Overreliance on Outputs | Blind trust in agent outputs |
| AA10 | Model Theft | Unauthorized access to proprietary models |

## Installation

### Using uv (recommended)

```bash
git clone https://github.com/NP-compete/owasp-agentic-ai-security-scanner.git
cd owasp-agentic-ai-security-scanner
uv sync
```

### Using pip

```bash
pip install owasp-agentic-scanner
```

## Quick Start

```bash
# Scan a directory
owasp-scan scan /path/to/your/agent

# Scan with specific rules
owasp-scan scan /path/to/code --rules goal_hijack,code_execution

# Generate SARIF for CI/CD
owasp-scan scan /path/to/code --format sarif --output results.sarif
```

## Usage

### Basic Scanning

```bash
# Scan a directory
owasp-scan scan /path/to/codebase

# Scan a single file
owasp-scan scan /path/to/file.py

# Verbose output with recommendations
owasp-scan scan /path/to/code --verbose
```

### Output Formats

```bash
# Console output (default) - rich formatting
owasp-scan scan /path/to/code

# JSON output
owasp-scan scan /path/to/code --format json

# SARIF output (for CI/CD integration)
owasp-scan scan /path/to/code --format sarif

# Write to file
owasp-scan scan /path/to/code --format json --output results.json
owasp-scan scan /path/to/code --format sarif --output results.sarif
```

### Filtering

```bash
# By rule short name
owasp-scan scan /path/to/code --rules goal_hijack,tool_misuse

# By rule ID
owasp-scan scan /path/to/code --rules AA01,AA02,AA05

# By minimum severity
owasp-scan scan /path/to/code --min-severity high  # Only high and critical
owasp-scan scan /path/to/code --min-severity critical  # Only critical
```

### Performance Options

```bash
# Parallel scanning (default: enabled with 4 workers)
owasp-scan scan /path/to/code --workers 8

# Disable parallel scanning
owasp-scan scan /path/to/code --no-parallel
```

### List Available Rules

```bash
owasp-scan list-rules
```

## Inline Suppression

Suppress specific findings with inline comments:

```python
# Suppress a single rule
eval(expression)  # noqa: AA05

# Suppress multiple rules
dangerous_code()  # noqa: AA01, AA05

# Suppress all rules on this line
risky_operation()  # noqa: ALL
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run OWASP Agentic Scanner
  run: |
    pip install owasp-agentic-scanner
    owasp-scan scan src --format sarif --output results.sarif

- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  image: python:3.12
  script:
    - pip install owasp-agentic-scanner
    - owasp-scan scan src --format json --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Development

### Setup

```bash
git clone https://github.com/NP-compete/owasp-agentic-ai-security-scanner.git
cd owasp-agentic-ai-security-scanner
make install-dev
```

### Commands

```bash
make lint        # Run ruff linter
make format      # Format code
make type-check  # Run mypy
make test        # Run tests
make test-cov    # Run tests with coverage
make pre-commit  # Run all checks
```

### Running Tests

```bash
# All tests
make test

# With coverage
make test-cov

# Specific test file
uv run pytest tests/unit/test_rules.py -v
```

## Rule Reference

| Short Name | ID | Patterns |
|------------|-----|----------|
| `goal_hijack` | AA01 | 8 |
| `tool_misuse` | AA02 | 8 |
| `privilege_abuse` | AA03 | 8 |
| `supply_chain` | AA04 | 9 |
| `code_execution` | AA05 | 9 |
| `memory_poisoning` | AA06 | 8 |
| `excessive_agency` | AA07 | 9 |
| `insecure_plugin` | AA08 | 9 |
| `overreliance` | AA09 | 8 |
| `model_theft` | AA10 | 9 |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical or high severity findings |
| 1 | Critical or high severity findings detected |

## Extending with Custom Rules

Create a new rule in `src/owasp_agentic_scanner/rules/`:

```python
from owasp_agentic_scanner.rules.base import (
    BaseRule,
    DetectionPattern,
    Severity,
    pattern,
)


class CustomRule(BaseRule):
    rule_id = "CUSTOM01"
    rule_name = "Custom Security Check"
    owasp_category = "Custom"
    description = "Detects custom security patterns"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"dangerous_function\s*\("),
                message="Dangerous function call detected",
                recommendation="Use safe_function() instead.",
                severity=Severity.HIGH,
                confidence="high",
            ),
        ]
```

## References

- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Agentic AI - Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP GenAI Security Project](https://genai.owasp.org/)
- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

## License

Apache License 2.0

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
