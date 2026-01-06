# OWASP Agentic AI Top 10 Scanner

[![Lint](https://github.com/NP-compete/owasp-agentic-ai-security-scanner/actions/workflows/lint.yml/badge.svg)](https://github.com/NP-compete/owasp-agentic-ai-security-scanner/actions/workflows/lint.yml)
[![Test](https://github.com/NP-compete/owasp-agentic-ai-security-scanner/actions/workflows/test.yml/badge.svg)](https://github.com/NP-compete/owasp-agentic-ai-security-scanner/actions/workflows/test.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Static analysis tool for detecting security risks from the **OWASP Top 10 for Agentic AI Applications** (December 2025).

## Quick Start

```bash
# Install
git clone https://github.com/NP-compete/owasp-agentic-ai-security-scanner.git
cd owasp-agentic-ai-security-scanner
uv sync

# Scan
owasp-scan scan /path/to/agent

# SARIF for CI/CD
owasp-scan scan src --format sarif --output results.sarif
```

## OWASP Agentic AI Top 10

| ID | Risk |
|----|------|
| AA01 | Agent Goal Hijack |
| AA02 | Tool Misuse & Exploitation |
| AA03 | Identity & Privilege Abuse |
| AA04 | Agentic Supply Chain |
| AA05 | Unexpected Code Execution |
| AA06 | Memory Poisoning |
| AA07 | Excessive Agency |
| AA08 | Insecure Plugin Design |
| AA09 | Overreliance on Outputs |
| AA10 | Model Theft |

## Usage

```bash
# Filter by rules
owasp-scan scan src --rules goal_hijack,code_execution

# Filter by severity
owasp-scan scan src --min-severity high

# JSON output
owasp-scan scan src --format json --output results.json

# List rules
owasp-scan list-rules
```

## Inline Suppression

```python
eval(expression)  # noqa: AA05
```

## CI/CD Integration

### GitHub Actions

```yaml
- run: owasp-scan scan src --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

## Development

```bash
make install-dev  # Setup
make pre-commit   # Run all checks
make test         # Run tests
```

## References

- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP GenAI Security Project](https://genai.owasp.org/)

## License

Apache License 2.0
