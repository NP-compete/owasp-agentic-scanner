# Usage Guide

## Basic Scanning

```bash
# Scan a directory
owasp-scan scan src/

# Scan with specific rules
owasp-scan scan src --rules goal_hijack,code_execution

# Filter by severity
owasp-scan scan src --min-severity high

# List all available rules
owasp-scan list-rules
```

## Output Formats

```bash
# Console output (default)
owasp-scan scan src

# JSON output
owasp-scan scan src --format json --output results.json

# SARIF output (for GitHub Code Scanning)
owasp-scan scan src --format sarif --output results.sarif
```

## Advanced Features

```bash
# Parallel scanning (faster for large codebases)
owasp-scan scan src --parallel --workers 8

# Incremental scanning with cache
owasp-scan scan src --cache --cache-dir .owasp-cache

# Scan only git-changed Modify
owasp-scan scan src --git-diff main

# Use baseline to track known issues
owasp-scan scan src --baseline .owasp-baseline.json
```

## Inline Suppression

Suppress specific findings in your code:

```python
# Suppress a specific rule
eval(expression)  # noqa: AA05

# Suppress all rules on a line
exec(code)  # noqa: owasp-scan

# Suppress multiple rules
dangerous_call()  # noqa: AA02,AA05
```

## Pre-commit Hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/NP-compete/owasp-agentic-scanner
    rev: v0.1.0
    hooks:
      - id: owasp-agentic-scan
        args: [--min-severity, high]
```
