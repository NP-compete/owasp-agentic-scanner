# Pre-commit Integration

Use the OWASP Agentic AI Scanner as a pre-commit hook to catch security issues before they're committed.

## Option 1: As a Pre-commit Hook (Recommended)

Add directly to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/NP-compete/owasp-agentic-ai-security-scanner
    rev: v0.1.0  # Use latest release tag
    hooks:
      - id: owasp-agentic-scan
```

### With Options

```yaml
repos:
  - repo: https://github.com/NP-compete/owasp-agentic-ai-security-scanner
    rev: v0.1.0
    hooks:
      - id: owasp-agentic-scan
        args: [--min-severity, high]  # Only high/critical
```

```yaml
repos:
  - repo: https://github.com/NP-compete/owasp-agentic-ai-security-scanner
    rev: v0.1.0
    hooks:
      - id: owasp-agentic-scan
        args: [--rules, goal_hijack,code_execution]  # Specific rules
```

## Option 2: As a Local Hook

If you prefer to install the scanner in your project:

```bash
pip install owasp-agentic-scanner
# or
uv add owasp-agentic-scanner
```

Then add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: owasp-agentic-scan
        name: OWASP Agentic AI Scanner
        entry: owasp-scan scan src
        language: system
        pass_filenames: false
        always_run: true
```

### Customized Local Hook

```yaml
repos:
  - repo: local
    hooks:
      - id: owasp-agentic-scan
        name: OWASP Agentic AI Scanner
        entry: owasp-scan scan src --min-severity high --rules goal_hijack,code_execution
        language: system
        pass_filenames: false
        always_run: true
        stages: [pre-commit]
```

## Available Arguments

| Argument | Description |
|----------|-------------|
| `--min-severity` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `--rules` | Comma-separated rule names or IDs (e.g., `goal_hijack,AA02`) |
| `--format` | Output format: `console`, `json`, `sarif` |
| `-v, --verbose` | Show detailed findings |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical/high findings (pass) |
| 1 | Critical/high findings detected (fail) |

## Recommended Setup

For most projects, use `--min-severity high` to focus on critical issues:

```yaml
repos:
  - repo: https://github.com/NP-compete/owasp-agentic-ai-security-scanner
    rev: v0.1.0
    hooks:
      - id: owasp-agentic-scan
        args: [--min-severity, high]
```

## Suppressing False Positives

Use inline comments to suppress specific findings:

```python
# Suppress a single rule
eval(expression)  # noqa: AA05

# Suppress multiple rules
dangerous_code()  # noqa: AA01, AA05
```
