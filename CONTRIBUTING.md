# Contributing to OWASP Agentic AI Scanner

Thank you for your interest in contributing!

## Getting Started

```bash
git clone https://github.com/NP-compete/owasp-agentic-ai-security-scanner.git
cd owasp-agentic-ai-security-scanner
make install-dev
```

## Development Workflow

1. Create a branch from `main`
2. Make your changes
3. Run checks: `make pre-commit`
4. Submit a PR

## Code Standards

- Python 3.11+
- Type hints required
- Ruff for linting/formatting
- 85% test coverage minimum

## Adding a New Rule

1. Create `src/owasp_agentic_scanner/rules/your_rule.py`
2. Inherit from `BaseRule`
3. Define patterns in `_get_patterns()`
4. Add tests in `tests/unit/test_rules.py`
5. Register in `rules/__init__.py`

```python
from owasp_agentic_scanner.rules.base import BaseRule, DetectionPattern, Severity, pattern

class YourRule(BaseRule):
    rule_id = "AA99"
    rule_name = "Your Rule Name"
    owasp_category = "Category"
    description = "What this rule detects"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"your_regex"),
                message="Finding message",
                recommendation="How to fix",
                severity=Severity.HIGH,
                confidence="high",
            ),
        ]
```

## PR Requirements

- [ ] All checks pass (`make pre-commit`)
- [ ] Tests added for new features
- [ ] Documentation updated if needed

## Questions?

Open an issue or discussion.
