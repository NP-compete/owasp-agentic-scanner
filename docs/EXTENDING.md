# Extending the Scanner

Guide to adding custom detection rules.

## Creating a Custom Rule

### 1. Create the Rule File

Create `src/owasp_agentic_scanner/rules/your_rule.py`:

```python
from owasp_agentic_scanner.rules.base import (
    BaseRule,
    DetectionPattern,
    Severity,
    pattern,
)


class YourRule(BaseRule):
    rule_id = "CUSTOM01"
    rule_name = "Your Rule Name"
    owasp_category = "Custom Category"
    description = "What this rule detects"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"dangerous_function\s*\("),
                message="Dangerous function call detected",
                recommendation="Use safe_function() instead.",
                severity=Severity.HIGH,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"risky_pattern"),
                message="Risky pattern found",
                recommendation="Consider alternative approach.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
        ]
```

### 2. Register the Rule

Add to `src/owasp_agentic_scanner/rules/__init__.py`:

```python
from owasp_agentic_scanner.rules.your_rule import YourRule

ALL_RULES: list[type[BaseRule]] = [
    # ... existing rules ...
    YourRule,
]
```

### 3. Add Tests

Add to `tests/unit/test_rules.py`:

```python
def test_your_rule_detects_dangerous_function():
    rule = YourRule()
    code = "result = dangerous_function(user_input)"
    findings = rule.scan_content(code, "test.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "CUSTOM01"
```

## Pattern Writing Tips

### Use `pattern()` helper

```python
from owasp_agentic_scanner.rules.base import pattern

# Creates case-insensitive compiled regex
p = pattern(r"eval\s*\(")
```

### Severity Levels

| Level | Use Case |
|-------|----------|
| `CRITICAL` | Immediate security risk |
| `HIGH` | Serious vulnerability |
| `MEDIUM` | Potential issue |
| `LOW` | Minor concern |
| `INFO` | Informational |

### Confidence Levels

| Level | Meaning |
|-------|---------|
| `high` | Very likely a real issue |
| `medium` | Probably an issue, needs review |
| `low` | Might be a false positive |

## File Type Filtering

Override `file_extensions` to limit scanning:

```python
class YourRule(BaseRule):
    file_extensions = [".py", ".js"]  # Only scan these
```

## Testing Your Rule

```bash
# Run specific test
uv run pytest tests/unit/test_rules.py::test_your_rule -v

# Test against real code
uv run owasp-scan scan /path/to/code --rules CUSTOM01
```
