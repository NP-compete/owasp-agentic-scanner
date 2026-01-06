# OWASP Agentic AI Top 10 Scanner

A static analysis tool that scans codebases for security risks defined in the **OWASP Top 10 for Agentic AI Applications** (December 2025).

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

```bash
cd owasp-top-10-agentic
uv sync
```

## Usage

### Basic Scan

```bash
# Scan a directory
python scanner.py /path/to/codebase

# Scan a single file
python scanner.py /path/to/file.py
```

### Output Formats

```bash
# Console output (default)
python scanner.py /path/to/codebase

# JSON output
python scanner.py /path/to/codebase --format json

# JSON to file
python scanner.py /path/to/codebase --format json --output results.json
```

### Filter by Rules

```bash
# By short name
python scanner.py /path/to/codebase --rules goal_hijack,tool_misuse

# By ID
python scanner.py /path/to/codebase --rules AA01,AA02,AA05

# Mixed
python scanner.py /path/to/codebase --rules goal_hijack,AA05
```

### Verbose Output

```bash
# Show detailed findings with recommendations
python scanner.py /path/to/codebase --verbose
```

### List Available Rules

```bash
python scanner.py list-rules
```

## Rule Short Names

| Short Name | ID | Risk |
|------------|-----|------|
| `goal_hijack` | AA01 | Agent Goal Hijack |
| `tool_misuse` | AA02 | Tool Misuse & Exploitation |
| `privilege_abuse` | AA03 | Identity & Privilege Abuse |
| `supply_chain` | AA04 | Agentic Supply Chain |
| `code_execution` | AA05 | Unexpected Code Execution |
| `memory_poisoning` | AA06 | Memory Poisoning |
| `excessive_agency` | AA07 | Excessive Agency |
| `insecure_plugin` | AA08 | Insecure Plugin Design |
| `overreliance` | AA09 | Overreliance on Outputs |
| `model_theft` | AA10 | Model Theft |

## Exit Codes

- `0` - No critical or high severity findings
- `1` - Critical or high severity findings detected

## Example Output

```
Scanning: /path/to/agent-project
Rules: 10 active

╭──────────────────────────────────────────────────────────────╮
│           OWASP Agentic AI Top 10 Scan Results               │
├──────────────────────────────────────────────────────────────┤
│ Scanned: /path/to/agent-project                              │
│ Total Findings: 5                                            │
│                                                              │
│   CRITICAL: 1                                                │
│   HIGH: 2                                                    │
│   MEDIUM: 2                                                  │
╰──────────────────────────────────────────────────────────────╯

AA01: Agent Goal Hijack

┏━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Sev  ┃ File          ┃ Line  ┃ Message                        ┃
┡━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ [!]  │ agent.py      │   42  │ Dynamic system prompt with ... │
│ [H]  │ prompts.py    │   15  │ F-string with user input ...   │
└──────┴───────────────┴───────┴────────────────────────────────┘
```

## JSON Output Schema

```json
{
  "scan_metadata": {
    "timestamp": "2025-12-15T10:30:00Z",
    "scan_path": "/path/to/codebase",
    "scanner": "OWASP Agentic AI Top 10 Scanner",
    "version": "0.1.0"
  },
  "summary": {
    "total_findings": 5,
    "by_severity": {
      "critical": 1,
      "high": 2,
      "medium": 2
    },
    "by_category": {
      "AA01: Agent Goal Hijack": 2,
      "AA05: Unexpected Code Execution": 3
    }
  },
  "findings": [
    {
      "rule_id": "AA01",
      "rule_name": "Agent Goal Hijack",
      "severity": "critical",
      "file_path": "/path/to/agent.py",
      "line_number": 42,
      "line_content": "system_prompt = base + user_input",
      "message": "Dynamic system prompt constructed with user input",
      "recommendation": "Never include unvalidated user input in system prompts.",
      "owasp_category": "AA01: Agent Goal Hijack",
      "confidence": "high"
    }
  ]
}
```

## Extending with Custom Rules

Create a new rule file in `rules/`:

```python
from rules.base import BaseRule, DetectionPattern, Severity, pattern

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

Then add it to `rules/__init__.py`.

## References

- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Agentic AI - Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP GenAI Security Project](https://genai.owasp.org/)

