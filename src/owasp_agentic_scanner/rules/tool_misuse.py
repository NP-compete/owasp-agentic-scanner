"""AA02: Tool Misuse & Exploitation detection rule."""

from owasp_agentic_scanner.rules.base import (
    BaseRule,
    DetectionPattern,
    Severity,
    pattern,
)


class ToolMisuseRule(BaseRule):
    """Detect patterns that could lead to tool misuse by agents.

    Tool Misuse occurs when AI agents are tricked into using legitimate tools
    for unauthorized or harmful purposes, often through indirect prompt injection
    via tool outputs.
    """

    rule_id = "AA02"
    rule_name = "Tool Misuse & Exploitation"
    owasp_category = "AA02: Tool Misuse & Exploitation"
    description = "Detects patterns that could allow tool misuse by agents"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(
                    r"@tool\s*\n\s*def\s+\w+\([^)]*\).*:(?!\s*\n\s*\"\"\".*validat)"
                ),
                message="Tool function without input validation documentation",
                recommendation="Add input validation to all tool functions and document validation in docstring.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"subprocess\.(run|call|Popen).*shell\s*=\s*True"),
                message="Shell execution in tool with shell=True",
                recommendation="Avoid shell=True. Use explicit command lists and validate all inputs.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"os\.system\s*\("),
                message="os.system usage - vulnerable to command injection",
                recommendation="Use subprocess with shell=False and explicit argument lists.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"tool_result.*\bexec\b|tool_output.*\bexec\b"),
                message="Tool result passed to exec",
                recommendation="Never execute tool output as code. Validate and sanitize all tool results.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(
                    r"def\s+\w+_tool.*:\s*\n(?:.*\n)*?.*open\s*\([^)]*,\s*['\"]w"
                ),
                message="Tool with file write capability",
                recommendation="Restrict file write paths. Use allowlists for writable directories.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"tool.*\bdelete\b|\bdelete\b.*tool|tool.*\bremove\b"),
                message="Tool with delete/remove capability",
                recommendation="Implement confirmation and audit logging for destructive operations.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"requests\.(get|post|put|delete)\s*\(.*tool"),
                message="Tool making HTTP requests",
                recommendation="Validate URLs against allowlist. Implement request signing and timeouts.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"sql.*execute.*tool|tool.*sql.*execute"),
                message="Tool executing SQL queries",
                recommendation="Use parameterized queries. Never interpolate tool inputs into SQL.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
        ]
