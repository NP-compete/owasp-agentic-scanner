"""AA01: Agent Goal Hijack detection rule."""

from owasp_agentic_scanner.rules.base import (
    BaseRule,
    DetectionPattern,
    Severity,
    pattern,
)


class GoalHijackRule(BaseRule):
    """Detect patterns that could lead to agent goal hijacking.

    Agent Goal Hijack occurs when attackers manipulate an AI agent's objectives,
    redirecting its actions toward malicious ends through prompt injection or
    manipulation of the agent's instruction context.
    """

    rule_id = "AA01"
    rule_name = "Agent Goal Hijack"
    owasp_category = "AA01: Agent Goal Hijack"
    description = (
        "Detects patterns that could allow attackers to hijack agent objectives"
    )

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"system_prompt\s*[+=].*\buser"),
                message="Dynamic system prompt constructed with user input",
                recommendation="Never include unvalidated user input in system prompts. Use parameterized templates with strict validation.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"f[\"'].*\{.*user.*\}.*system|system.*\{.*user.*\}"),
                message="F-string with user input in system context",
                recommendation="Avoid f-strings for system prompts. Use validated template rendering.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(
                    r"\.format\(.*user.*\).*prompt|prompt.*\.format\(.*user"
                ),
                message="String format with user input in prompt",
                recommendation="Use parameterized prompts with input sanitization.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"jinja.*render.*user|user.*jinja.*render"),
                message="Jinja template rendering with user input",
                recommendation="Ensure Jinja templates have autoescape enabled and user input is validated.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"prompt\s*=.*\+.*input|input.*\+.*prompt"),
                message="Prompt concatenation with input",
                recommendation="Never concatenate user input directly into prompts.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(
                    r"system_message.*user_input|user_input.*system_message"
                ),
                message="User input referenced in system message context",
                recommendation="Validate and sanitize user input before any system context usage.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"ignore\s+(previous|all|above)\s+instructions"),
                message="Potential prompt injection payload detected",
                recommendation="Implement input validation to detect and block injection attempts.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(
                    r"you\s+are\s+now|new\s+instructions|forget\s+everything"
                ),
                message="Potential prompt injection payload detected",
                recommendation="Implement input validation to detect and block injection attempts.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
        ]
