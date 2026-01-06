"""AA09: Overreliance on Agentic Outputs detection rule."""

from rules.base import BaseRule, DetectionPattern, Severity, pattern


class OverrelianceRule(BaseRule):
    """Detect patterns indicating overreliance on agent outputs.

    Overreliance occurs when there is blind trust in agent-generated outputs
    without verification, leading to misinformation or flawed decisions.
    """

    rule_id = "AA09"
    rule_name = "Overreliance on Agentic Outputs"
    owasp_category = "AA09: Overreliance on Agentic Outputs"
    description = "Detects patterns indicating overreliance on agent outputs"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"llm.*output.*directly|directly.*use.*response"),
                message="Direct use of LLM output without validation",
                recommendation="Validate and verify LLM outputs before use in logic.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"agent.*decision.*final|trust.*agent.*output"),
                message="Agent output treated as final decision",
                recommendation="Implement human review for consequential decisions.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"if.*response.*:(?!.*valid)|if.*output.*:(?!.*check)"),
                message="Conditional logic on unvalidated output",
                recommendation="Validate output structure and content before conditional logic.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"json\.loads\s*\(.*response(?!.*try)"),
                message="JSON parsing of response without error handling",
                recommendation="Wrap JSON parsing in try/except. Validate structure.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"float\s*\(.*response|int\s*\(.*response"),
                message="Numeric parsing of response without validation",
                recommendation="Validate numeric responses. Handle parsing errors.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"return.*llm.*response|return.*agent.*output"),
                message="Direct return of LLM/agent output",
                recommendation="Validate and sanitize outputs before returning.",
                severity=Severity.LOW,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"cache.*response.*\(|store.*response.*\("),
                message="Caching agent response without validation",
                recommendation="Validate responses before caching. Consider TTLs.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"fact.*check.*false|verify.*false|validate.*=\s*False"),
                message="Validation explicitly disabled",
                recommendation="Always enable validation for agent outputs.",
                severity=Severity.HIGH,
                confidence="high",
            ),
        ]

