"""AA07: Excessive Agency detection rule."""

from rules.base import BaseRule, DetectionPattern, Severity, pattern


class ExcessiveAgencyRule(BaseRule):
    """Detect patterns indicating excessive agent autonomy.

    Excessive Agency occurs when agents operate with too much autonomy,
    making decisions or taking actions without adequate oversight or
    human-in-the-loop controls.
    """

    rule_id = "AA07"
    rule_name = "Excessive Agency"
    owasp_category = "AA07: Excessive Agency"
    description = "Detects patterns indicating excessive agent autonomy"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"auto.*approve|approve.*auto|skip.*confirm"),
                message="Automatic approval without human review",
                recommendation="Require human approval for consequential actions.",
                severity=Severity.HIGH,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"human.*loop.*false|human_in_loop\s*=\s*False"),
                message="Human-in-the-loop explicitly disabled",
                recommendation="Enable human oversight for production agents.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"max.*iterations.*=\s*(-1|None|999|1000)"),
                message="Unlimited or very high iteration limit",
                recommendation="Set reasonable iteration limits to prevent runaway agents.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"while\s+True.*agent|agent.*while\s+True"),
                message="Unbounded agent loop",
                recommendation="Add termination conditions and iteration limits.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"auto.*execute|execute.*auto|autonomous.*action"),
                message="Autonomous execution pattern",
                recommendation="Add confirmation steps for autonomous actions.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"recursion.*limit.*=\s*\d{4,}|max.*depth.*=\s*\d{4,}"),
                message="Very high recursion/depth limit",
                recommendation="Use reasonable limits to prevent resource exhaustion.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"force.*=\s*True|skip.*validation|bypass.*check"),
                message="Validation bypass pattern",
                recommendation="Never bypass validation in production code.",
                severity=Severity.HIGH,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"send.*email.*auto|auto.*send.*message|post.*social.*auto"),
                message="Automatic external communication",
                recommendation="Require human review before sending external communications.",
                severity=Severity.HIGH,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"delete.*auto|auto.*delete|drop.*table.*auto"),
                message="Automatic destructive operation",
                recommendation="Always require confirmation for destructive operations.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
        ]

