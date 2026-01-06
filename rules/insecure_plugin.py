"""AA08: Insecure Plugin Design detection rule."""

from rules.base import BaseRule, DetectionPattern, Severity, pattern


class InsecurePluginRule(BaseRule):
    """Detect patterns indicating insecure plugin design.

    Insecure Plugin Design vulnerabilities allow attackers to exploit agents
    through plugins or extensions with insufficient input validation,
    excessive permissions, or lack of access control.
    """

    rule_id = "AA08"
    rule_name = "Insecure Plugin Design"
    owasp_category = "AA08: Insecure Plugin Design"
    description = "Detects patterns indicating insecure plugin/tool design"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"plugin.*register.*\(|register.*plugin.*\("),
                message="Plugin registration detected",
                recommendation="Validate plugin sources. Implement plugin signing and verification.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"load.*plugin.*\(.*url|plugin.*from.*url"),
                message="Plugin loaded from URL",
                recommendation="Only load plugins from trusted, verified sources.",
                severity=Severity.HIGH,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"__getattr__.*tool|dynamic.*tool.*lookup"),
                message="Dynamic tool lookup pattern",
                recommendation="Use explicit tool registration. Avoid dynamic lookups.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"tool.*\*\*kwargs|\*\*kwargs.*tool"),
                message="Tool accepting arbitrary kwargs",
                recommendation="Define explicit parameters for tools. Avoid **kwargs.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"mcp.*server.*\((?!.*validate)"),
                message="MCP server without explicit validation",
                recommendation="Implement input validation for all MCP tool handlers.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"tool.*no.*auth|auth.*none.*tool"),
                message="Tool without authentication",
                recommendation="Implement authentication for all tools with side effects.",
                severity=Severity.HIGH,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"allow.*all.*origins|cors.*\*|\*.*cors"),
                message="Overly permissive CORS configuration",
                recommendation="Restrict CORS to specific trusted origins.",
                severity=Severity.HIGH,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"serialize.*tool|tool.*pickle|marshal.*tool"),
                message="Tool serialization detected",
                recommendation="Use safe serialization formats. Avoid pickle for untrusted data.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"hook.*before|hook.*after|middleware.*tool"),
                message="Tool middleware/hooks detected",
                recommendation="Validate all data passing through hooks and middleware.",
                severity=Severity.LOW,
                confidence="low",
            ),
        ]

