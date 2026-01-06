"""AA03: Identity & Privilege Abuse detection rule."""

from owasp_agentic_scanner.rules.base import (
    BaseRule,
    DetectionPattern,
    Severity,
    pattern,
)


class PrivilegeAbuseRule(BaseRule):
    """Detect patterns that could lead to identity and privilege abuse.

    Identity & Privilege Abuse occurs when compromised credentials or
    mismanaged permissions allow agents to operate beyond their intended scope.
    """

    rule_id = "AA03"
    rule_name = "Identity & Privilege Abuse"
    owasp_category = "AA03: Identity & Privilege Abuse"
    description = "Detects patterns that could lead to privilege abuse by agents"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"(api_key|apikey|secret|password|token)\s*=\s*[\"'][^\"']+[\"']"),
                message="Hardcoded credential detected",
                recommendation="Use environment variables or secrets management for credentials.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"admin|superuser|root"),
                message="Elevated privilege reference detected",
                recommendation="Apply principle of least privilege. Avoid admin/root access for agents.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"sudo\s|as\s+root|--privileged"),
                message="Privileged execution detected",
                recommendation="Agents should never run with elevated privileges.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"chmod\s+777|chmod\s+\+x\s+.*\$"),
                message="Dangerous permission modification",
                recommendation="Avoid broad permission changes. Use minimal required permissions.",
                severity=Severity.HIGH,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"service_account.*all|all.*permissions|full.*access"),
                message="Overly permissive access pattern",
                recommendation="Scope service accounts to minimal required permissions.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"impersonate|assume.*role|sts.*assume"),
                message="Role assumption/impersonation detected",
                recommendation="Audit and restrict role assumption capabilities.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"auth.*bypass|skip.*auth|no.*auth"),
                message="Authentication bypass pattern",
                recommendation="Never bypass authentication. Implement proper auth for all agent actions.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"),
                message="Potential hardcoded bearer token",
                recommendation="Use secure token storage and rotation.",
                severity=Severity.CRITICAL,
                confidence="medium",
            ),
        ]
