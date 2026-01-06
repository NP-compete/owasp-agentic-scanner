"""AA04: Agentic Supply Chain Vulnerabilities detection rule."""

from owasp_agentic_scanner.rules.base import (
    BaseRule,
    DetectionPattern,
    Severity,
    pattern,
)


class SupplyChainRule(BaseRule):
    """Detect patterns indicating supply chain vulnerabilities.

    Agentic Supply Chain Vulnerabilities occur when malicious or tampered tools,
    models, or agent personas compromise execution, especially in dynamic environments.
    """

    rule_id = "AA04"
    rule_name = "Agentic Supply Chain Vulnerabilities"
    owasp_category = "AA04: Agentic Supply Chain Vulnerabilities"
    description = "Detects patterns that could indicate supply chain vulnerabilities"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"pip\s+install\s+(?!.*==)"),
                message="Unpinned pip dependency installation",
                recommendation="Pin all dependencies to specific versions. Use lockfiles.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"npm\s+install\s+(?!.*@\d)"),
                message="Unpinned npm dependency installation",
                recommendation="Pin all dependencies to specific versions. Use package-lock.json.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"from_pretrained\s*\([\"'][^\"']+[\"']\s*\)"),
                message="Model loaded from remote source",
                recommendation="Verify model checksums. Use trusted model registries with integrity verification.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"load_model\s*\(.*http|download.*model"),
                message="Dynamic model download",
                recommendation="Pin model versions. Verify checksums before loading.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(
                    r"importlib\.import_module\s*\(.*\buser\b|__import__\s*\(.*\buser\b"
                ),
                message="Dynamic import with user input",
                recommendation="Never dynamically import based on user input. Use allowlists.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"plugin.*load.*url|load.*remote.*plugin"),
                message="Remote plugin loading",
                recommendation="Only load plugins from trusted, verified sources.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"curl.*\|\s*sh|wget.*\|\s*bash"),
                message="Piped remote script execution",
                recommendation="Never pipe remote scripts to shell. Download, verify, then execute.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"trust_remote_code\s*=\s*True"),
                message="Remote code trust enabled for model loading",
                recommendation="Avoid trust_remote_code=True. Use verified model sources.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"pickle\.load|torch\.load(?!.*weights_only)"),
                message="Unsafe deserialization (pickle/torch)",
                recommendation="Use safe deserialization. For torch, use weights_only=True.",
                severity=Severity.HIGH,
                confidence="high",
            ),
        ]
