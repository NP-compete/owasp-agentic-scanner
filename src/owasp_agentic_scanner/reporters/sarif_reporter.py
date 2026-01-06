"""SARIF reporter for scan results.

SARIF (Static Analysis Results Interchange Format) is a standard format
for static analysis tools, enabling integration with CI/CD systems.
"""

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from owasp_agentic_scanner.rules.base import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


class SarifReporter:
    """SARIF output for scan results."""

    SEVERITY_MAP: ClassVar[dict[str, str]] = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }

    def report(self, findings: list["Finding"], scan_path: str) -> str:
        """Generate SARIF report from findings."""
        report_data = self._build_report(findings, scan_path)
        return json.dumps(report_data, indent=2)

    def _build_report(self, findings: list["Finding"], scan_path: str) -> dict[str, Any]:
        """Build the SARIF report structure."""
        rules = self._build_rules(findings)
        results = self._build_results(findings)

        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "OWASP Agentic AI Scanner",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/NP-compete/owasp-agentic-ai-security-scanner",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(UTC).isoformat(),
                        }
                    ],
                    "artifacts": [
                        {
                            "location": {"uri": scan_path},
                            "roles": ["analysisTarget"],
                        }
                    ],
                }
            ],
        }

    def _build_rules(self, findings: list["Finding"]) -> list[dict[str, Any]]:
        """Build SARIF rules from unique findings."""
        seen_rules: dict[str, dict[str, Any]] = {}

        for f in findings:
            if f.rule_id not in seen_rules:
                seen_rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.rule_name,
                    "shortDescription": {"text": f.rule_name},
                    "fullDescription": {"text": f.message},
                    "helpUri": f"https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#{f.rule_id.lower()}",
                    "properties": {
                        "category": f.owasp_category,
                        "security-severity": self._get_security_severity(f.severity.value),
                    },
                }

        return list(seen_rules.values())

    def _build_results(self, findings: list["Finding"]) -> list[dict[str, Any]]:
        """Build SARIF results from findings."""
        results = []

        for f in findings:
            results.append(
                {
                    "ruleId": f.rule_id,
                    "level": self.SEVERITY_MAP.get(f.severity.value, "warning"),
                    "message": {"text": f"{f.message}\n\nRecommendation: {f.recommendation}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.file_path},
                                "region": {
                                    "startLine": f.line_number,
                                    "snippet": {"text": f.line_content.strip()},
                                },
                            }
                        }
                    ],
                    "properties": {
                        "confidence": f.confidence,
                        "owasp_category": f.owasp_category,
                    },
                }
            )

        return results

    def _get_security_severity(self, severity: str) -> str:
        """Map severity to SARIF security-severity score."""
        scores = {
            "critical": "9.0",
            "high": "7.0",
            "medium": "5.0",
            "low": "3.0",
            "info": "1.0",
        }
        return scores.get(severity, "5.0")

    def report_to_file(self, findings: list["Finding"], scan_path: str, output_path: str) -> None:
        """Write SARIF report to file."""
        report = self.report(findings, scan_path)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
