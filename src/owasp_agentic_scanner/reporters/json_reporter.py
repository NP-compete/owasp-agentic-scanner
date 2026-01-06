"""JSON reporter for scan results."""

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from owasp_agentic_scanner.rules.base import Finding


class JsonReporter:
    """JSON output for scan results."""

    def report(self, findings: list["Finding"], scan_path: str) -> str:
        """Generate JSON report from findings."""
        report_data = self._build_report(findings, scan_path)
        return json.dumps(report_data, indent=2)

    def _build_report(
        self, findings: list["Finding"], scan_path: str
    ) -> dict[str, Any]:
        """Build the report data structure."""
        # Count by severity
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Count by category
        category_counts: dict[str, int] = {}
        for f in findings:
            cat = f.owasp_category
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return {
            "scan_metadata": {
                "timestamp": datetime.now(UTC).isoformat(),
                "scan_path": scan_path,
                "scanner": "OWASP Agentic AI Top 10 Scanner",
                "version": "0.1.0",
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": severity_counts,
                "by_category": category_counts,
            },
            "findings": [f.to_dict() for f in findings],
        }

    def report_to_file(
        self, findings: list["Finding"], scan_path: str, output_path: str
    ) -> None:
        """Write JSON report to file."""
        report = self.report(findings, scan_path)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
