"""Tests for reporters."""

import json
import tempfile
from pathlib import Path

from owasp_agentic_scanner.reporters.console import ConsoleReporter
from owasp_agentic_scanner.reporters.json_reporter import JsonReporter
from owasp_agentic_scanner.reporters.sarif_reporter import SarifReporter
from owasp_agentic_scanner.rules.base import Finding, Severity


def create_test_finding(
    rule_id: str = "AA01",
    severity: Severity = Severity.HIGH,
    line_number: int = 42,
) -> Finding:
    """Create a test finding."""
    return Finding(
        rule_id=rule_id,
        rule_name="Test Rule",
        severity=severity,
        file_path="/test/file.py",
        line_number=line_number,
        line_content="dangerous_code()",
        message="Test message",
        recommendation="Fix it",
        owasp_category=f"{rule_id}: Test Category",
        confidence="high",
    )


class TestJsonReporter:
    """Tests for JSON reporter."""

    def test_report_empty_findings(self) -> None:
        """Test reporting with no findings."""
        reporter = JsonReporter()
        result = reporter.report([], "/test/path")
        data = json.loads(result)

        assert data["summary"]["total_findings"] == 0
        assert data["findings"] == []

    def test_report_with_findings(self) -> None:
        """Test reporting with findings."""
        reporter = JsonReporter()
        findings = [
            create_test_finding("AA01", Severity.CRITICAL),
            create_test_finding("AA02", Severity.HIGH),
        ]

        result = reporter.report(findings, "/test/path")
        data = json.loads(result)

        assert data["summary"]["total_findings"] == 2
        assert data["summary"]["by_severity"]["critical"] == 1
        assert data["summary"]["by_severity"]["high"] == 1
        assert len(data["findings"]) == 2

    def test_report_metadata(self) -> None:
        """Test report contains metadata."""
        reporter = JsonReporter()
        result = reporter.report([], "/test/path")
        data = json.loads(result)

        assert "scan_metadata" in data
        assert data["scan_metadata"]["scan_path"] == "/test/path"
        assert "timestamp" in data["scan_metadata"]
        assert "version" in data["scan_metadata"]

    def test_report_to_file(self) -> None:
        """Test writing report to file."""
        reporter = JsonReporter()
        findings = [create_test_finding()]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            reporter.report_to_file(findings, "/test", f.name)

        content = Path(f.name).read_text()
        data = json.loads(content)
        assert data["summary"]["total_findings"] == 1


class TestSarifReporter:
    """Tests for SARIF reporter."""

    def test_sarif_schema(self) -> None:
        """Test SARIF output has correct schema."""
        reporter = SarifReporter()
        result = reporter.report([], "/test/path")
        data = json.loads(result)

        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_sarif_tool_info(self) -> None:
        """Test SARIF contains tool information."""
        reporter = SarifReporter()
        result = reporter.report([], "/test/path")
        data = json.loads(result)

        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "OWASP Agentic AI Scanner"
        assert "version" in tool

    def test_sarif_rules(self) -> None:
        """Test SARIF contains rule definitions."""
        reporter = SarifReporter()
        findings = [
            create_test_finding("AA01"),
            create_test_finding("AA02"),
        ]

        result = reporter.report(findings, "/test")
        data = json.loads(result)

        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2

        rule_ids = [r["id"] for r in rules]
        assert "AA01" in rule_ids
        assert "AA02" in rule_ids

    def test_sarif_results(self) -> None:
        """Test SARIF contains results."""
        reporter = SarifReporter()
        findings = [create_test_finding("AA01", Severity.CRITICAL, 42)]

        result = reporter.report(findings, "/test")
        data = json.loads(result)

        results = data["runs"][0]["results"]
        assert len(results) == 1

        r = results[0]
        assert r["ruleId"] == "AA01"
        assert r["level"] == "error"  # CRITICAL maps to error
        assert r["locations"][0]["physicalLocation"]["region"]["startLine"] == 42

    def test_sarif_severity_mapping(self) -> None:
        """Test severity to SARIF level mapping."""
        reporter = SarifReporter()

        assert reporter.SEVERITY_MAP["critical"] == "error"
        assert reporter.SEVERITY_MAP["high"] == "error"
        assert reporter.SEVERITY_MAP["medium"] == "warning"
        assert reporter.SEVERITY_MAP["low"] == "note"
        assert reporter.SEVERITY_MAP["info"] == "none"

    def test_sarif_to_file(self) -> None:
        """Test writing SARIF to file."""
        reporter = SarifReporter()
        findings = [create_test_finding()]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            reporter.report_to_file(findings, "/test", f.name)

        content = Path(f.name).read_text()
        data = json.loads(content)
        assert data["version"] == "2.1.0"


class TestConsoleReporter:
    """Tests for console reporter."""

    def test_console_reporter_init(self) -> None:
        """Test console reporter initializes."""
        reporter = ConsoleReporter()

        assert reporter.console is not None
        assert "critical" in reporter.SEVERITY_COLORS
        assert "critical" in reporter.SEVERITY_ICONS

    def test_severity_colors_complete(self) -> None:
        """Test all severities have colors."""
        reporter = ConsoleReporter()

        for sev in ["critical", "high", "medium", "low", "info"]:
            assert sev in reporter.SEVERITY_COLORS
            assert sev in reporter.SEVERITY_ICONS
