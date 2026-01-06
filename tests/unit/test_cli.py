"""Tests for CLI functionality."""

import tempfile
from pathlib import Path

from typer.testing import CliRunner

from owasp_agentic_scanner.cli import (
    RULE_MAP,
    app,
    filter_suppressed,
    get_rules_by_filter,
    is_suppressed,
)
from owasp_agentic_scanner.rules.base import Finding, Severity

runner = CliRunner()


class TestRuleFiltering:
    """Tests for rule filtering."""

    def test_get_all_rules_no_filter(self) -> None:
        """Test getting all rules with no filter."""
        rules = get_rules_by_filter(None)
        assert len(rules) == 10

    def test_get_rules_by_short_name(self) -> None:
        """Test filtering by short name."""
        rules = get_rules_by_filter("goal_hijack")
        assert len(rules) == 1
        assert rules[0].rule_id == "AA01"

    def test_get_rules_by_id(self) -> None:
        """Test filtering by rule ID."""
        rules = get_rules_by_filter("AA05")
        assert len(rules) == 1
        assert rules[0].rule_id == "AA05"

    def test_get_rules_multiple(self) -> None:
        """Test filtering multiple rules."""
        rules = get_rules_by_filter("goal_hijack,AA02,code_execution")
        assert len(rules) == 3

        rule_ids = {r.rule_id for r in rules}
        assert "AA01" in rule_ids
        assert "AA02" in rule_ids
        assert "AA05" in rule_ids

    def test_get_rules_invalid_filter(self) -> None:
        """Test invalid filter returns all rules."""
        rules = get_rules_by_filter("nonexistent_rule")
        assert len(rules) == 10


class TestSuppression:
    """Tests for noqa suppression."""

    def test_is_suppressed_exact_match(self) -> None:
        """Test exact rule suppression."""
        line = "dangerous_code()  # noqa: AA01"
        assert is_suppressed(line, "AA01")
        assert not is_suppressed(line, "AA02")

    def test_is_suppressed_multiple_rules(self) -> None:
        """Test multiple rule suppression."""
        line = "dangerous_code()  # noqa: AA01, AA02"
        assert is_suppressed(line, "AA01")
        assert is_suppressed(line, "AA02")
        assert not is_suppressed(line, "AA03")

    def test_is_suppressed_all(self) -> None:
        """Test ALL suppression."""
        line = "dangerous_code()  # noqa: ALL"
        assert is_suppressed(line, "AA01")
        assert is_suppressed(line, "AA10")

    def test_is_suppressed_no_comment(self) -> None:
        """Test line without noqa."""
        line = "dangerous_code()"
        assert not is_suppressed(line, "AA01")

    def test_filter_suppressed(self) -> None:
        """Test filtering suppressed findings."""
        findings = [
            Finding(
                rule_id="AA01",
                rule_name="Test",
                severity=Severity.HIGH,
                file_path="/test.py",
                line_number=1,
                line_content="code()  # noqa: AA01",
                message="msg",
                recommendation="rec",
                owasp_category="AA01: Test",
            ),
            Finding(
                rule_id="AA02",
                rule_name="Test",
                severity=Severity.HIGH,
                file_path="/test.py",
                line_number=2,
                line_content="code()",
                message="msg",
                recommendation="rec",
                owasp_category="AA02: Test",
            ),
        ]

        filtered = filter_suppressed(findings)
        assert len(filtered) == 1
        assert filtered[0].rule_id == "AA02"


class TestCLI:
    """Tests for CLI commands."""

    def test_version_command(self) -> None:
        """Test version command."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.stdout

    def test_list_rules_command(self) -> None:
        """Test list-rules command."""
        result = runner.invoke(app, ["list-rules"])
        assert result.exit_code == 0
        assert "AA01" in result.stdout
        assert "Goal Hijack" in result.stdout

    def test_scan_nonexistent_path(self) -> None:
        """Test scanning nonexistent path."""
        result = runner.invoke(app, ["scan", "/nonexistent/path"])
        assert result.exit_code == 1
        assert "does not exist" in result.stdout

    def test_scan_empty_directory(self) -> None:
        """Test scanning empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["scan", tmpdir])
            assert result.exit_code == 0
            assert "No security findings" in result.stdout

    def test_scan_with_findings(self) -> None:
        """Test scanning directory with findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.py").write_text("exec(user_input)\n")

            result = runner.invoke(app, ["scan", tmpdir])
            assert result.exit_code == 1  # Exit 1 due to critical finding

    def test_scan_json_output(self) -> None:
        """Test JSON output format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.py").write_text("x = 1\n")

            result = runner.invoke(app, ["scan", tmpdir, "--format", "json"])
            assert result.exit_code == 0
            assert '"total_findings"' in result.stdout

    def test_scan_sarif_output(self) -> None:
        """Test SARIF output format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.py").write_text("x = 1\n")

            result = runner.invoke(app, ["scan", tmpdir, "--format", "sarif"])
            assert result.exit_code == 0
            assert '"version": "2.1.0"' in result.stdout

    def test_scan_with_rule_filter(self) -> None:
        """Test scanning with rule filter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # This file would trigger AA05 but not AA01
            (Path(tmpdir) / "test.py").write_text("exec(code)\n")

            result = runner.invoke(app, ["scan", tmpdir, "--rules", "goal_hijack"])
            # Should pass because we filtered to only AA01
            assert result.exit_code == 0

    def test_scan_min_severity(self) -> None:
        """Test minimum severity filter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # This triggers a CRITICAL finding
            (Path(tmpdir) / "test.py").write_text("exec(code)\n")

            # With min-severity=info, should exit 1 (finding reported)
            result = runner.invoke(app, ["scan", tmpdir, "--min-severity", "critical"])
            assert result.exit_code == 1


class TestRuleMap:
    """Tests for RULE_MAP."""

    def test_rule_map_complete(self) -> None:
        """Test RULE_MAP has all 10 rules."""
        assert len(RULE_MAP) == 10

    def test_rule_map_values(self) -> None:
        """Test RULE_MAP has correct mappings."""
        assert RULE_MAP["goal_hijack"] == "AA01"
        assert RULE_MAP["tool_misuse"] == "AA02"
        assert RULE_MAP["privilege_abuse"] == "AA03"
        assert RULE_MAP["supply_chain"] == "AA04"
        assert RULE_MAP["code_execution"] == "AA05"
        assert RULE_MAP["memory_poisoning"] == "AA06"
        assert RULE_MAP["excessive_agency"] == "AA07"
        assert RULE_MAP["insecure_plugin"] == "AA08"
        assert RULE_MAP["overreliance"] == "AA09"
        assert RULE_MAP["model_theft"] == "AA10"
