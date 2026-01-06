"""Tests for base rule classes."""

import tempfile
from pathlib import Path

from owasp_agentic_scanner.rules.base import (
    BaseRule,
    DetectionPattern,
    Finding,
    Severity,
    pattern,
)


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self) -> None:
        """Test severity enum has expected values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_ordering(self) -> None:
        """Test severity can be compared by value."""
        severities = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]
        sorted_sev = sorted(severities, key=lambda s: s.value)
        assert sorted_sev[0] == Severity.CRITICAL


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self) -> None:
        """Test creating a finding."""
        finding = Finding(
            rule_id="AA01",
            rule_name="Test Rule",
            severity=Severity.HIGH,
            file_path="/test/file.py",
            line_number=42,
            line_content="dangerous_code()",
            message="Test message",
            recommendation="Fix it",
            owasp_category="AA01: Test",
        )

        assert finding.rule_id == "AA01"
        assert finding.severity == Severity.HIGH
        assert finding.line_number == 42
        assert finding.confidence == "medium"  # default

    def test_finding_to_dict(self) -> None:
        """Test finding serialization."""
        finding = Finding(
            rule_id="AA02",
            rule_name="Test",
            severity=Severity.CRITICAL,
            file_path="/test.py",
            line_number=1,
            line_content="  code  ",
            message="msg",
            recommendation="rec",
            owasp_category="AA02: Test",
            confidence="high",
        )

        result = finding.to_dict()

        assert result["rule_id"] == "AA02"
        assert result["severity"] == "critical"
        assert result["line_content"] == "code"  # stripped
        assert result["confidence"] == "high"


class TestDetectionPattern:
    """Tests for DetectionPattern dataclass."""

    def test_pattern_defaults(self) -> None:
        """Test pattern has correct defaults."""
        p = DetectionPattern(
            pattern=pattern(r"test"),
            message="Test",
            recommendation="Fix",
        )

        assert p.severity == Severity.MEDIUM
        assert p.confidence == "medium"

    def test_pattern_custom_values(self) -> None:
        """Test pattern with custom values."""
        p = DetectionPattern(
            pattern=pattern(r"test"),
            message="Test",
            recommendation="Fix",
            severity=Severity.CRITICAL,
            confidence="high",
        )

        assert p.severity == Severity.CRITICAL
        assert p.confidence == "high"


class ConcreteRule(BaseRule):
    """Concrete implementation for testing."""

    rule_id = "TEST01"
    rule_name = "Test Rule"
    owasp_category = "TEST: Test Category"
    description = "A test rule"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"dangerous_function\s*\("),
                message="Dangerous function detected",
                recommendation="Use safe_function instead",
                severity=Severity.HIGH,
            ),
            DetectionPattern(
                pattern=pattern(r"eval\s*\("),
                message="eval() usage",
                recommendation="Avoid eval",
                severity=Severity.CRITICAL,
            ),
        ]


class TestBaseRule:
    """Tests for BaseRule class."""

    def test_rule_initialization(self) -> None:
        """Test rule initializes patterns."""
        rule = ConcreteRule()

        assert rule.rule_id == "TEST01"
        assert len(rule.patterns) == 2

    def test_should_scan_file_python(self) -> None:
        """Test Python files are scanned."""
        rule = ConcreteRule()

        assert rule.should_scan_file(Path("/test/file.py"))
        assert rule.should_scan_file(Path("/test/file.js"))
        assert rule.should_scan_file(Path("/test/file.yaml"))

    def test_should_skip_binary(self) -> None:
        """Test binary files are skipped."""
        rule = ConcreteRule()

        assert not rule.should_scan_file(Path("/test/file.exe"))
        assert not rule.should_scan_file(Path("/test/file.so"))
        assert not rule.should_scan_file(Path("/test/file.png"))

    def test_should_skip_directories(self) -> None:
        """Test skip directories are respected."""
        rule = ConcreteRule()

        assert not rule.should_scan_file(Path("/test/__pycache__/file.py"))
        assert not rule.should_scan_file(Path("/test/node_modules/pkg/file.js"))
        assert not rule.should_scan_file(Path("/test/.venv/lib/file.py"))

    def test_scan_file_finds_patterns(self) -> None:
        """Test scanning a file finds patterns."""
        rule = ConcreteRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("x = 1\n")
            f.write("dangerous_function()\n")
            f.write("y = 2\n")
            f.flush()

            findings = rule.scan_file(Path(f.name))

        assert len(findings) == 1
        assert findings[0].rule_id == "TEST01"
        assert findings[0].line_number == 2
        assert "dangerous_function" in findings[0].line_content

    def test_scan_file_multiple_patterns(self) -> None:
        """Test finding multiple patterns in one file."""
        rule = ConcreteRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("dangerous_function()\n")
            f.write("eval('code')\n")
            f.flush()

            findings = rule.scan_file(Path(f.name))

        assert len(findings) == 2
        severities = {f.severity for f in findings}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities

    def test_scan_file_no_matches(self) -> None:
        """Test scanning file with no matches."""
        rule = ConcreteRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("safe_code()\n")
            f.flush()

            findings = rule.scan_file(Path(f.name))

        assert len(findings) == 0

    def test_scan_directory(self) -> None:
        """Test scanning a directory."""
        rule = ConcreteRule()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            (Path(tmpdir) / "file1.py").write_text("dangerous_function()")
            (Path(tmpdir) / "file2.py").write_text("safe_code()")
            subdir = Path(tmpdir) / "sub"
            subdir.mkdir()
            (subdir / "file3.py").write_text("eval('x')")

            findings = rule.scan_directory(Path(tmpdir))

        assert len(findings) == 2


class TestPatternHelper:
    """Tests for pattern() helper function."""

    def test_pattern_case_insensitive(self) -> None:
        """Test patterns are case insensitive by default."""
        p = pattern(r"dangerous")

        assert p.search("DANGEROUS")
        assert p.search("Dangerous")
        assert p.search("dangerous")

    def test_pattern_regex(self) -> None:
        """Test pattern supports regex."""
        p = pattern(r"eval\s*\([^)]*\)")

        assert p.search("eval(x)")
        assert p.search("eval( 'code' )")
        assert not p.search("evaluate()")
