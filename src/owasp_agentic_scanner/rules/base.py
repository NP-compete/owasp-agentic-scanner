"""Base rule class for OWASP Agentic AI detection."""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from re import Pattern
from typing import ClassVar


class Severity(Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A security finding from a rule scan."""

    rule_id: str
    rule_name: str
    severity: Severity
    file_path: str
    line_number: int
    line_content: str
    message: str
    recommendation: str
    owasp_category: str
    confidence: str = "medium"

    def to_dict(self) -> dict[str, str | int]:
        """Convert finding to dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content.strip(),
            "message": self.message,
            "recommendation": self.recommendation,
            "owasp_category": self.owasp_category,
            "confidence": self.confidence,
        }


@dataclass
class DetectionPattern:
    """A pattern to detect in source code."""

    pattern: Pattern[str]
    message: str
    recommendation: str
    severity: Severity = Severity.MEDIUM
    confidence: str = "medium"


class BaseRule(ABC):
    """Base class for all detection rules."""

    rule_id: ClassVar[str] = ""
    rule_name: ClassVar[str] = ""
    owasp_category: ClassVar[str] = ""
    description: ClassVar[str] = ""

    # File extensions to scan
    file_extensions: ClassVar[set[str]] = {
        ".py",
        ".js",
        ".ts",
        ".yaml",
        ".yml",
        ".json",
    }

    # Directories to skip
    skip_dirs: ClassVar[set[str]] = {
        "__pycache__",
        ".git",
        "node_modules",
        ".venv",
        "venv",
        ".tox",
        "dist",
        "build",
        ".eggs",
        "htmlcov",
    }

    def __init__(self) -> None:
        """Initialize the rule with its patterns."""
        self.patterns = self._get_patterns()

    @abstractmethod
    def _get_patterns(self) -> list[DetectionPattern]:
        """Return the detection patterns for this rule."""
        ...

    def should_scan_file(self, file_path: Path) -> bool:
        """Check if a file should be scanned."""
        if any(skip in file_path.parts for skip in self.skip_dirs):
            return False
        return file_path.suffix in self.file_extensions

    def scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file for findings."""
        if not self.should_scan_file(file_path):
            return []

        findings = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()

            for line_num, line in enumerate(lines, start=1):
                for detection in self.patterns:
                    if detection.pattern.search(line):
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                rule_name=self.rule_name,
                                severity=detection.severity,
                                file_path=str(file_path),
                                line_number=line_num,
                                line_content=line,
                                message=detection.message,
                                recommendation=detection.recommendation,
                                owasp_category=self.owasp_category,
                                confidence=detection.confidence,
                            )
                        )
        except (OSError, UnicodeDecodeError):
            pass

        return findings

    def scan_directory(self, directory: Path) -> list[Finding]:
        """Recursively scan a directory for findings."""
        findings = []
        for file_path in directory.rglob("*"):
            if file_path.is_file():
                findings.extend(self.scan_file(file_path))
        return findings


def pattern(regex: str, flags: int = re.IGNORECASE) -> Pattern[str]:
    """Compile a regex pattern with common flags."""
    return re.compile(regex, flags)
