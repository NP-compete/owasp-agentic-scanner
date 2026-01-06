"""OWASP Agentic AI Top 10 Security Scanner.

A static analysis tool that scans codebases for security risks defined in the
OWASP Top 10 for Agentic AI Applications (December 2025).
"""

from owasp_agentic_scanner.rules import ALL_RULES
from owasp_agentic_scanner.rules.base import BaseRule, Finding, Severity

__version__ = "0.1.0"
__all__ = ["ALL_RULES", "BaseRule", "Finding", "Severity", "__version__"]
