"""OWASP Agentic AI Top 10 detection rules."""

from owasp_agentic_scanner.rules.base import BaseRule, Finding, Severity
from owasp_agentic_scanner.rules.code_execution import CodeExecutionRule
from owasp_agentic_scanner.rules.excessive_agency import ExcessiveAgencyRule
from owasp_agentic_scanner.rules.goal_hijack import GoalHijackRule
from owasp_agentic_scanner.rules.insecure_plugin import InsecurePluginRule
from owasp_agentic_scanner.rules.memory_poisoning import MemoryPoisoningRule
from owasp_agentic_scanner.rules.model_theft import ModelTheftRule
from owasp_agentic_scanner.rules.overreliance import OverrelianceRule
from owasp_agentic_scanner.rules.privilege_abuse import PrivilegeAbuseRule
from owasp_agentic_scanner.rules.supply_chain import SupplyChainRule
from owasp_agentic_scanner.rules.tool_misuse import ToolMisuseRule

ALL_RULES: list[BaseRule] = [
    GoalHijackRule(),
    ToolMisuseRule(),
    PrivilegeAbuseRule(),
    SupplyChainRule(),
    CodeExecutionRule(),
    MemoryPoisoningRule(),
    ExcessiveAgencyRule(),
    InsecurePluginRule(),
    OverrelianceRule(),
    ModelTheftRule(),
]

__all__ = [
    "ALL_RULES",
    "BaseRule",
    "CodeExecutionRule",
    "ExcessiveAgencyRule",
    "Finding",
    "GoalHijackRule",
    "InsecurePluginRule",
    "MemoryPoisoningRule",
    "ModelTheftRule",
    "OverrelianceRule",
    "PrivilegeAbuseRule",
    "Severity",
    "SupplyChainRule",
    "ToolMisuseRule",
]
