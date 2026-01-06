"""OWASP Agentic AI Top 10 detection rules."""

from rules.base import BaseRule, Finding, Severity
from rules.goal_hijack import GoalHijackRule
from rules.tool_misuse import ToolMisuseRule
from rules.privilege_abuse import PrivilegeAbuseRule
from rules.supply_chain import SupplyChainRule
from rules.code_execution import CodeExecutionRule
from rules.memory_poisoning import MemoryPoisoningRule
from rules.excessive_agency import ExcessiveAgencyRule
from rules.insecure_plugin import InsecurePluginRule
from rules.overreliance import OverrelianceRule
from rules.model_theft import ModelTheftRule

ALL_RULES = [
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
    "BaseRule",
    "Finding",
    "Severity",
    "ALL_RULES",
    "GoalHijackRule",
    "ToolMisuseRule",
    "PrivilegeAbuseRule",
    "SupplyChainRule",
    "CodeExecutionRule",
    "MemoryPoisoningRule",
    "ExcessiveAgencyRule",
    "InsecurePluginRule",
    "OverrelianceRule",
    "ModelTheftRule",
]

