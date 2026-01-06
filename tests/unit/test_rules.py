"""Tests for individual detection rules."""

import tempfile
from pathlib import Path

from owasp_agentic_scanner.rules import ALL_RULES
from owasp_agentic_scanner.rules.base import Severity
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


class TestAllRules:
    """Tests for the ALL_RULES collection."""

    def test_all_rules_count(self) -> None:
        """Test we have all 10 rules."""
        assert len(ALL_RULES) == 10

    def test_all_rules_unique_ids(self) -> None:
        """Test all rule IDs are unique."""
        ids = [r.rule_id for r in ALL_RULES]
        assert len(ids) == len(set(ids))

    def test_all_rules_have_patterns(self) -> None:
        """Test all rules have at least one pattern."""
        for rule in ALL_RULES:
            assert len(rule.patterns) > 0, f"{rule.rule_id} has no patterns"

    def test_all_rules_have_metadata(self) -> None:
        """Test all rules have required metadata."""
        for rule in ALL_RULES:
            assert rule.rule_id.startswith("AA")
            assert rule.rule_name
            assert rule.owasp_category


class TestGoalHijackRule:
    """Tests for AA01: Agent Goal Hijack."""

    def test_detects_dynamic_system_prompt(self) -> None:
        """Test detection of dynamic system prompt."""
        rule = GoalHijackRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("system_prompt += user_input\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_prompt_injection_payload(self) -> None:
        """Test detection of injection payload."""
        rule = GoalHijackRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('text = "ignore previous instructions"\n')
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) >= 1


class TestToolMisuseRule:
    """Tests for AA02: Tool Misuse & Exploitation."""

    def test_detects_shell_true(self) -> None:
        """Test detection of shell=True."""
        rule = ToolMisuseRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("subprocess.run(cmd, shell=True)\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_os_system(self) -> None:
        """Test detection of os.system."""
        rule = ToolMisuseRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("os.system(command)\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) == 1


class TestPrivilegeAbuseRule:
    """Tests for AA03: Identity & Privilege Abuse."""

    def test_detects_hardcoded_secret(self) -> None:
        """Test detection of hardcoded secrets."""
        rule = PrivilegeAbuseRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('api_key = "sk-1234567890abcdef"\n')
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_sudo(self) -> None:
        """Test detection of sudo usage."""
        rule = PrivilegeAbuseRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('cmd = "sudo rm -rf /"\n')
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) >= 1


class TestSupplyChainRule:
    """Tests for AA04: Agentic Supply Chain Vulnerabilities."""

    def test_detects_trust_remote_code(self) -> None:
        """Test detection of trust_remote_code."""
        rule = SupplyChainRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("model = Model.from_pretrained(name, trust_remote_code=True)\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_pickle_load(self) -> None:
        """Test detection of pickle.load."""
        rule = SupplyChainRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("data = pickle.load(f)\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) >= 1


class TestCodeExecutionRule:
    """Tests for AA05: Unexpected Code Execution."""

    def test_detects_exec(self) -> None:
        """Test detection of exec()."""
        rule = CodeExecutionRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("exec(code)\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_eval(self) -> None:
        """Test detection of eval()."""
        rule = CodeExecutionRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("result = eval(user_input)\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


class TestMemoryPoisoningRule:
    """Tests for AA06: Memory Poisoning."""

    def test_detects_vector_store_add(self) -> None:
        """Test detection of vector store operations."""
        rule = MemoryPoisoningRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("vector_store.add(user_content)\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) >= 1


class TestExcessiveAgencyRule:
    """Tests for AA07: Excessive Agency."""

    def test_detects_human_in_loop_disabled(self) -> None:
        """Test detection of disabled human-in-the-loop."""
        rule = ExcessiveAgencyRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("config = Config(human_in_loop=False)\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_auto_approve(self) -> None:
        """Test detection of auto-approve pattern."""
        rule = ExcessiveAgencyRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("auto_approve = True\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) >= 1


class TestInsecurePluginRule:
    """Tests for AA08: Insecure Plugin Design."""

    def test_detects_cors_wildcard(self) -> None:
        """Test detection of CORS wildcard."""
        rule = InsecurePluginRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('allow_all_origins = "*"\n')
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) >= 1


class TestOverrelianceRule:
    """Tests for AA09: Overreliance on Agentic Outputs."""

    def test_detects_validation_disabled(self) -> None:
        """Test detection of disabled validation."""
        rule = OverrelianceRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("validate = False\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) >= 1


class TestModelTheftRule:
    """Tests for AA10: Model Theft."""

    def test_detects_no_rate_limit(self) -> None:
        """Test detection of missing rate limiting."""
        rule = ModelTheftRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("rate_limit = None  # no_rate_limit for testing\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) >= 1

    def test_detects_debug_mode(self) -> None:
        """Test detection of debug mode."""
        rule = ModelTheftRule()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("DEBUG = True\n")
            f.flush()
            findings = rule.scan_file(Path(f.name))

        assert len(findings) >= 1
