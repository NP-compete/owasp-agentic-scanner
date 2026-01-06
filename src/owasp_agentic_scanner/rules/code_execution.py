"""AA05: Unexpected Code Execution detection rule."""

from owasp_agentic_scanner.rules.base import (
    BaseRule,
    DetectionPattern,
    Severity,
    pattern,
)


class CodeExecutionRule(BaseRule):
    """Detect patterns that could lead to unexpected code execution.

    Unexpected Code Execution occurs when agents generate or execute
    attacker-controlled code, leading to potential RCE vulnerabilities.
    """

    rule_id = "AA05"
    rule_name = "Unexpected Code Execution"
    owasp_category = "AA05: Unexpected Code Execution"
    description = "Detects patterns that could lead to code execution vulnerabilities"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"\bexec\s*\("),
                message="exec() function usage detected",
                recommendation="Avoid exec(). If necessary, use strict sandboxing and input validation.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"\beval\s*\("),
                message="eval() function usage detected",
                recommendation="Never use eval() with untrusted input. Use ast.literal_eval() for data.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"compile\s*\(.*exec|compile\s*\(.*eval"),
                message="Dynamic code compilation",
                recommendation="Avoid dynamic code compilation. Use static approaches.",
                severity=Severity.HIGH,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"subprocess.*\$|subprocess.*format|subprocess.*\+"),
                message="Subprocess with dynamic input",
                recommendation="Use subprocess with explicit argument lists. Never interpolate user input.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"code_interpreter|execute_code|run_code"),
                message="Code execution capability detected",
                recommendation="Implement strict sandboxing for code execution. Limit capabilities.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(
                    r"llm.*code.*execute|execute.*llm.*code|agent.*generate.*code.*run"
                ),
                message="LLM-generated code execution",
                recommendation="Never execute LLM-generated code without human review and sandboxing.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"Function\s*\(|new\s+Function\s*\("),
                message="JavaScript Function constructor (eval equivalent)",
                recommendation="Avoid Function constructor. Use static code.",
                severity=Severity.CRITICAL,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"setInterval\s*\(.*\$|setTimeout\s*\(.*\$"),
                message="Dynamic code in timer functions",
                recommendation="Use function references, not string code in timers.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"child_process.*exec\s*\("),
                message="Node.js child_process exec usage",
                recommendation="Use execFile or spawn with explicit arguments instead of exec.",
                severity=Severity.HIGH,
                confidence="high",
            ),
        ]
