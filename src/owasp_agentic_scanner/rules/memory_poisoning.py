"""AA06: Memory Poisoning detection rule."""

from owasp_agentic_scanner.rules.base import (
    BaseRule,
    DetectionPattern,
    Severity,
    pattern,
)


class MemoryPoisoningRule(BaseRule):
    """Detect patterns that could lead to memory poisoning.

    Memory Poisoning occurs when attackers inject malicious data into an agent's
    memory (conversation history, vector stores, checkpoints), influencing
    future actions or outputs.
    """

    rule_id = "AA06"
    rule_name = "Memory Poisoning"
    owasp_category = "AA06: Memory Poisoning"
    description = "Detects patterns that could allow memory poisoning attacks"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"checkpoint.*save.*user|save.*checkpoint.*user"),
                message="User input saved to checkpoint without validation",
                recommendation="Sanitize all user input before persisting to checkpoints.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(
                    r"history\.append\s*\(.*user|messages\.append\s*\(.*user"
                ),
                message="User input appended directly to conversation history",
                recommendation="Validate and sanitize user messages before adding to history.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"vector.*store.*add.*user|embed.*user.*store"),
                message="User input added to vector store",
                recommendation="Validate content before embedding. Consider content moderation.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"memory.*update.*tool|tool.*result.*memory"),
                message="Tool results stored in memory without validation",
                recommendation="Validate and sanitize tool outputs before storing in memory.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"persist.*state.*\(|save.*state.*\("),
                message="State persistence detected",
                recommendation="Ensure all persisted state is validated and sanitized.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"cache\.set\s*\(.*user|redis.*set.*user"),
                message="User input cached without validation",
                recommendation="Validate input before caching. Set appropriate TTLs.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"long_term_memory|persistent_memory|semantic_memory"),
                message="Long-term memory usage detected",
                recommendation="Implement content moderation and validation for all memory writes.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"summarize.*history|compress.*messages"),
                message="Message summarization detected",
                recommendation="Ensure summarization preserves security context and removes injections.",
                severity=Severity.LOW,
                confidence="low",
            ),
        ]
