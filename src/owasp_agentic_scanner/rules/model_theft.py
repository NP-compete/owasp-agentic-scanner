"""AA10: Model Theft detection rule."""

from owasp_agentic_scanner.rules.base import (
    BaseRule,
    DetectionPattern,
    Severity,
    pattern,
)


class ModelTheftRule(BaseRule):
    """Detect patterns that could lead to model theft.

    Model Theft occurs through unauthorized access to proprietary models via
    API exploitation, side-channel attacks, or direct exfiltration.
    """

    rule_id = "AA10"
    rule_name = "Model Theft"
    owasp_category = "AA10: Model Theft"
    description = "Detects patterns that could lead to model theft"

    def _get_patterns(self) -> list[DetectionPattern]:
        return [
            DetectionPattern(
                pattern=pattern(r"model\.save\s*\(|save_pretrained\s*\("),
                message="Model saving/serialization detected",
                recommendation="Restrict model save operations. Implement access controls.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"model.*export|export.*model|onnx.*export"),
                message="Model export functionality",
                recommendation="Restrict model export. Implement audit logging.",
                severity=Severity.HIGH,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"weights.*download|download.*weights|model.*download"),
                message="Model weights download capability",
                recommendation="Implement authentication and rate limiting for downloads.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"embed.*api.*public|public.*embed|embedding.*endpoint"),
                message="Public embedding endpoint",
                recommendation="Protect embedding endpoints. Implement rate limiting.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"logits|hidden_states|return.*all.*layers"),
                message="Model internals exposed",
                recommendation="Limit API responses to necessary outputs only.",
                severity=Severity.MEDIUM,
                confidence="medium",
            ),
            DetectionPattern(
                pattern=pattern(r"rate.*limit.*none|no.*rate.*limit|unlimited.*request"),
                message="Missing rate limiting",
                recommendation="Implement rate limiting to prevent extraction attacks.",
                severity=Severity.HIGH,
                confidence="high",
            ),
            DetectionPattern(
                pattern=pattern(r"debug.*true.*prod|debug.*=\s*True"),
                message="Debug mode potentially enabled",
                recommendation="Disable debug mode in production. It may leak model info.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"model\.parameters\(\)|get.*weights|state_dict"),
                message="Direct model parameter access",
                recommendation="Restrict parameter access to authorized operations only.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
            DetectionPattern(
                pattern=pattern(r"distill|student.*model|knowledge.*transfer"),
                message="Model distillation pattern",
                recommendation="Control distillation workflows. Audit knowledge transfer.",
                severity=Severity.MEDIUM,
                confidence="low",
            ),
        ]
