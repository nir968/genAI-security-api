"""Prompt analysis: injection keywords first, then the DLP engine."""
from dataclasses import dataclass
from typing import Optional

from dlp import engine as dlp_engine
from dlp.models import ScanResult

# Phrase checked in addition to INJECTION_KEYWORDS.
IGNORE_PREVIOUS_PHRASE = "ignore previous"

INJECTION_KEYWORDS = [
    "previous instructions",
    "system prompt",
    "developer mode",
    "jailbreak",
    "override",
]

# threat_type recorded for each final DLP action
DLP_THREAT_TYPES = {
    "allow": "Safe",
    "alert": "DLP Alert",
    "redact": "DLP Redaction",
    "block": "DLP Violation",
}


@dataclass(frozen=True)
class DetectionResult:
    is_blocked: bool
    risk_score: int
    threat_type: str
    action: str = "allow"  # "allow" | "alert" | "redact" | "block"
    dlp: Optional[ScanResult] = None  # None when the prompt is an injection


def analyze_prompt(text: str) -> DetectionResult:
    """Classify a prompt. Case-insensitive substring match; injection wins.

    Injection is checked first and short-circuits. Otherwise the DLP engine
    decides, according to the loaded policy.
    """
    prompt_text = text.lower()

    if IGNORE_PREVIOUS_PHRASE in prompt_text or any(
        word in prompt_text for word in INJECTION_KEYWORDS
    ):
        return DetectionResult(True, 95, "Prompt Injection", "block", None)

    scan = dlp_engine.scan(text)
    return DetectionResult(
        is_blocked=scan.action == "block",
        risk_score=scan.risk_score,
        threat_type=DLP_THREAT_TYPES[scan.action],
        action=scan.action,
        dlp=scan,
    )
