"""Pure prompt-analysis logic (no I/O), kept separate so it is easy to test."""
from dataclasses import dataclass

# Phrase checked in addition to INJECTION_KEYWORDS.
IGNORE_PREVIOUS_PHRASE = "ignore previous"

INJECTION_KEYWORDS = [
    "previous instructions",
    "system prompt",
    "developer mode",
    "jailbreak",
    "override",
]

DLP_KEYWORDS = [
    "credit card",
    "cc number",
    "password",
    "cvv",
    "api key",
    "secret",
]


@dataclass(frozen=True)
class DetectionResult:
    is_blocked: bool
    risk_score: int
    threat_type: str


def analyze_prompt(text: str) -> DetectionResult:
    """Classify a prompt. Case-insensitive substring match; injection wins."""
    prompt_text = text.lower()

    if IGNORE_PREVIOUS_PHRASE in prompt_text or any(
        word in prompt_text for word in INJECTION_KEYWORDS
    ):
        return DetectionResult(True, 95, "Prompt Injection")

    if any(word in prompt_text for word in DLP_KEYWORDS):
        return DetectionResult(True, 80, "DLP Violation")

    return DetectionResult(False, 10, "Safe")
