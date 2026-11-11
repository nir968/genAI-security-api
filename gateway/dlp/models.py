"""Data types shared by the DLP package."""
from dataclasses import dataclass, field

# Every data type the detectors can produce. The policy must cover all of them.
DATA_TYPES = (
    "CREDIT_CARD",
    "IL_ID",
    "IBAN",
    "EMAIL",
    "PHONE_IL",
    "AWS_ACCESS_KEY",
    "GITHUB_TOKEN",
    "PRIVATE_KEY",
    "JWT",
    "CREDENTIAL_ASSIGNMENT",
    "HIGH_ENTROPY_SECRET",
)

# Policy actions, from least to most severe (the index is the severity).
ACTIONS = ("allow", "alert", "redact", "block")

# Finding confidence, from least to most certain (the index is the rank).
CONFIDENCES = ("low", "medium", "high")


def action_severity(action: str) -> int:
    return ACTIONS.index(action)


def confidence_rank(confidence: str) -> int:
    return CONFIDENCES.index(confidence)


@dataclass(frozen=True)
class Finding:
    """One piece of sensitive data located in a text.

    Only the position and a *masked* rendering are kept. The raw matched value
    is deliberately never stored, so a Finding is always safe to log.
    """

    data_type: str
    start: int
    end: int
    confidence: str  # "high" | "medium" | "low"
    masked_value: str


@dataclass(frozen=True)
class ScanResult:
    findings: list = field(default_factory=list)
    action: str = "allow"  # "allow" | "alert" | "redact" | "block"
    risk_score: int = 10
    redacted_text: str = ""
    data_types: list = field(default_factory=list)  # sorted, unique
