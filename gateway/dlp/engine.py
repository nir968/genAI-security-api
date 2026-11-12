"""The scan engine: detectors + policy -> a single ScanResult."""
import os

from .detectors import run_detectors
from .models import ScanResult, action_severity, confidence_rank
from .policy import Policy, load_policy

DIRECTIONS = ("input", "output")

_policy = None


def init_policy(path=None) -> Policy:
    """Load and validate the policy (call at startup; raises PolicyError)."""
    global _policy
    _policy = load_policy(path or os.environ.get("DLP_POLICY_PATH") or None)
    return _policy


def get_policy() -> Policy:
    return _policy if _policy is not None else init_policy()


def reset_policy() -> None:
    """Forget the loaded policy (used by tests)."""
    global _policy
    _policy = None


def mask_text(text: str, findings) -> str:
    """Replace every finding with its masked value, right to left so earlier
    offsets stay valid."""
    for finding in sorted(findings, key=lambda f: f.start, reverse=True):
        text = text[:finding.start] + finding.masked_value + text[finding.end:]
    return text


def scan(text: str, direction: str = "input", policy: Policy = None) -> ScanResult:
    """Scan `text` and decide what to do with it.

    Findings below their type's min_confidence, or whose rule is "allow", are
    dropped. The result's action is the most severe among the remaining
    findings and its risk score the highest. `redacted_text` masks the
    findings whose action is redact or block; alert-only findings stay visible.
    """
    if direction not in DIRECTIONS:
        raise ValueError(f"direction must be one of {DIRECTIONS}, got {direction!r}")
    policy = policy or get_policy()

    kept = []
    actions = {}
    for finding in run_detectors(text):
        rule = policy.rules[finding.data_type]
        if confidence_rank(finding.confidence) < confidence_rank(rule.min_confidence):
            continue
        action = policy.action_for(finding.data_type, direction)
        if action == "allow":
            continue
        kept.append(finding)
        actions[finding] = action

    if not kept:
        return ScanResult([], "allow", 10, text, [])

    action = max((actions[f] for f in kept), key=action_severity)
    risk = max(policy.rules[f.data_type].risk_score for f in kept)
    to_mask = [f for f in kept if actions[f] in ("redact", "block")]
    return ScanResult(
        findings=kept,
        action=action,
        risk_score=risk,
        redacted_text=mask_text(text, to_mask),
        data_types=sorted({f.data_type for f in kept}),
    )
