import copy

import pytest
import yaml

from dlp.engine import mask_text, scan
from dlp.policy import DEFAULT_POLICY_PATH, parse_policy

CARD = "4111 1111 1111 1111"
IBAN = "IL620108000000099999999"
EMAIL = "dana@example.com"


def custom_policy(**overrides):
    with open(DEFAULT_POLICY_PATH, encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    document = copy.deepcopy(document)
    for data_type, changes in overrides.items():
        document["data_types"][data_type].update(changes)
    return parse_policy(document)


def test_clean_text_is_allowed_unchanged():
    result = scan("What is the capital of France?")
    assert (result.action, result.risk_score) == ("allow", 10)
    assert result.redacted_text == "What is the capital of France?"
    assert result.findings == [] and result.data_types == []


def test_empty_text_is_allowed():
    assert scan("").action == "allow"


def test_single_actions():
    assert scan(f"card {CARD}").action == "block"
    assert scan(f"iban {IBAN}").action == "redact"
    assert scan(f"mail {EMAIL}").action == "alert"


def test_most_severe_action_wins():
    assert scan(f"{EMAIL} {IBAN}").action == "redact"
    assert scan(f"{EMAIL} {IBAN} {CARD}").action == "block"
    assert scan(f"{EMAIL} {CARD}").action == "block"


def test_risk_score_is_the_maximum():
    assert scan(f"{EMAIL}").risk_score == 30
    assert scan(f"{EMAIL} {IBAN}").risk_score == 60
    assert scan(f"{EMAIL} {IBAN} {CARD}").risk_score == 80
    assert scan("password: hunter2").risk_score == 90


def test_data_types_are_sorted_and_unique():
    result = scan(f"{IBAN} {CARD} {CARD} {EMAIL}")
    assert result.data_types == ["CREDIT_CARD", "EMAIL", "IBAN"]


def test_multiple_findings_are_redacted_at_the_right_offsets():
    text = f"A {IBAN} B {CARD} C {EMAIL} D"
    result = scan(text)
    assert result.redacted_text == f"A [REDACTED:IBAN] B ****1111 C {EMAIL} D"
    assert mask_text(text, result.findings) == (
        "A [REDACTED:IBAN] B ****1111 C d***@example.com D"
    )


def test_adjacent_findings_do_not_corrupt_each_other():
    result = scan(f"{CARD},{IBAN}")
    assert result.redacted_text == "****1111,[REDACTED:IBAN]"


def test_block_findings_are_masked_in_the_redacted_text():
    result = scan(f"pay with {CARD} now")
    assert result.action == "block"
    assert result.redacted_text == "pay with ****1111 now"


def test_output_direction_turns_block_into_redact():
    result = scan(f"your card is {CARD}", direction="output")
    assert result.action == "redact"
    assert result.redacted_text == "your card is ****1111"
    assert result.risk_score == 80


def test_output_direction_keeps_alerts():
    assert scan(f"mail {EMAIL}", direction="output").action == "alert"


def test_il_id_is_ignored_without_context_and_redacted_with_it(make_il_id):
    number = make_il_id("31415926")
    assert scan(f"number {number}").action == "allow"
    result = scan(f"teudat zehut {number}")
    assert result.action == "redact"
    assert result.redacted_text == "teudat zehut [REDACTED:IL_ID]"


def test_forgot_password_question_is_clean():
    assert scan("I forgot my password, how do I reset it?").action == "allow"


def test_allow_rule_drops_the_finding():
    policy = custom_policy(CREDIT_CARD={"action": "allow"})
    result = scan(CARD, policy=policy)
    assert result.action == "allow" and result.findings == []


def test_min_confidence_filters_findings():
    policy = custom_policy(IL_ID={"min_confidence": "low"})
    assert scan("number 314159265", policy=policy).action == "allow"  # invalid id
    policy_high = custom_policy(EMAIL={"min_confidence": "high"})
    assert scan(EMAIL, policy=policy_high).action == "allow"


def test_invalid_direction_is_rejected():
    with pytest.raises(ValueError):
        scan("x", direction="sideways")
