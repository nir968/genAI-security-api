import base64
import dataclasses
import json

import pytest

from dlp import detectors
from dlp.engine import mask_text, scan

CARD = "4111 1111 1111 1111"
AWS = "AKIAIOSFODNN7EXAMPLE"
GITHUB = "ghp_" + "a" * 36
IBAN = "IL620108000000099999999"


def jwt_token():
    def seg(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return ".".join([seg({"alg": "HS256", "typ": "JWT"}), seg({"sub": "someone"}), "c2lnbmF0dXJl"])


def private_key():
    return "-----" + "BEGIN PRIVATE KEY" + "-----\nQUJDREVGR0g=\n-----" + "END PRIVATE KEY" + "-----"


def masked(finding_text):
    (finding,) = detectors.run_detectors(finding_text)
    return finding.masked_value


def test_credit_card_keeps_only_last_four_digits():
    assert masked(CARD) == "****1111"
    assert masked("5500-0000-0000-0004") == "****0004"


def test_email_keeps_first_character_and_domain():
    assert masked("dana@example.com") == "d***@example.com"


@pytest.mark.parametrize(
    "text, data_type",
    [
        (IBAN, "IBAN"),
        (AWS, "AWS_ACCESS_KEY"),
        (GITHUB, "GITHUB_TOKEN"),
        ("050-1234567", "PHONE_IL"),
        (private_key(), "PRIVATE_KEY"),
        (jwt_token(), "JWT"),
    ],
)
def test_other_types_are_fully_redacted(text, data_type):
    assert masked(text) == f"[REDACTED:{data_type}]"


def test_credential_value_is_redacted_but_the_field_name_stays():
    assert mask_text("password: hunter2", detectors.run_detectors("password: hunter2")) == (
        "password: [REDACTED:CREDENTIAL_ASSIGNMENT]"
    )


@pytest.mark.parametrize(
    "raw",
    [CARD, IBAN, AWS, GITHUB, "password: hunter2", jwt_token(), private_key()],
    ids=["card", "iban", "aws", "github", "credential", "jwt", "private-key"],
)
def test_no_raw_value_in_any_finding_or_scan_field(raw):
    result = scan(f"here: {raw} end")
    assert result.findings
    secret = raw.split(": ")[-1] if raw.startswith("password") else raw
    for field in dataclasses.fields(result):
        assert secret not in repr(getattr(result, field.name)), field.name
    for finding in result.findings:
        for field in dataclasses.fields(finding):
            assert secret not in str(getattr(finding, field.name)), field.name


def test_finding_has_no_field_for_the_raw_value():
    names = {field.name for field in dataclasses.fields(detectors.Finding)}
    assert names == {"data_type", "start", "end", "confidence", "masked_value"}


def test_alert_only_text_keeps_the_value_but_findings_never_hold_it():
    result = scan("write to dana@example.com")
    assert result.action == "alert"
    assert "dana@example.com" in result.redacted_text  # alerts do not redact
    assert all("dana@example.com" not in repr(f) for f in result.findings)
