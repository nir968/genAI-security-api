import base64
import json
import random
import string

import pytest

from dlp import detectors
from dlp.models import Finding
from dlp.validators import shannon_entropy


def spans(findings, text):
    """(type, matched-text) pairs, for readable assertions."""
    return [(f.data_type, text[f.start:f.end]) for f in findings]


def b64url(data: dict) -> str:
    raw = json.dumps(data).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# ---------------------------------------------------------------- CREDIT_CARD


@pytest.mark.parametrize(
    "number",
    [
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "4111111111111111",
        "5500 0000 0000 0004",
        "4111 111111 111111",  # irregular grouping, single separators
    ],
)
def test_credit_card_true_positives(number):
    text = f"my card is {number}, thanks"
    found = detectors.detect_credit_card(text)
    assert spans(found, text) == [("CREDIT_CARD", number)]
    assert found[0].confidence == "high"


@pytest.mark.parametrize(
    "text",
    [
        "4111 1111 1111 1112",  # fails Luhn
        "0000000000000000",  # passes Luhn but is not a card
        "411111111111",  # 12 digits
        "41111111111111111111",  # 20 digits
        "4111  1111  1111  1111",  # double separators
        "no digits here",
        "",
    ],
)
def test_credit_card_true_negatives(text):
    assert detectors.detect_credit_card(text) == []


def test_credit_card_found_after_unrelated_digits():
    # the leading "12 34" may itself combine with the card into a longer
    # Luhn-valid candidate, so only require the real card to be covered
    text = "ref 12 34 4111 1111 1111 1111"
    found = spans(detectors.detect_credit_card(text), text)
    assert any(t.endswith("4111 1111 1111 1111") for _, t in found)
    assert [x.data_type for x in detectors.run_detectors(text)] == ["CREDIT_CARD"]


def test_two_cards_in_one_text():
    text = "4111 1111 1111 1111 and 5500 0000 0000 0004"
    assert len(detectors.detect_credit_card(text)) == 2


# --------------------------------------------------------------------- IL_ID


def test_il_id_without_context_is_low_confidence(make_il_id):
    number = make_il_id("31415926")
    found = detectors.detect_il_id(f"number {number} here")
    assert [f.confidence for f in found] == ["low"]


@pytest.mark.parametrize(
    "context",
    ["ת.ז", 'ת"ז', "ת״ז", "תעודת זהות", "teudat zehut", "ID number", "ID", "identity"],
)
def test_il_id_with_context_is_medium_confidence(make_il_id, context):
    number = make_il_id("27182818")
    text = f"{context}: {number}"
    found = detectors.detect_il_id(text)
    assert [(f.confidence, text[f.start:f.end]) for f in found] == [("medium", number)]


def test_il_id_context_must_be_within_30_chars_before(make_il_id):
    number = make_il_id("27182818")
    near = detectors.detect_il_id("id " + "x" * 20 + " " + number)
    far = detectors.detect_il_id("id " + "x" * 40 + " " + number)
    assert near[0].confidence == "medium"
    assert far[0].confidence == "low"


def test_il_id_context_word_is_not_matched_inside_other_words(make_il_id):
    number = make_il_id("27182818")
    assert detectors.detect_il_id(f"valid {number}")[0].confidence == "low"


def test_il_id_context_only_counts_text_before_the_number(make_il_id):
    number = make_il_id("27182818")
    assert detectors.detect_il_id(f"{number} id")[0].confidence == "low"


def test_il_id_rejects_bad_check_digit_length_and_word_boundaries(make_il_id):
    valid = make_il_id("31415926")
    wrong = valid[:-1] + str((int(valid[-1]) + 1) % 10)
    assert detectors.detect_il_id(f"id {wrong}") == []
    assert detectors.detect_il_id(f"id {valid}0") == []  # 10 digits
    assert detectors.detect_il_id(f"id {valid[:-1]}") == []  # 8 digits
    assert detectors.detect_il_id(f"id x{valid}") == []
    assert detectors.detect_il_id(f"id {valid}x") == []


# ---------------------------------------------------------------------- IBAN


@pytest.mark.parametrize(
    "iban",
    [
        "IL620108000000099999999",
        "IL62 0108 0000 0009 9999 999",
        "il620108000000099999999",
        "GB82 WEST 1234 5698 7654 32",
    ],
)
def test_iban_true_positives(iban):
    text = f"send it to {iban} please"
    found = detectors.detect_iban(text)
    assert spans(found, text) == [("IBAN", iban)]
    assert found[0].confidence == "high"


def test_iban_followed_directly_by_a_word_is_still_found():
    text = "IL620108000000099999999 and more words"
    assert spans(detectors.detect_iban(text), text) == [("IBAN", "IL620108000000099999999")]


@pytest.mark.parametrize(
    "text",
    [
        "IL630108000000099999999",  # wrong check digits
        "ZZ620108000000099999999",  # unknown country
        "IL62010800000009999999",  # too short
        "IL6201080000000999999999",  # too long
        "xIL620108000000099999999",  # inside a word
        "IL62  0108 0000 0009 9999 999",  # double space
        "just some text",
    ],
)
def test_iban_true_negatives(text):
    assert detectors.detect_iban(text) == []


# ------------------------------------------------------------ EMAIL / PHONE_IL


@pytest.mark.parametrize(
    "address", ["dana@example.com", "first.last+tag@mail.example.co.il", "A_B-1@x-y.org"]
)
def test_email_true_positives(address):
    text = f"write to {address}."
    found = detectors.detect_email(text)
    assert spans(found, text) == [("EMAIL", address)]
    assert found[0].confidence == "medium"


@pytest.mark.parametrize("text", ["a@b", "@example.com", "dana@example", "dana at example.com"])
def test_email_true_negatives(text):
    assert detectors.detect_email(text) == []


@pytest.mark.parametrize(
    "number",
    ["050-1234567", "0501234567", "050 123 4567", "+972 50-123-4567", "+972501234567", "052-123-4567"],
)
def test_phone_il_true_positives(number):
    text = f"call {number} now"
    found = detectors.detect_phone_il(text)
    assert spans(found, text) == [("PHONE_IL", number)]


@pytest.mark.parametrize("text", ["0601234567", "050123456", "05012345678", "x 1050-1234567"])
def test_phone_il_true_negatives(text):
    assert detectors.detect_phone_il(text) == []


# ------------------------------------------------------------ provider secrets


def test_aws_access_key():
    text = "key AKIAIOSFODNN7EXAMPLE here"
    assert spans(detectors.detect_aws_access_key(text), text) == [
        ("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
    ]
    temporary = "ASIA" + "B" * 16
    assert len(detectors.detect_aws_access_key(temporary)) == 1


@pytest.mark.parametrize(
    "text", ["AKIA123", "akiaiosfodnn7example", "AKIA" + "A" * 17, "xAKIA" + "A" * 16]
)
def test_aws_access_key_negatives(text):
    assert detectors.detect_aws_access_key(text) == []


@pytest.mark.parametrize("kind", ["p", "o", "u", "s", "r"])
def test_github_token_prefixes(kind):
    token = f"gh{kind}_" + "a" * 36  # built at runtime: no secret-like literal
    text = f"token {token} end"
    assert spans(detectors.detect_github_token(text), text) == [("GITHUB_TOKEN", token)]


def test_github_fine_grained_token():
    token = "github_pat_" + "A1" * 41
    assert len(detectors.detect_github_token(f"x {token}")) == 1


@pytest.mark.parametrize(
    "text",
    ["ghp_" + "a" * 35, "ghp_" + "a" * 37, "ghx_" + "a" * 36, "github_pat_" + "a" * 10],
)
def test_github_token_negatives(text):
    assert detectors.detect_github_token(text) == []


def pem(label="RSA ", body="QUJD" * 4):
    header = "-----" + "BEGIN " + label + "PRIVATE KEY" + "-----"
    footer = "-----" + "END " + label + "PRIVATE KEY" + "-----"
    return header, body, footer


def test_private_key_spans_header_to_footer():
    header, body, footer = pem()
    block = f"{header}\n{body}\n{footer}"
    text = f"here:\n{block}\nthanks"
    found = detectors.detect_private_key(text)
    assert spans(found, text) == [("PRIVATE_KEY", block)]


def test_private_key_without_footer_spans_to_end_of_text():
    header, body, _ = pem(label="")
    text = f"x {header}\n{body}"
    found = detectors.detect_private_key(text)
    assert spans(found, text) == [("PRIVATE_KEY", f"{header}\n{body}")]


def test_private_key_negatives():
    assert detectors.detect_private_key("begin private key rotation") == []
    assert detectors.detect_private_key("public key material") == []


def test_jwt_detects_header_with_alg():
    token = ".".join([b64url({"alg": "HS256", "typ": "JWT"}), b64url({"sub": "x" * 8}), "c2lnbmF0dXJl"])
    text = f"Authorization: Bearer {token}"
    assert spans(detectors.detect_jwt(text), text) == [("JWT", token)]


def test_jwt_negatives():
    no_alg = ".".join([b64url({"typ": "JWT", "x": "y" * 5}), "cGF5bG9hZA", "c2ln"])
    assert detectors.detect_jwt(no_alg) == []
    assert detectors.detect_jwt("aaaaaaaaaaaa.bbbbbbbbbb.cccccccccc") == []
    assert detectors.detect_jwt("version 1.2.3") == []
    not_json = ".".join([base64.urlsafe_b64encode(b"\xff\xfe\xfd" * 4).decode(), "aa", "bb"])
    assert detectors.detect_jwt(not_json) == []


# ------------------------------------------------------ CREDENTIAL_ASSIGNMENT


@pytest.mark.parametrize(
    "text, value",
    [
        ("password: hunter2", "hunter2"),
        ("my password is 1234", "1234"),
        ("API_KEY=abcd1234", "abcd1234"),
        ("api key: sk-test-value", "sk-test-value"),
        ("PWD = secret99", "secret99"),
        ("token: abcd", "abcd"),
        ("passwd:x1y2z3", "x1y2z3"),
        ("the secret is Tr0ub4dor", "Tr0ub4dor"),
    ],
)
def test_credential_assignment_true_positives(text, value):
    found = detectors.detect_credential_assignment(text)
    assert spans(found, text) == [("CREDENTIAL_ASSIGNMENT", value)]
    assert found[0].confidence == "high"


@pytest.mark.parametrize(
    "text",
    [
        "I forgot my password, how do I reset it?",
        "password: abc",  # value shorter than 4
        "reset your password",
        "passwords: hunter2",
        "tokenizer = hunter2",
        "",
    ],
)
def test_credential_assignment_true_negatives(text):
    assert detectors.detect_credential_assignment(text) == []


# ---------------------------------------------------------- HIGH_ENTROPY_SECRET


def random_token(length=32, seed=7):
    rng = random.Random(seed)
    alphabet = string.ascii_letters + string.digits
    while True:
        token = "".join(rng.choice(alphabet) for _ in range(length))
        if any(c.isdigit() for c in token) and any(c.isalpha() for c in token):
            return token


def test_high_entropy_secret_true_positive():
    token = random_token()
    assert shannon_entropy(token) >= 4.0
    text = f"use {token} for it"
    found = detectors.detect_high_entropy_secret(text)
    assert spans(found, text) == [("HIGH_ENTROPY_SECRET", token)]
    assert found[0].confidence == "low"


@pytest.mark.parametrize(
    "text",
    [
        "a" * 30,  # no digits
        "abcdefghijklmnopqrstuvwxyz",  # no digits
        "1234567890123456789012345",  # no letters
        "ab12" * 8,  # low entropy
        "short1Ab",
    ],
)
def test_high_entropy_secret_true_negatives(text):
    assert detectors.detect_high_entropy_secret(text) == []


def test_high_entropy_skips_text_covered_by_another_finding():
    token = random_token()
    covered = [Finding("CREDENTIAL_ASSIGNMENT", 0, len(token), "high", "[x]")]
    assert detectors.detect_high_entropy_secret(token, covered) == []
    assert detectors.detect_high_entropy_secret(token, []) != []


# ---------------------------------------------------------- overlap resolution


def f(kind, start, end, confidence):
    return Finding(kind, start, end, confidence, "[m]")


def test_overlap_keeps_higher_confidence():
    kept = detectors.resolve_overlaps([f("A", 0, 20, "low"), f("B", 5, 10, "high")])
    assert [x.data_type for x in kept] == ["B"]


def test_overlap_keeps_longer_on_equal_confidence():
    kept = detectors.resolve_overlaps([f("A", 0, 5, "high"), f("B", 3, 12, "high")])
    assert [x.data_type for x in kept] == ["B"]


def test_non_overlapping_findings_are_all_kept_in_text_order():
    kept = detectors.resolve_overlaps([f("B", 10, 12, "low"), f("A", 0, 5, "high")])
    assert [x.data_type for x in kept] == ["A", "B"]


def test_run_detectors_card_wins_over_il_id_inside_it():
    text = "4111 1111 1111 1111"
    assert [x.data_type for x in detectors.run_detectors(text)] == ["CREDIT_CARD"]


def test_run_detectors_does_not_report_entropy_for_a_github_token():
    token = "ghp_" + random_token(36)
    assert [x.data_type for x in detectors.run_detectors(token)] == ["GITHUB_TOKEN"]
