import math

import pytest

from dlp.validators import iban_valid, israeli_id_valid, luhn_valid, shannon_entropy


@pytest.mark.parametrize("digits", ["4111111111111111", "5500000000000004", "79927398713"])
def test_luhn_accepts_valid_numbers(digits):
    assert luhn_valid(digits)


@pytest.mark.parametrize(
    "digits", ["4111111111111112", "79927398710", "", "41111111111111x1", "４１１１"]
)
def test_luhn_rejects_invalid_input(digits):
    assert not luhn_valid(digits)


@pytest.mark.parametrize("prefix", ["00000001", "12345678", "31415926", "98765432", "00012345"])
def test_israeli_id_accepts_generated_valid_numbers(make_il_id, prefix):
    assert israeli_id_valid(make_il_id(prefix))


def test_israeli_id_rejects_wrong_check_digit(make_il_id):
    valid = make_il_id("12345678")
    wrong = valid[:-1] + str((int(valid[-1]) + 1) % 10)
    assert not israeli_id_valid(wrong)


def test_israeli_id_accepts_short_numbers_left_padded(make_il_id):
    full = make_il_id("00001234")  # 000012348-style: 5 significant digits
    assert israeli_id_valid(full.lstrip("0"))
    assert israeli_id_valid(full)


@pytest.mark.parametrize("digits", ["", "1234", "1234567890", "12345678a", "000000000"])
def test_israeli_id_rejects_bad_length_or_content(digits):
    assert not israeli_id_valid(digits)


@pytest.mark.parametrize(
    "iban",
    [
        "IL620108000000099999999",  # official example
        "IL62 0108 0000 0009 9999 999",
        "il620108000000099999999",
        "GB82WEST12345698765432",
        "DE89370400440532013000",
    ],
)
def test_iban_accepts_valid_numbers(iban):
    assert iban_valid(iban)


@pytest.mark.parametrize(
    "iban",
    [
        "IL630108000000099999999",  # wrong check digits
        "IL62010800000009999999",  # too short for mod-97 to pass
        "IL62-0108-0000-0009-9999-999",
        "1262010800000009999999",
        "",
        "IL62",
    ],
)
def test_iban_rejects_invalid_numbers(iban):
    assert not iban_valid(iban)


def test_entropy_of_empty_and_constant_strings_is_zero():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_of_uniform_alphabet_is_log2_of_size():
    assert shannon_entropy("abcd" * 10) == pytest.approx(2.0)
    assert shannon_entropy("abcdefgh") == pytest.approx(math.log2(8))


def test_entropy_orders_random_above_natural_text():
    assert shannon_entropy("wJalrXUtnFEMI7K9mPqR2sTvZ4yB") > shannon_entropy(
        "thethethethethethethe"
    )
