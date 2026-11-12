"""Pure validation helpers used to cut false positives from the regex detectors."""
import math
from collections import Counter


def _is_ascii_digits(text: str) -> bool:
    return bool(text) and text.isascii() and text.isdigit()


# Maps a digit d to the digit of (2*d, minus 9 if that exceeds 9): the Luhn
# "doubling" step expressed as a byte translation so it runs at C speed.
_LUHN_DOUBLE = bytes.maketrans(b"0123456789", b"0246813579")


def luhn_valid(digits: str) -> bool:
    """Luhn (mod 10) checksum, as used by payment card numbers.

    Starting from the rightmost digit and moving left, every second digit is
    doubled (subtracting 9 when the result exceeds 9). The number is valid when
    the sum of all digits is a multiple of 10. Empty or non-digit input is
    invalid.

    Implementation note: the digits are handled as ASCII bytes. Slicing the
    reversed bytes with a step of 2 separates the doubled positions from the
    others, and `bytes.translate` applies the doubling, which keeps this fast
    enough to run on every candidate in a large text.
    """
    if not _is_ascii_digits(digits):
        return False
    reversed_digits = digits.encode("ascii")[::-1]
    kept = reversed_digits[0::2]
    doubled = reversed_digits[1::2].translate(_LUHN_DOUBLE)
    # every byte is the digit's value + 48 ("0" is 48)
    return (sum(kept) + sum(doubled) - 48 * len(reversed_digits)) % 10 == 0


def israeli_id_valid(digits: str) -> bool:
    """Check digit of an Israeli ID number (Teudat Zehut).

    The number is left-padded with zeros to 9 digits (5-9 digits accepted).
    Digits are multiplied alternately by 1 and 2, starting with 1 on the
    leftmost digit; any two-digit product is reduced to the sum of its digits
    (equivalently, minus 9). The ID is valid when the total is a multiple of
    10. The all-zero number passes the arithmetic but is not a real ID, so it
    is rejected.
    """
    if not _is_ascii_digits(digits) or not 5 <= len(digits) <= 9:
        return False
    padded = digits.zfill(9)
    if set(padded) == {"0"}:
        return False
    total = 0
    for position, char in enumerate(padded):
        product = (ord(char) - 48) * (1 if position % 2 == 0 else 2)
        if product > 9:
            product -= 9
        total += product
    return total % 10 == 0


def iban_valid(text: str) -> bool:
    """ISO 13616 IBAN check using the mod-97 algorithm (ISO 7064).

    Spaces are ignored. The first four characters (country code and check
    digits) are moved to the end, every letter is replaced by its position
    number (A=10 ... Z=35), and the resulting integer must leave remainder 1
    when divided by 97. Length must be 15-34 characters.
    """
    compact = text.replace(" ", "").upper()
    if not 15 <= len(compact) <= 34:
        return False
    if not (compact.isascii() and compact.isalnum()):
        return False
    if not (compact[:2].isalpha() and compact[2:4].isdigit()):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(char, 36)) for char in rearranged)
    return int(numeric) % 97 == 1


def shannon_entropy(text: str) -> float:
    """Shannon entropy of a string in bits per character.

    H = -sum(p * log2(p)) over the frequency p of each distinct character.
    Random keys score high (a 20+ character random token is usually above
    4 bits); natural words and repeated characters score low. The empty
    string has entropy 0.
    """
    if not text:
        return 0.0
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(text).values()
    )
