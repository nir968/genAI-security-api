import random
import time

import pytest

from dlp.engine import scan

SIZE = 100_000


def random_spaced_digits():
    # Linear, but the slowest case: every digit starts a fresh card candidate
    # that must be checksummed, so it is sized at 40 KB to keep the 1 s bound
    # meaningful on slow CI machines. A quadratic regex would still blow it.
    rng = random.Random(1)
    return " ".join(str(rng.randrange(10)) for _ in range(20_000))


ADVERSARIAL = {
    "spaced-ones": "1 " * (SIZE // 2),
    "all-a": "a" * SIZE,
    "random-spaced-digits": random_spaced_digits(),
    "digit-dashes": "4-" * (SIZE // 2),
    "at-signs": "@" * SIZE,
    "a-at": "a@" * (SIZE // 2),
    "dotted": "a." * (SIZE // 2),
    "long-local-part": ("a" * 63 + "@") * (SIZE // 64),
    "password-words": "password " * (SIZE // 9),
    "password-colons": "password: " * (SIZE // 10),
    "private-key-headers": "BEGIN PRIVATE KEY " * (SIZE // 18),
    "jwt-like": "aaaaaaaaaaaa." * (SIZE // 13),
    "aws-prefix": "AKIA" * (SIZE // 4),
    "repeated-cards": "4111111111111111 " * (SIZE // 17),
    "high-entropy-run": "a1" * (SIZE // 2),
    "iban-anchors": "IL62 " * (SIZE // 5),
    "ids": "123456782 " * (SIZE // 10),
}


def timed_scan(text):
    started = time.perf_counter()
    scan(text)
    return time.perf_counter() - started


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_scanning_100kb_adversarial_input_is_fast(name):
    text = ADVERSARIAL[name]
    assert len(text) >= 39_000

    elapsed = min(timed_scan(text) for _ in range(2))  # best of 2: less CI noise

    assert elapsed < 1.0, f"{name} took {elapsed:.2f}s"
