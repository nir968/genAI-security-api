import pytest


def _make_il_id(prefix8: str) -> str:
    """Append the correct check digit to an 8-digit prefix (IDs are never hardcoded)."""
    assert len(prefix8) == 8 and prefix8.isdigit()
    total = 0
    for position, char in enumerate(prefix8):
        product = int(char) * (1 if position % 2 == 0 else 2)
        total += product - 9 if product > 9 else product
    return prefix8 + str((10 - total % 10) % 10)


@pytest.fixture
def make_il_id():
    return _make_il_id
