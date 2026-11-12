"""Regex + validator based detectors, one per data type.

Every detector takes the text and returns a list of Finding objects. Findings
carry only offsets and a masked value, never the raw match.

Regexes are written to be linear-time: no nested or overlapping quantifiers,
bounded repetition where a bound is natural, and look-behinds that stop a
scan from restarting inside a token it has already rejected. The one
detector that would otherwise need a long open-ended scan (EMAIL) uses a
bounded pattern for the same reason.
"""
import base64
import bisect
import json
import re
from functools import lru_cache
from itertools import accumulate

from .models import Finding, confidence_rank
from .validators import iban_valid, israeli_id_valid, luhn_valid, shannon_entropy

# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------


def mask_credit_card(digits: str) -> str:
    return "****" + digits[-4:]


def mask_email(address: str) -> str:
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain}"


def mask_generic(data_type: str) -> str:
    return f"[REDACTED:{data_type}]"


# --------------------------------------------------------------------------
# CREDIT_CARD
# --------------------------------------------------------------------------

# Zero-width match at the start of every digit run: the look-ahead captures up
# to 19 digits, each optionally separated from the previous by ONE space or
# dash. Using a look-ahead lets a valid card still be found when it directly
# follows another failed candidate.
_CARD_RUN = re.compile(r"(?<!\d)(?=(\d(?:[ -]?\d){0,18}))")


_STRIP_SEPARATORS = str.maketrans("", "", " -")


@lru_cache(maxsize=4096)
def _best_card_window(run: str, digit_follows_run: bool):
    """Longest 13-19 digit prefix of `run` that passes Luhn.

    A window may only end at the end of a digit group (the digits between two
    separators), never in the middle of one. Returns (end_offset_in_run,
    digits) or None. Cached because adversarial input repeats the same run
    thousands of times.
    """
    groups = run.replace("-", " ").split(" ")
    # digit count after each group -> index of that group
    group_ends = {total: index for index, total in enumerate(accumulate(map(len, groups)))}
    total = max(group_ends)
    if total < 13:
        return None
    all_digits = run.translate(_STRIP_SEPARATORS)
    for count in range(total, 12, -1):
        if count == total:
            if digit_follows_run:
                continue  # the number is longer than 19 digits: not a card
        elif count not in group_ends:
            continue  # window would end in the middle of a digit group
        digits = all_digits[:count]
        if luhn_valid(digits) and len(set(digits)) > 1:
            # a run of one repeated digit (0000...) passes Luhn but is no card
            return count + group_ends[count], digits  # + one separator per group gap
    return None


def detect_credit_card(text: str) -> list:
    findings = []
    for match in _CARD_RUN.finditer(text):
        run = match.group(1)
        if len(run) < 13:
            continue
        base = match.start()
        after = base + len(run)
        digit_follows = after < len(text) and text[after].isdigit()
        best = _best_card_window(run, digit_follows)
        if best is None:
            continue
        end_offset, digits = best
        end = base + end_offset
        findings.append(
            Finding("CREDIT_CARD", base, end, "high", mask_credit_card(digits))
        )
    return findings


# --------------------------------------------------------------------------
# IL_ID
# --------------------------------------------------------------------------

_IL_ID = re.compile(r"(?<![A-Za-z0-9_])\d{9}(?![A-Za-z0-9_])")
_IL_ID_CONTEXT = re.compile(
    r"ת\.ז|ת\"ז|ת״ז|תעודת זהות|teudat zehut|id number|\bid\b|identity",
    re.IGNORECASE,
)
_CONTEXT_WINDOW = 30


def detect_il_id(text: str) -> list:
    findings = []
    for match in _IL_ID.finditer(text):
        if not israeli_id_valid(match.group()):
            continue
        before = text[max(0, match.start() - _CONTEXT_WINDOW):match.start()]
        confidence = "medium" if _IL_ID_CONTEXT.search(before) else "low"
        findings.append(
            Finding("IL_ID", match.start(), match.end(), confidence, mask_generic("IL_ID"))
        )
    return findings


# --------------------------------------------------------------------------
# IBAN
# --------------------------------------------------------------------------

# Total IBAN length per country (ISO 13616 registry). Candidates whose country
# code is not listed are ignored, which keeps random "ab12..." strings out.
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
    "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
    "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
    "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23,
    "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22,
    "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24,
    "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "TL": 23, "TN": 24,
    "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}

_IBAN_ANCHOR = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]{2})\d{2}")


def _ascii_alnum(char: str) -> bool:
    return char.isascii() and char.isalnum()


def detect_iban(text: str) -> list:
    findings = []
    for anchor in _IBAN_ANCHOR.finditer(text):
        total_length = IBAN_LENGTHS.get(anchor.group(1).upper())
        if total_length is None:
            continue
        # consume exactly the number of characters this country's IBAN has,
        # allowing single spaces between groups
        needed = total_length - 4
        pos = anchor.end()
        while needed and pos < len(text):
            char = text[pos]
            if _ascii_alnum(char):
                needed -= 1
                pos += 1
            elif (
                char == " "
                and pos + 1 < len(text)
                and _ascii_alnum(text[pos + 1])
            ):
                pos += 1
            else:
                break
        if needed or (pos < len(text) and _ascii_alnum(text[pos])):
            continue
        candidate = text[anchor.start():pos]
        if iban_valid(candidate):
            findings.append(
                Finding("IBAN", anchor.start(), pos, "high", mask_generic("IBAN"))
            )
    return findings


# --------------------------------------------------------------------------
# EMAIL and PHONE_IL
# --------------------------------------------------------------------------

# The look-behind means a scan only starts at the beginning of a local part,
# and every repetition is bounded, so work per position is constant.
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@"
    r"(?:[A-Za-z0-9-]{1,63}\.){1,10}[A-Za-z]{2,24}(?![A-Za-z0-9-])"
)


def detect_email(text: str) -> list:
    return [
        Finding("EMAIL", m.start(), m.end(), "medium", mask_email(m.group()))
        for m in _EMAIL.finditer(text)
    ]


_PHONE_IL = re.compile(
    r"(?<![\d+])(?:\+972[-\s]?|0)5\d[-\s]?\d{3}[-\s]?\d{4}(?!\d)"
)


def detect_phone_il(text: str) -> list:
    return [
        Finding("PHONE_IL", m.start(), m.end(), "medium", mask_generic("PHONE_IL"))
        for m in _PHONE_IL.finditer(text)
    ]


# --------------------------------------------------------------------------
# Provider secrets: AWS, GitHub, private keys, JWT
# --------------------------------------------------------------------------

_AWS_KEY = re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])")


def detect_aws_access_key(text: str) -> list:
    return [
        Finding("AWS_ACCESS_KEY", m.start(), m.end(), "high", mask_generic("AWS_ACCESS_KEY"))
        for m in _AWS_KEY.finditer(text)
    ]


_GITHUB_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_\w{82})(?![A-Za-z0-9_])"
)


def detect_github_token(text: str) -> list:
    return [
        Finding("GITHUB_TOKEN", m.start(), m.end(), "high", mask_generic("GITHUB_TOKEN"))
        for m in _GITHUB_TOKEN.finditer(text)
    ]


# The header/footer are matched as regexes (not literals) on purpose.
_PK_BEGIN = re.compile(r"(?:-{5})?BEGIN(?: [A-Z]{1,10}){0,3} PRIVATE KEY(?:-{5})?")
_PK_END = re.compile(r"(?:-{5})?END(?: [A-Z]{1,10}){0,3} PRIVATE KEY(?:-{5})?")


def detect_private_key(text: str) -> list:
    """Flag a private key block.

    The finding spans from the header to the matching footer so that the key
    body is redacted too, not just the header line. If there is no footer
    (truncated paste), it spans to the end of the text: over-redacting is the
    safe failure here. Scanning resumes after each block, so the work stays
    linear even for thousands of headers.
    """
    findings = []
    pos = 0
    while True:
        begin = _PK_BEGIN.search(text, pos)
        if begin is None:
            break
        footer = _PK_END.search(text, begin.end())
        end = footer.end() if footer else len(text)
        findings.append(
            Finding("PRIVATE_KEY", begin.start(), end, "high", mask_generic("PRIVATE_KEY"))
        )
        pos = end
        if pos >= len(text):
            break
    return findings


_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])"
)


def _jwt_header_has_alg(segment: str) -> bool:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except ValueError:  # includes binascii.Error and UnicodeDecodeError
        return False
    return isinstance(header, dict) and "alg" in header


def detect_jwt(text: str) -> list:
    return [
        Finding("JWT", m.start(), m.end(), "high", mask_generic("JWT"))
        for m in _JWT.finditer(text)
        if _jwt_header_has_alg(m.group(1))
    ]


# --------------------------------------------------------------------------
# CREDENTIAL_ASSIGNMENT and HIGH_ENTROPY_SECRET
# --------------------------------------------------------------------------

_CREDENTIAL = re.compile(
    r"\b(?:password|passwd|pwd|secret|api[_ -]?key|token)\b"
    r"[ \t]{0,3}(?:[:=]|[ \t]+is[ \t]+)[ \t]{0,3}(\S{4,})",
    re.IGNORECASE,
)


def detect_credential_assignment(text: str) -> list:
    """`password: x`, `api_key=x`, `my secret is x`. The finding covers only
    the value, so the redacted text still shows which field was removed."""
    return [
        Finding(
            "CREDENTIAL_ASSIGNMENT",
            m.start(1),
            m.end(1),
            "high",
            mask_generic("CREDENTIAL_ASSIGNMENT"),
        )
        for m in _CREDENTIAL.finditer(text)
    ]


_HIGH_ENTROPY_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{20,}")
ENTROPY_THRESHOLD = 4.0


def detect_high_entropy_secret(text: str, existing=()) -> list:
    """Long random-looking tokens that no specific detector explained."""
    taken = _IntervalSet.merged((f.start, f.end) for f in existing)

    findings = []
    for match in _HIGH_ENTROPY_TOKEN.finditer(text):
        token = match.group()
        if not (any(c.isalpha() for c in token) and any(c.isdigit() for c in token)):
            continue
        if taken.overlaps(match.start(), match.end()):
            continue
        if shannon_entropy(token) >= ENTROPY_THRESHOLD:
            findings.append(
                Finding(
                    "HIGH_ENTROPY_SECRET",
                    match.start(),
                    match.end(),
                    "low",
                    mask_generic("HIGH_ENTROPY_SECRET"),
                )
            )
    return findings


# --------------------------------------------------------------------------
# Running everything and resolving overlaps
# --------------------------------------------------------------------------


class _IntervalSet:
    """Disjoint half-open intervals with O(log n) overlap checks."""

    def __init__(self):
        self._starts = []
        self._ends = []

    @classmethod
    def merged(cls, spans):
        """Build from possibly-overlapping spans by merging them first."""
        result = cls()
        for start, end in sorted(spans):
            if result._ends and start < result._ends[-1]:
                result._ends[-1] = max(result._ends[-1], end)
            else:
                result.add(start, end)
        return result

    def overlaps(self, start: int, end: int) -> bool:
        i = bisect.bisect_left(self._starts, end)  # intervals starting before `end`
        return i > 0 and self._ends[i - 1] > start

    def add(self, start: int, end: int) -> None:
        i = bisect.bisect_left(self._starts, start)
        self._starts.insert(i, start)
        self._ends.insert(i, end)


def resolve_overlaps(findings) -> list:
    """Keep the higher-confidence finding, then the longer one, on overlap."""
    ordered = sorted(
        findings,
        key=lambda f: (-confidence_rank(f.confidence), -(f.end - f.start), f.start),
    )
    taken = _IntervalSet()
    kept = []
    for finding in ordered:
        if not taken.overlaps(finding.start, finding.end):
            taken.add(finding.start, finding.end)
            kept.append(finding)
    return sorted(kept, key=lambda f: (f.start, f.end))


DETECTORS = (
    detect_credit_card,
    detect_il_id,
    detect_iban,
    detect_email,
    detect_phone_il,
    detect_aws_access_key,
    detect_github_token,
    detect_private_key,
    detect_jwt,
    detect_credential_assignment,
)


def run_detectors(text: str) -> list:
    """Run every detector and return non-overlapping findings, in text order."""
    findings = []
    for detector in DETECTORS:
        findings.extend(detector(text))
    # entropy runs last: it skips anything another detector already explained
    findings.extend(detect_high_entropy_secret(text, findings))
    return resolve_overlaps(findings)
