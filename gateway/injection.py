"""Heuristics for *indirect* prompt injection in untrusted content.

Untrusted content is anything an AI agent reads but did not write: tool
results (a document, a web page) and tool descriptions supplied by an MCP
server. An attacker hides instructions for the model in that content, hoping
the model obeys them as if the user had written them.

This is deliberately separate from ``detection.analyze_prompt`` (the direct
prompt check behind /inspect), which is unchanged.

``analyze(text)`` looks for three families of signals and returns their spans:

* ``ai_instruction``  - text addressed to an AI ("AI assistant", "ignore
  previous instructions", "do not tell the user", "you must now", an
  ``<IMPORTANT>`` tag);
* ``hidden_content``  - things a human reader does not see: HTML comments,
  zero-width characters, Unicode tag characters, bidi controls;
* ``exfiltration``    - a send / email / forward / upload verb followed by "to"
  and an e-mail address or URL (or a BCC address).

It is a set of heuristics, not a classifier: a paraphrase it has no pattern for
gets through, and ordinary text can match (an HTML comment, "send mail to
help@..."). Callers should treat a detection as "do not trust this", not as
proof of an attack.

Everything here is a pure function. Regexes use bounded quantifiers or simple
alternations, and the only scans of the whole text are ``str.find`` loops and
single passes, so cost grows linearly with the input.
"""
import re
import unicodedata
from bisect import bisect_left
from dataclasses import dataclass

KIND_AI_INSTRUCTION = "ai_instruction"
KIND_HIDDEN_CONTENT = "hidden_content"
KIND_EXFILTRATION = "exfiltration"

REMOVED_MARKER = "[removed by security proxy: possible prompt injection]"

# How far (in characters) a sending verb and its target may be apart.
EXFIL_WINDOW = 160
# How far a flagged instruction is widened to take its whole sentence with it.
EXPAND_LIMIT = 300


@dataclass(frozen=True)
class Signal:
    """One suspicious span. Offsets index the *original* text."""

    kind: str
    name: str
    start: int
    end: int

    def to_dict(self) -> dict:
        return {"kind": self.kind, "name": self.name, "start": self.start, "end": self.end}


@dataclass(frozen=True)
class InjectionResult:
    signals: tuple
    sanitized_text: str

    @property
    def detected(self) -> bool:
        return bool(self.signals)

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "signals": [signal.to_dict() for signal in self.signals],
            "sanitized_text": self.sanitized_text,
        }


# --------------------------------------------------------------------------
# invisible characters
# --------------------------------------------------------------------------

# Never legitimate in text an agent should act on.
_ALWAYS_HIDDEN = {
    "​": "zero_width_characters",  # zero width space
    "⁠": "zero_width_characters",  # word joiner
    "᠎": "zero_width_characters",  # mongolian vowel separator
    "﻿": "zero_width_characters",  # zero width no-break space / BOM
    **{chr(c): "bidi_control_characters" for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))},
}
# ZWNJ / ZWJ have real uses (emoji sequences, Persian, Indic scripts), so they
# only count when they sit between two ASCII letters or digits: the usual way
# to break up an English word.
_JOINERS = "‌‍"
# Everything the folding step removes before pattern matching.
_FOLD_AWAY = set(_ALWAYS_HIDDEN) | set(_JOINERS) | {"­", "‎", "‏", "⁡", "⁢", "⁣", "⁤"}


def _is_tag_char(char: str) -> bool:
    return 0xE0000 <= ord(char) <= 0xE007F


def _is_ascii_alnum(char: str) -> bool:
    return char.isascii() and char.isalnum()


def _hidden_char_signals(text: str) -> list:
    """Runs of hidden characters, one signal per run."""
    signals = []
    run_start = run_name = None
    last = -2
    for index, char in enumerate(text):
        name = None
        if _is_tag_char(char):
            name = "unicode_tag_characters"
        elif char in _ALWAYS_HIDDEN and not (char == "﻿" and index == 0):
            name = _ALWAYS_HIDDEN[char]
        elif char in _JOINERS:
            before = text[index - 1] if index > 0 else ""
            after = text[index + 1] if index + 1 < len(text) else ""
            if _is_ascii_alnum(before) and _is_ascii_alnum(after):
                name = "zero_width_characters"
        if name is None:
            continue
        if run_start is not None and index == last + 1 and name == run_name:
            last = index
            continue
        if run_start is not None:
            signals.append(Signal(KIND_HIDDEN_CONTENT, run_name, run_start, last + 1))
        run_start, run_name, last = index, name, index
    if run_start is not None:
        signals.append(Signal(KIND_HIDDEN_CONTENT, run_name, run_start, last + 1))
    return signals


def _html_comment_signals(text: str) -> list:
    """``<!-- ... -->`` spans. An unterminated comment hides the rest of the text."""
    signals = []
    position = 0
    while True:
        start = text.find("<!--", position)
        if start == -1:
            return signals
        close = text.find("-->", start + 4)
        end = len(text) if close == -1 else close + 3
        signals.append(Signal(KIND_HIDDEN_CONTENT, "html_comment", start, end))
        position = end


def _fold(text: str):
    """Text as a reader (or a model) would see it, plus a map back to ``text``.

    Invisible characters are removed and look-alike forms (full-width letters,
    ligatures) are normalised, so "I<ZWSP>gnore" is still "Ignore" for the
    patterns. Returns ``(folded, index_map)``; ``index_map`` is ``None`` when
    the text is plain ASCII and the two are identical.
    """
    if text.isascii():
        return text, None
    chars = []
    index_map = []
    for index, char in enumerate(text):
        if char in _FOLD_AWAY or _is_tag_char(char):
            continue
        normalised = unicodedata.normalize("NFKC", char)
        chars.append(normalised)
        index_map.extend([index] * len(normalised))
    return "".join(chars), index_map


# --------------------------------------------------------------------------
# instructions addressed to an AI
# --------------------------------------------------------------------------

_APOS = "['’]?"
_FLAGS = re.IGNORECASE

_AI_PATTERNS = [
    (
        "addresses_ai",
        re.compile(
            r"\b(?:a\.?i\.?)[\s-]+(?:assistant|agent)s?\b"
            r"|\b(?:dear|attention|note\s+to|message\s+for|instructions?\s+for|hey)\s+(?:the\s+)?"
            r"(?:ai|assistant|agent|llm|model|chatbot)\b",
            _FLAGS,
        ),
    ),
    (
        "ignore_instructions",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\s+(?:(?:all|any|the|your)\s+){0,2}"
            r"(?:previous|prior|above|earlier|preceding|original|system)\s+"
            r"(?:instructions?|directions?|rules?|prompts?|guidelines?)\b"
            r"|\bignore\s+(?:all|any|your)\s+(?:instructions?|rules?|guidelines?)\b",
            _FLAGS,
        ),
    ),
    (
        "conceal_from_user",
        re.compile(
            rf"\b(?:do\s+not|don{_APOS}t|never|without)\s+"
            r"(?:tell(?:ing)?|inform(?:ing)?|notify(?:ing)?|alert(?:ing)?|mention(?:ing)?)\s+"
            r"(?:this\s+to\s+|it\s+to\s+)?the\s+user\b"
            r"|\bdo\s+not\s+(?:reveal|disclose|show)\s+(?:this|these|it)\s+to\s+the\s+user\b",
            _FLAGS,
        ),
    ),
    (
        "behavior_override",
        re.compile(r"\byou\s+must\s+now\b|\bfrom\s+now\s+on,?\s+you\b", _FLAGS),
    ),
    ("important_tag", re.compile(r"<\s*/?\s*important\s*>", _FLAGS)),
]


# --------------------------------------------------------------------------
# exfiltration cues
# --------------------------------------------------------------------------

_SEND_VERB = re.compile(
    r"\b(?:send(?:s|ing)?|sent|e-?mail(?:s|ed|ing)?|mail(?:s|ed|ing)?|forward(?:s|ed|ing)?"
    r"|upload(?:s|ed|ing)?|transmit(?:s|ted|ting)?|exfiltrat\w{0,6}|bcc)\b",
    _FLAGS,
)
_TARGET = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,4}"
    r"|\b(?:https?|ftp)://[^\s<>\"')\]]{1,200}",
    _FLAGS,
)


_TO = re.compile(r"\bto\b", _FLAGS)


def _exfiltration_signals(folded: str) -> list:
    """A sending verb, then "to", then an address or URL, all within EXFIL_WINDOW
    characters ("email its contents to audit@..."). ``bcc`` needs no "to".

    Contact details such as "Email: dana@example.com" or "mail dana@example.com"
    are not flagged: there is no "to", so nothing says the text is being sent.
    """
    targets = [(m.start(), m.end()) for m in _TARGET.finditer(folded)]
    if not targets:
        return []
    starts = [start for start, _ in targets]
    signals = []
    for verb in _SEND_VERB.finditer(folded):
        index = bisect_left(starts, verb.end())  # first target after the verb
        if index > 0 and targets[index - 1][1] > verb.start():
            continue  # the "verb" is a piece of an address (mail@...)
        if index >= len(targets):
            continue
        t_start, t_end = targets[index]
        if t_start - verb.end() > EXFIL_WINDOW:
            continue
        is_bcc = verb.group().lower() == "bcc"
        if not is_bcc and not _TO.search(folded, verb.end(), t_start):
            continue
        signals.append(Signal(KIND_EXFILTRATION, "send_to_address_or_url", verb.start(), t_end))
    return signals


# --------------------------------------------------------------------------
# putting it together
# --------------------------------------------------------------------------


def _to_original(span, index_map):
    start, end = span
    if index_map is None:
        return start, end
    return index_map[start], index_map[end - 1] + 1


def find_signals(text: str) -> list:
    """All signals in ``text``, sorted by position. Offsets index ``text``."""
    signals = _html_comment_signals(text) + _hidden_char_signals(text)

    folded, index_map = _fold(text)
    for name, pattern in _AI_PATTERNS:
        for match in pattern.finditer(folded):
            start, end = _to_original(match.span(), index_map)
            signals.append(Signal(KIND_AI_INSTRUCTION, name, start, end))
    for signal in _exfiltration_signals(folded):
        start, end = _to_original((signal.start, signal.end), index_map)
        signals.append(Signal(signal.kind, signal.name, start, end))

    return sorted(signals, key=lambda s: (s.start, s.end, s.kind, s.name))


def _widen(text: str, start: int, end: int):
    """Grow an instruction span to its sentence, so "ignore previous
    instructions" does not leave the rest of the sentence behind.

    The sentence ends at a line break or after ". ", "! ", "? "; the search is
    capped at EXPAND_LIMIT characters either side. Only ``find``/``rfind`` are
    used, so the work per span is bounded and runs at C speed.
    """
    low = max(0, start - EXPAND_LIMIT)
    high = min(len(text), end + EXPAND_LIMIT)
    left = max(text.rfind("\n", low, start) + 1, low)
    for stop in (". ", "! ", "? "):
        found = text.rfind(stop, low, start)
        if found != -1:
            left = max(left, found + len(stop))
    right = high
    newline = text.find("\n", end, high)
    if newline != -1:
        right = newline
    for stop in (". ", "! ", "? "):
        found = text.find(stop, end, right)
        if found != -1:
            right = min(right, found + 1)  # keep the punctuation mark with the sentence
    return min(left, start), max(right, end)


def sanitize(text: str, signals) -> str:
    """``text`` with every flagged span replaced by ``REMOVED_MARKER``.

    Instruction and exfiltration spans are widened to the whole sentence;
    hidden-content spans (comments, invisible characters) are removed exactly.
    Overlapping spans are merged into one marker.
    """
    spans = []
    for signal in signals:
        if signal.kind == KIND_HIDDEN_CONTENT:
            spans.append((signal.start, signal.end))
        else:
            spans.append(_widen(text, signal.start, signal.end))
    if not spans:
        return text
    spans.sort()
    merged = [list(spans[0])]
    for start, end in spans[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    pieces = []
    cursor = 0
    for start, end in merged:
        pieces.append(text[cursor:start])
        pieces.append(REMOVED_MARKER)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def analyze(text: str) -> InjectionResult:
    """Find injection signals in untrusted ``text`` and a sanitized copy."""
    signals = find_signals(text)
    return InjectionResult(tuple(signals), sanitize(text, signals))
