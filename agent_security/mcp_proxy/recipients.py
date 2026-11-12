"""Who is an email going to, and is that inside the organisation?

Used for ``requires_approval: external_recipient``. The rule is fail-closed:
anything that cannot be understood as an address inside an allowed domain
counts as external.

* domains are compared case-insensitively, and a trailing dot is ignored;
* a subdomain of an allowed domain is internal (``mail.corp.example`` for
  ``corp.example``) but a look-alike is not (``evilcorp.example``,
  ``corp.example.evil.org``);
* ``to`` / ``cc`` / ``bcc`` / ``recipient(s)`` are all checked, each may hold
  several addresses and display names (``"Dana Levi" <dana@corp.example>``);
* if no recipient field is present, or one cannot be parsed, the check says
  "external" so that a human looks at it.
"""
import re
from dataclasses import dataclass, field
from email.utils import getaddresses

RECIPIENT_FIELDS = ("to", "cc", "bcc", "recipient", "recipients")

_LOCAL_PART = re.compile(r"^[^\s<>()\[\],;:\\\"@%!|]{1,64}$")
_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


@dataclass(frozen=True)
class RecipientCheck:
    addresses: tuple = ()
    external: tuple = field(default_factory=tuple)
    undetermined: bool = False

    @property
    def has_external(self) -> bool:
        """True if any recipient is outside the allowed domains, or unclear."""
        return bool(self.external) or self.undetermined


def normalize_domain(address: str):
    """The lower-case domain of a plain address, or None if it is not a valid one."""
    local, at, domain = address.strip().rpartition("@")
    if not at or not _LOCAL_PART.match(local):
        return None
    domain = domain.lower().rstrip(".")
    return domain if _DOMAIN.match(domain) else None


def is_internal_domain(domain: str, allowed_domains) -> bool:
    """Equal to an allowed domain, or a subdomain of one."""
    domain = domain.lower().rstrip(".")
    return any(domain == allowed or domain.endswith("." + allowed) for allowed in allowed_domains)


def _addresses_in(value):
    """Plain address strings in one field value. ``None`` entries are unparseable."""
    if isinstance(value, str):
        pieces = [value]
    elif isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        pieces = list(value)
    else:
        return [None]
    # a line break or other control character in a recipient is a header-injection
    # attempt (an address followed by a line break and a "Bcc:" header): never try
    # to interpret it
    if any(ord(char) < 0x20 or ord(char) == 0x7F for piece in pieces for char in piece):
        return [None]
    pieces = [piece.replace(";", ",") for piece in pieces]
    found = []
    for _name, address in getaddresses(pieces):
        found.append(address.strip() or None)
    return found or [None]


def check_recipients(arguments, allowed_domains) -> RecipientCheck:
    """Classify every recipient in a tool call's arguments."""
    if not isinstance(arguments, dict):
        return RecipientCheck(undetermined=True)
    present = [key for key in RECIPIENT_FIELDS if key in arguments]
    if not present:
        return RecipientCheck(undetermined=True)

    addresses, external = [], []
    undetermined = False
    for key in present:
        for address in _addresses_in(arguments[key]):
            if address is None:
                undetermined = True
                continue
            domain = normalize_domain(address)
            if domain is None:
                undetermined = True
                continue
            addresses.append(address.lower())
            if not is_internal_domain(domain, allowed_domains):
                external.append(address.lower())
    return RecipientCheck(tuple(addresses), tuple(external), undetermined)
