"""The proxy's local policy: which tools exist for the agent and how each is guarded.

The file is validated strictly at startup: an unknown key, a wrong type or an
unknown value stops the proxy from starting (``PolicyError``). A typo such as
``scan_result: false`` must not silently leave a tool unguarded.

Example (see ``policy.yaml``)::

    server: corp-docs
    allowed_email_domains: [corp.example]
    approval_timeout_seconds: 120
    tools:
      read_document: {allowed: true, scan_results: true}
      send_email:    {allowed: true, scan_args: true, requires_approval: external_recipient}

Any tool that is not listed is denied.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

APPROVAL_MODES = ("never", "always", "external_recipient")
DEFAULT_PATH = Path(__file__).resolve().parent / "policy.yaml"

_TOP_LEVEL_KEYS = {"server", "tools", "allowed_email_domains", "approval_timeout_seconds"}
_TOOL_KEYS = {"allowed", "scan_args", "scan_results", "requires_approval"}
_SERVER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


class PolicyError(ValueError):
    """The policy file is missing, unreadable or invalid."""


@dataclass(frozen=True)
class ToolPolicy:
    """How one tool is guarded. Scanning defaults to *on*: a tool has to opt out."""

    allowed: bool = True
    scan_args: bool = True
    scan_results: bool = True
    requires_approval: str = "never"


@dataclass(frozen=True)
class ProxyPolicy:
    server: str
    tools: dict = field(default_factory=dict)
    allowed_email_domains: tuple = ()
    approval_timeout_seconds: int = 120

    def tool(self, name: str) -> Optional[ToolPolicy]:
        """The rule for ``name``, or None if the tool is not listed (= denied)."""
        return self.tools.get(name)

    def is_allowed(self, name: str) -> bool:
        rule = self.tools.get(name)
        return rule is not None and rule.allowed


def _flag(value, where: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{where} must be true or false, got {value!r}")
    return value


def _parse_tool(name, rule) -> ToolPolicy:
    where = f"tools.{name}"
    if not isinstance(name, str) or not name:
        raise PolicyError(f"tool names must be non-empty strings, got {name!r}")
    if rule is None:
        rule = {}
    if not isinstance(rule, dict):
        raise PolicyError(f"{where} must be a mapping, got {type(rule).__name__}")
    unknown = sorted(str(key) for key in rule if key not in _TOOL_KEYS)
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {', '.join(unknown)} (allowed: {', '.join(sorted(_TOOL_KEYS))})")
    defaults = ToolPolicy()
    approval = rule.get("requires_approval", defaults.requires_approval)
    if approval not in APPROVAL_MODES:
        raise PolicyError(f"{where}.requires_approval must be one of {', '.join(APPROVAL_MODES)}, got {approval!r}")
    return ToolPolicy(
        allowed=_flag(rule.get("allowed", defaults.allowed), f"{where}.allowed"),
        scan_args=_flag(rule.get("scan_args", defaults.scan_args), f"{where}.scan_args"),
        scan_results=_flag(rule.get("scan_results", defaults.scan_results), f"{where}.scan_results"),
        requires_approval=approval,
    )


def parse_policy(document) -> ProxyPolicy:
    """Validate a parsed YAML document and build the policy."""
    if not isinstance(document, dict):
        raise PolicyError("the policy must be a mapping with a 'server' and a 'tools' section")
    unknown = sorted(str(key) for key in document if key not in _TOP_LEVEL_KEYS)
    if unknown:
        raise PolicyError(f"unknown key(s) {', '.join(unknown)} (allowed: {', '.join(sorted(_TOP_LEVEL_KEYS))})")

    server = document.get("server")
    if not isinstance(server, str) or not _SERVER_NAME.match(server):
        raise PolicyError("'server' must be a name of letters, digits, '_', '.' or '-'")

    tools_doc = document.get("tools")
    if not isinstance(tools_doc, dict):
        raise PolicyError("'tools' must be a mapping of tool name -> rules (it may be empty to deny everything)")
    tools = {name: _parse_tool(name, rule) for name, rule in tools_doc.items()}

    domains_doc = document.get("allowed_email_domains", [])
    if not isinstance(domains_doc, list):
        raise PolicyError("'allowed_email_domains' must be a list of domains")
    domains = []
    for domain in domains_doc:
        if not isinstance(domain, str) or not _DOMAIN.match(domain.strip().lower().rstrip(".")):
            raise PolicyError(f"'allowed_email_domains' has an invalid domain: {domain!r}")
        domains.append(domain.strip().lower().rstrip("."))

    timeout = document.get("approval_timeout_seconds", 120)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 3600:
        raise PolicyError("'approval_timeout_seconds' must be a whole number between 1 and 3600")

    if not domains and any(rule.requires_approval == "external_recipient" for rule in tools.values()):
        raise PolicyError(
            "requires_approval: external_recipient needs 'allowed_email_domains' "
            "(otherwise every recipient would count as external)"
        )

    return ProxyPolicy(
        server=server,
        tools=tools,
        allowed_email_domains=tuple(domains),
        approval_timeout_seconds=timeout,
    )


def load_policy(path=None) -> ProxyPolicy:
    """Read, parse and validate the policy file (the default is ``policy.yaml``)."""
    path = Path(path) if path else DEFAULT_PATH
    try:
        with path.open(encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc.strerror or exc}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy file {path} is not valid YAML: {exc}") from exc
    return parse_policy(document)
