"""The proxy's decision pipeline: where policy is *enforced*.

The proxy is the policy enforcement point (PEP): it sits on the only path
between the agent and the MCP server and applies the local policy file. The
gateway is the policy decision point (PDP) for everything that needs the DLP
engine, injection heuristics or a human: it classifies text and records the
decisions. The proxy asks, then enforces the answer.

Controls, in the order a tool call meets them:

1. allowlist        a tool that is not listed (or not allowed) does not exist
2. tool pinning     a pinned tool whose definition changed is blocked
3. argument DLP     arguments with sensitive data: the call is refused (never edited)
4. approval         risky calls wait for a human; the approved hash must match
5. result scanning  results are redacted and stripped of injected instructions

Failing closed: if the gateway cannot be reached or answers with an error, any
call that needs a scan or an approval is refused, and nothing is forwarded.

This module has no MCP SDK types, so it can be tested with plain objects and a
fake gateway. Nothing here ever logs or stores raw arguments or results: events
carry data-type names, counts and signal names only.
"""
import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional

from .gateway_client import GatewayError
from .pinning import (
    PINNED,
    QUARANTINED,
    PinStore,
    PinStoreError,
    args_fingerprint,
    canonical_json,
    tool_fingerprint,
)
from .policy import ProxyPolicy
from .recipients import check_recipients

logger = logging.getLogger("mcp_proxy")

# what review_tools / the definition check says about one tool
STATUS_OK = "ok"
STATUS_NOT_ALLOWED = "not_allowed"
STATUS_QUARANTINED = "quarantined"
STATUS_CHANGED = "changed"
STATUS_UNVERIFIED = "unverified"  # could not be checked (gateway or pin file trouble)

# risk scores recorded with the proxy's own events (DLP events use the gateway's)
RISK_POISONING = 95
RISK_CHANGED = 90
RISK_INJECTION = 90

BACKLOG_LIMIT = 200
MAX_SCHEMA_TEXT = 100_000


@dataclass(frozen=True)
class ToolDef:
    """The three things a tool definition is pinned on."""

    name: str
    description: Optional[str]
    input_schema: dict


@dataclass(frozen=True)
class CallDecision:
    allowed: bool
    message: str = ""
    args: Optional[dict] = None
    args_sha256: Optional[str] = None


class ResultWithheld(Exception):
    """A tool result could not be checked, so it must not reach the agent."""


def deny(message: str) -> CallDecision:
    return CallDecision(False, message)


def _schema_strings(value, out: list, depth: int = 0) -> None:
    """Every string value in a JSON schema (descriptions, titles, enums, defaults)."""
    if depth > 20 or sum(map(len, out)) > MAX_SCHEMA_TEXT:
        return
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            _schema_strings(item, out, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _schema_strings(item, out, depth + 1)


def definition_text(definition: ToolDef) -> str:
    """What the model reads about a tool: its description and every text inside
    its input schema (parameter descriptions are a favourite hiding place)."""
    parts = [definition.description or ""]
    _schema_strings(definition.input_schema, parts)
    return "\n".join(parts)[:MAX_SCHEMA_TEXT]


def summarize_signals(signals) -> str:
    """"ai_instruction:ignore_instructions x2, ..." - names and counts, never content."""
    counts = {}
    for signal in signals or []:
        key = f"{signal.get('kind', '?')}:{signal.get('name', '?')}"
        counts[key] = counts.get(key, 0) + 1
    return ", ".join(f"{key} x{count}" for key, count in sorted(counts.items())) or "none"


class SecurityPipeline:
    def __init__(
        self,
        policy: ProxyPolicy,
        gateway,
        pins: PinStore,
        *,
        sleep=asyncio.sleep,
        clock=time.monotonic,
        poll_interval: float = 2.0,
        approval_grace: float = 3.0,
    ):
        self.policy = policy
        self.gateway = gateway
        self.pins = pins
        self._sleep = sleep
        self._clock = clock
        self.poll_interval = poll_interval
        self.approval_grace = approval_grace
        self._backlog = deque(maxlen=BACKLOG_LIMIT)  # events the gateway has not received yet
        self._reported = set()  # (kind, tool, hash) already reported, to avoid flooding

    # --- event log ----------------------------------------------------------

    async def event(self, event_type, decision, tool=None, risk=0, data_types=(), details=""):
        """Record a decision at the gateway. Never raises: a logging failure must
        not take the proxy down. Events that could not be delivered are kept
        (up to BACKLOG_LIMIT) and sent before the next one."""
        await self._deliver(
            {
                "event_type": event_type,
                "server_name": self.policy.server,
                "tool_name": tool,
                "decision": decision,
                "risk_score": int(risk),
                "data_types": list(data_types),
                "details": details,
            }
        )

    async def _deliver(self, record: dict) -> None:
        """Queue the event, then send the queue oldest first."""
        self._backlog.append(record)
        while self._backlog:
            head = self._backlog[0]
            try:
                await self.gateway.post_event(head)
            except GatewayError as exc:
                if exc.status is not None and exc.status < 500:
                    # the gateway refuses this event for good (bad request, bad token): retrying is pointless
                    logger.warning("event %s dropped: %s", head["event_type"], exc)
                    self._backlog.popleft()
                    continue
                logger.warning("event %s queued for later: %s", head["event_type"], exc)
                return
            except Exception as exc:  # noqa: BLE001 - logging must never crash the proxy
                logger.warning("event %s dropped (%s)", head["event_type"], type(exc).__name__)
                self._backlog.popleft()
                return
            self._backlog.popleft()

    def _gateway_unavailable(self, doing: str, tool=None) -> None:
        """Say, on stderr, that the gateway cannot be reached, and queue the
        GATEWAY_UNAVAILABLE event for when it is back."""
        logger.error("GATEWAY_UNAVAILABLE: cannot reach the gateway while %s; failing closed", doing)
        self._backlog.append(
            {
                "event_type": "GATEWAY_UNAVAILABLE",
                "server_name": self.policy.server,
                "tool_name": tool,
                "decision": "deny",
                "risk_score": 0,
                "data_types": [],
                "details": f"gateway unreachable while {doing}",
            }
        )

    async def _report_once(self, key, *event_args, force=False, **event_kwargs) -> None:
        if key in self._reported and not force:
            return
        self._reported.add(key)
        await self.event(*event_args, **event_kwargs)

    # --- 1 + 2: allowlist and pinning ---------------------------------------

    async def review_tools(self, definitions) -> dict:
        """Status of every tool the upstream server offers: name -> STATUS_*.

        Only STATUS_OK tools may be shown to the agent. Called on every
        ``tools/list``, with a fresh list from the upstream server.
        """
        statuses = {}
        for definition in definitions:
            if not self.policy.is_allowed(definition.name):
                statuses[definition.name] = STATUS_NOT_ALLOWED
            else:
                statuses[definition.name] = await self._check_definition(definition)
        return statuses

    async def _check_definition(self, definition: ToolDef, on_call: bool = False) -> str:
        fingerprint = tool_fingerprint(definition.name, definition.description, definition.input_schema)
        try:
            entry = self.pins.get(self.policy.server, definition.name)
        except PinStoreError as exc:
            logger.error("tool pins unavailable, treating %s as unverified: %s", definition.name, exc)
            return STATUS_UNVERIFIED

        if entry is None:
            return await self._first_sight(definition, fingerprint)

        if entry.get("status") == QUARANTINED:
            await self._report_once(
                ("quarantined", definition.name, fingerprint),
                "TOOL_POISONING_SUSPECTED", "quarantine", definition.name, RISK_POISONING,
                details="tool is quarantined since its description was flagged",
                force=on_call,
            )
            return STATUS_QUARANTINED

        if entry.get("sha256") == fingerprint:
            return STATUS_OK

        await self._report_once(
            ("changed", definition.name, fingerprint),
            "TOOL_DEFINITION_CHANGED", "deny", definition.name, RISK_CHANGED,
            details=(
                f"definition changed: pinned {str(entry.get('sha256'))[:12]}, now {fingerprint[:12]}"
                + ("; call blocked" if on_call else "")
            ),
            force=on_call,
        )
        return STATUS_CHANGED

    async def _first_sight(self, definition: ToolDef, fingerprint: str) -> str:
        """Trust on first use: scan the description once, then pin or quarantine."""
        try:
            result = await self.gateway.scan(definition_text(definition), "tool_description")
        except GatewayError:
            self._gateway_unavailable("scanning a new tool definition", definition.name)
            return STATUS_UNVERIFIED
        injection = result["injection"]
        poisoned = bool(injection.get("detected"))
        try:
            self.pins.record(self.policy.server, definition.name, fingerprint, QUARANTINED if poisoned else PINNED)
        except (PinStoreError, OSError) as exc:
            logger.error("cannot save the pin for %s, treating it as unverified: %s", definition.name, exc)
            return STATUS_UNVERIFIED
        if poisoned:
            await self.event(
                "TOOL_POISONING_SUSPECTED", "quarantine", definition.name, RISK_POISONING,
                details=f"tool description flagged: {summarize_signals(injection.get('signals'))}",
            )
            return STATUS_QUARANTINED
        return STATUS_OK

    @staticmethod
    def _status_message(name: str, status: str) -> str:
        if status == STATUS_CHANGED:
            return (
                f"Tool {name!r} was blocked: its definition changed since it was pinned (possible rug pull). "
                f"A human must review it and re-approve it with: python -m mcp_proxy pins reset {name}"
            )
        if status == STATUS_QUARANTINED:
            return (
                f"Tool {name!r} was blocked: its description looks like a prompt injection (possible tool "
                f"poisoning). A human must review it and re-approve it with: python -m mcp_proxy pins reset {name}"
            )
        return (
            f"Tool {name!r} was blocked: its definition could not be verified (security gateway or pin "
            "file unavailable). Nothing was executed."
        )

    # --- the call path: 1 -> 4 ----------------------------------------------

    async def authorize_call(self, name: str, arguments, definitions) -> CallDecision:
        """Decide whether the agent's call may go to the upstream server.

        ``definitions`` is a *fresh* tool list from the upstream server, so a
        rug pull between the list and the call is caught here too. On success
        the returned ``args`` are exactly what must be sent (their hash is in
        ``args_sha256``).
        """
        rule = self.policy.tool(name)
        if rule is None or not rule.allowed:
            await self.event("TOOL_NOT_ALLOWED", "deny", name, details="tool is not in the policy allowlist")
            return deny(f"Tool {name!r} is not allowed by the security proxy policy.")

        definition = next((d for d in definitions if d.name == name), None)
        if definition is None:
            await self.event("TOOL_NOT_ALLOWED", "deny", name, details="tool is not offered by the upstream server")
            return deny(f"Tool {name!r} is not offered by the upstream server.")
        status = await self._check_definition(definition, on_call=True)
        if status != STATUS_OK:
            return deny(self._status_message(name, status))

        arguments = arguments if isinstance(arguments, dict) else {}
        recipients = (
            check_recipients(arguments, self.policy.allowed_email_domains)
            if rule.requires_approval == "external_recipient"
            else None
        )
        needs_approval = rule.requires_approval == "always" or (recipients is not None and recipients.has_external)

        # 3. argument DLP (also needed to mask the arguments shown to an approver)
        scan = None
        if rule.scan_args or needs_approval:
            try:
                scan = await self.gateway.scan(canonical_json(arguments), "tool_args")
            except GatewayError:
                self._gateway_unavailable("scanning tool arguments", name)
                return deny(self._unavailable_message(name))
        elif rule.scan_results and not await self.gateway.is_available():
            # the result must be scanned later: refuse now, before anything runs
            self._gateway_unavailable("checking the gateway before a call whose result must be scanned", name)
            return deny(self._unavailable_message(name))

        if rule.scan_args and scan is not None:
            refusal = await self._check_argument_dlp(name, scan["dlp"])
            if refusal:
                return refusal

        sha256 = args_fingerprint(arguments)

        # 4. approval
        approved = False
        if needs_approval:
            reason = self._approval_reason(rule.requires_approval, recipients)
            refusal = await self._get_approval(name, scan["dlp"].get("redacted_text", ""), sha256, reason)
            if refusal:
                return deny(refusal)
            approved = True

        # whatever was approved is exactly what is sent
        if args_fingerprint(arguments) != sha256:
            await self.event("APPROVAL_DENIED", "deny", name, details="arguments changed after the hash was taken")
            return deny("The arguments changed after they were checked, so the call was refused.")

        await self.event("TOOL_CALL_ALLOWED", "allow", name, details="approved by a human" if approved else "")
        return CallDecision(True, args=arguments, args_sha256=sha256)

    def _unavailable_message(self, name: str) -> str:
        return (
            f"Tool {name!r} was not called: the security gateway is unreachable and this call needs a "
            "security check. Nothing was executed. Try again later."
        )

    async def _check_argument_dlp(self, name: str, dlp: dict) -> Optional[CallDecision]:
        action = dlp.get("action")
        types = dlp.get("data_types") or []
        risk = dlp.get("risk_score") or 0
        listed = ", ".join(types) or "sensitive data"
        if action == "block":
            await self.event(
                "ARGS_DLP_BLOCKED", "deny", name, risk, types, f"arguments contain: {listed}"
            )
            return deny(
                f"Tool {name!r} was not called: the arguments contain sensitive data ({listed}), which policy "
                "does not allow to be sent. Remove it and try again."
            )
        if action == "redact":
            await self.event(
                "ARGS_DLP_REDACTED", "deny", name, risk, types, f"arguments contain data policy masks: {listed}"
            )
            return deny(
                f"Tool {name!r} was not called: the arguments contain data that policy requires to be masked "
                f"({listed}). The proxy never edits a call silently, so remove the sensitive data from the "
                "arguments yourself and call the tool again."
            )
        return None

    @staticmethod
    def _approval_reason(mode: str, recipients) -> str:
        if mode == "always":
            return "this tool always requires approval"
        if recipients is not None and recipients.external:
            return f"{len(recipients.external)} recipient(s) outside the allowed email domains"
        return "recipients could not be determined"

    async def _get_approval(self, name: str, masked_args: str, sha256: str, reason: str) -> Optional[str]:
        """Ask a human and wait. Returns None if approved, else the refusal message."""
        timeout = self.policy.approval_timeout_seconds
        try:
            created = await self.gateway.create_approval(
                server_name=self.policy.server,
                tool_name=name,
                args_masked=masked_args,
                args_sha256=sha256,
                reason=reason,
                timeout_seconds=timeout,
            )
        except GatewayError:
            self._gateway_unavailable("requesting an approval", name)
            return self._unavailable_message(name)

        approval_id = created["id"]
        await self.event("APPROVAL_REQUESTED", "pending", name, details=f"approval {approval_id}: {reason}")
        logger.warning("approval needed for %s: id=%s (waiting up to %ss)", name, approval_id, timeout)

        deadline = self._clock() + timeout + self.approval_grace
        failures = 0
        while True:
            record = None
            try:
                record = await self.gateway.get_approval(approval_id)
                failures = 0
            except GatewayError:
                failures += 1
                if failures >= 3:
                    self._gateway_unavailable("waiting for an approval", name)
                    return self._unavailable_message(name)

            status = record.get("status") if record else None
            if status == "approved":
                matches = (
                    record.get("id") == approval_id
                    and record.get("args_sha256") == sha256
                    and record.get("tool_name") == name
                    and record.get("server_name") == self.policy.server
                )
                if not matches:
                    await self.event(
                        "APPROVAL_DENIED", "deny", name, details="the approval does not match this call"
                    )
                    return "The approval does not match this call (different arguments), so it was refused."
                await self.event("APPROVAL_GRANTED", "allow", name, details=f"approval {approval_id} granted")
                return None
            if status == "denied":
                await self.event("APPROVAL_DENIED", "deny", name, details=f"approval {approval_id} denied")
                return f"Tool {name!r} was not called: a human denied the request."
            if status == "expired":
                await self.event("APPROVAL_EXPIRED", "deny", name, details=f"approval {approval_id} expired")
                return f"Tool {name!r} was not called: nobody approved the request in time."
            if status is not None and status != "pending":
                await self.event("APPROVAL_DENIED", "deny", name, details="the gateway reported an unknown status")
                return f"Tool {name!r} was not called: the approval request returned an unexpected status."

            if self._clock() >= deadline:
                await self.event("APPROVAL_EXPIRED", "deny", name, details=f"approval {approval_id}: no decision in time")
                return f"Tool {name!r} was not called: nobody approved the request in time."
            await self._sleep(self.poll_interval)

    # --- 5: results ---------------------------------------------------------

    async def sanitize_result(self, name: str, text: str) -> str:
        """The text of a tool result with sensitive data redacted and injected
        instructions removed. Raises ResultWithheld if it cannot be checked."""
        if not text.strip():
            return text
        try:
            result = await self.gateway.scan(text, "tool_result")
        except GatewayError:
            self._gateway_unavailable("scanning a tool result", name)
            raise ResultWithheld(
                f"The result of {name!r} was withheld: the security gateway is unreachable, so it could "
                "not be checked."
            ) from None
        safe_text = result.get("safe_text")
        if not isinstance(safe_text, str):
            self._gateway_unavailable("reading a scan response without safe_text", name)
            raise ResultWithheld(f"The result of {name!r} was withheld: the scan response was not understood.")

        injection, dlp = result["injection"], result["dlp"]
        if injection.get("detected"):
            await self.event(
                "RESULT_INJECTION_REMOVED", "sanitize", name, RISK_INJECTION,
                details=f"removed suspected injected instructions: {summarize_signals(injection.get('signals'))}",
            )
        if dlp.get("action") in ("redact", "block"):
            types = dlp.get("data_types") or []
            await self.event(
                "RESULT_REDACTED", "redact", name, dlp.get("risk_score") or 0, types,
                f"sensitive data masked in the result; data types found: {', '.join(types) or 'n/a'}",
            )
        return safe_text
