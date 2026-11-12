"""Gateway endpoints for the MCP security proxy.

The proxy (``agent_security/mcp_proxy``) enforces policy next to the AI agent;
the gateway makes the decisions that need the DLP engine, a shared audit trail
or a human:

* ``POST /scan``                          scan tool arguments / results / descriptions
* ``POST /mcp/events``, ``GET /mcp/events``, ``GET /mcp/stats``   audit trail of proxy decisions
* ``POST /mcp/approvals`` ...             human-in-the-loop approvals

Rules that apply to everything stored here: **raw tool arguments and results
are never stored**. Whatever the proxy sends is masked again on arrival (every
DLP finding, and any injection text), so a faulty or malicious client cannot
make the gateway persist raw data.

Authentication: the endpoints the proxy calls need the ``X-Proxy-Token``
header to equal the ``MCP_PROXY_TOKEN`` environment variable. If that variable
is not set they answer 503 (fail closed) rather than being open.
"""
import hmac
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.orm import Session

import injection
from db_base import Base
from dlp import engine as dlp_engine

EVENT_TYPES = (
    "TOOL_CALL_ALLOWED",
    "TOOL_NOT_ALLOWED",
    "ARGS_DLP_BLOCKED",
    "ARGS_DLP_REDACTED",
    "RESULT_REDACTED",
    "RESULT_INJECTION_REMOVED",
    "TOOL_POISONING_SUSPECTED",
    "TOOL_DEFINITION_CHANGED",
    "APPROVAL_REQUESTED",
    "APPROVAL_GRANTED",
    "APPROVAL_DENIED",
    "APPROVAL_EXPIRED",
    "GATEWAY_UNAVAILABLE",
)
EventType = Literal[EVENT_TYPES]

DECISIONS = ("allow", "deny", "redact", "sanitize", "quarantine", "pending")
Decision = Literal[DECISIONS]

SCAN_KINDS = ("tool_args", "tool_result", "tool_description")
ScanKind = Literal[SCAN_KINDS]

APPROVAL_STATUSES = ("pending", "approved", "denied", "expired")

# longest text /scan accepts, in characters (tool results can be large)
MAX_SCAN_CHARS = int(os.environ.get("MAX_SCAN_CHARS", "200000"))
# stored text is cut to this many characters
MAX_STORED_CHARS = 2000

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DATA_TYPE = re.compile(r"^[A-Z][A-Z0-9_]{0,39}$")


def _utcnow() -> datetime:
    """Naive UTC, like the rest of the gateway's timestamps (tests patch this)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value: Optional[datetime]) -> Optional[str]:
    """Naive-UTC datetime -> ISO 8601 with a trailing Z (what the browser needs)."""
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


# --- tables -----------------------------------------------------------------


class McpEventDB(Base):
    __tablename__ = "mcp_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=_utcnow, index=True)
    event_type = Column(String, nullable=False)
    server_name = Column(String, nullable=False)
    tool_name = Column(String, nullable=True)
    decision = Column(String, nullable=False)
    risk_score = Column(Integer, default=0)
    data_types = Column(String, default="")  # comma-separated
    # masked text only: see safe_for_storage
    details_masked = Column(String, default="")


class McpApprovalDB(Base):
    __tablename__ = "mcp_approvals"

    id = Column(String(36), primary_key=True)
    created_at = Column(DateTime, default=_utcnow)
    expires_at = Column(DateTime, nullable=False)
    server_name = Column(String, nullable=False)
    tool_name = Column(String, nullable=False)
    args_masked = Column(String, default="")
    args_sha256 = Column(String(64), nullable=False)
    reason = Column(String, default="")
    status = Column(String, nullable=False, default="pending")
    decided_at = Column(DateTime, nullable=True)


# --- masking ----------------------------------------------------------------


def _truncate(text: str) -> str:
    return text if len(text) <= MAX_STORED_CHARS else text[: MAX_STORED_CHARS - 1] + "…"


def _mask_dlp(text: str) -> str:
    """Every DLP finding replaced by its mask, alert-only ones included."""
    return dlp_engine.mask_text(text, dlp_engine.scan(text).findings)


def safe_for_storage(text: str) -> str:
    """Text that may be stored in the event log: DLP-masked, injection text
    removed, truncated. Applied to everything the proxy sends."""
    return _truncate(injection.analyze(_mask_dlp(text)).sanitized_text)


_REVEAL = {c: f"<U+{ord(c):04X}>" for c in "​‌‍⁠﻿᠎­‎‏"}
_REVEAL.update({chr(c): f"<U+{c:04X}>" for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))})


def reveal_hidden(text: str) -> str:
    """Show invisible and tag characters as <U+XXXX> so a human approver can
    see what a screen would hide."""
    out = []
    for char in text:
        if char in _REVEAL:
            out.append(_REVEAL[char])
        elif 0xE0000 <= ord(char) <= 0xE007F:
            out.append(f"<U+{ord(char):X}>")
        else:
            out.append(char)
    return "".join(out)


def safe_for_approval(text: str) -> str:
    """What an approver sees: DLP-masked (never raw secrets), but *not* stripped
    of suspicious text (the human needs to see it), with invisible characters
    made visible."""
    return _truncate(reveal_hidden(_mask_dlp(text)))


# --- authentication ---------------------------------------------------------


def require_proxy_token(x_proxy_token: Optional[str] = Header(default=None)) -> None:
    """Dependency for the endpoints the proxy calls."""
    expected = os.environ.get("MCP_PROXY_TOKEN", "")
    if not expected:
        # fail closed: an unconfigured gateway must not accept proxy traffic
        raise HTTPException(
            status_code=503,
            detail={"error": "MCP proxy endpoints are disabled: MCP_PROXY_TOKEN is not set"},
        )
    supplied = (x_proxy_token or "").encode("utf-8")
    if not hmac.compare_digest(supplied, expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail={"error": "Invalid or missing X-Proxy-Token"})


# --- request bodies ---------------------------------------------------------


class ScanRequest(BaseModel):
    text: str
    kind: ScanKind


class EventIn(BaseModel):
    event_type: EventType
    server_name: str = Field(min_length=1, max_length=200)
    tool_name: Optional[str] = Field(default=None, max_length=200)
    decision: Decision
    risk_score: int = Field(default=0, ge=0, le=100)
    data_types: list = Field(default_factory=list, max_length=20)
    details: str = Field(default="", max_length=MAX_STORED_CHARS * 2)


class ApprovalIn(BaseModel):
    server_name: str = Field(min_length=1, max_length=200)
    tool_name: str = Field(min_length=1, max_length=200)
    args_masked: str = Field(default="", max_length=100_000)
    args_sha256: str
    reason: str = Field(default="", max_length=1000)
    timeout_seconds: int = Field(default=120, ge=1, le=3600)


class DecisionIn(BaseModel):
    decision: Literal["approve", "deny"]


# --- serialisation ----------------------------------------------------------


def _event_dict(row: McpEventDB) -> dict:
    return {
        "id": row.id,
        "timestamp": _iso(row.timestamp),
        "event_type": row.event_type,
        "server_name": row.server_name,
        "tool_name": row.tool_name,
        "decision": row.decision,
        "risk_score": row.risk_score,
        "data_types": [t for t in (row.data_types or "").split(",") if t],
        "details": row.details_masked or "",
    }


def _approval_dict(row: McpApprovalDB) -> dict:
    return {
        "id": row.id,
        "created_at": _iso(row.created_at),
        "expires_at": _iso(row.expires_at),
        "server_name": row.server_name,
        "tool_name": row.tool_name,
        "args_masked": row.args_masked or "",
        "args_sha256": row.args_sha256,
        "reason": row.reason or "",
        "status": row.status,
        "decided_at": _iso(row.decided_at),
    }


def _expire_pending(db: Session, now: datetime) -> None:
    """Store the "expired" status for pending approvals that ran out of time."""
    updated = (
        db.query(McpApprovalDB)
        .filter(McpApprovalDB.status == "pending", McpApprovalDB.expires_at <= now)
        .update({"status": "expired"}, synchronize_session=False)
    )
    if updated:
        db.commit()


# --- the router -------------------------------------------------------------


def create_mcp_router(get_db) -> APIRouter:
    """Build the router. ``get_db`` is main's session dependency (passed in, so
    tests can override it and this module never imports ``main``)."""
    router = APIRouter()
    proxy_only = [Depends(require_proxy_token)]

    @router.post("/scan", dependencies=proxy_only)
    def scan_text(request: ScanRequest):
        if len(request.text) > MAX_SCAN_CHARS:
            raise HTTPException(
                status_code=413,
                detail={"error": "Input too long", "max_chars": MAX_SCAN_CHARS},
            )
        # tool results flow back to the agent, so they are scanned like model
        # output (a "block" rule becomes a redaction); everything else is input
        direction = "output" if request.kind == "tool_result" else "input"
        dlp = dlp_engine.scan(request.text, direction=direction)
        inj = injection.analyze(request.text)
        # one text with both treatments applied, for callers that want to
        # forward a single cleaned string
        safe_text = dlp_engine.scan(inj.sanitized_text, direction=direction).redacted_text
        return {
            "dlp": {
                "action": dlp.action,
                "risk_score": dlp.risk_score,
                "data_types": dlp.data_types,
                "redacted_text": dlp.redacted_text,
            },
            "injection": inj.to_dict(),
            "safe_text": safe_text,
        }

    # --- events -------------------------------------------------------------

    @router.post("/mcp/events", status_code=201, dependencies=proxy_only)
    def create_event(event: EventIn, db: Session = Depends(get_db)):
        data_types = [t for t in event.data_types if isinstance(t, str) and _DATA_TYPE.match(t)]
        row = McpEventDB(
            event_type=event.event_type,
            server_name=event.server_name,
            tool_name=event.tool_name,
            decision=event.decision,
            risk_score=event.risk_score,
            data_types=",".join(data_types),
            details_masked=safe_for_storage(event.details),
        )
        db.add(row)
        db.commit()
        return {"id": row.id}

    # TODO(auth): the read endpoints below and the approval decision endpoint are
    # meant for the dashboard, which has no user authentication yet. Anyone who can
    # reach the gateway can read events and approve or deny requests. Add real
    # authentication (and authorization for approvers) before exposing this.
    @router.get("/mcp/events")
    def list_events(hours: int = 24, limit: int = 500, db: Session = Depends(get_db)):
        if hours < 1 or hours > 720:
            raise HTTPException(status_code=400, detail="hours must be between 1 and 720")
        if limit < 1 or limit > 5000:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 5000")
        cutoff = _utcnow() - timedelta(hours=hours)
        rows = (
            db.query(McpEventDB)
            .filter(McpEventDB.timestamp >= cutoff)
            .order_by(McpEventDB.timestamp.desc(), McpEventDB.id.desc())
            .limit(limit)
            .all()
        )
        return {"events": [_event_dict(row) for row in rows]}

    @router.get("/mcp/stats")
    def mcp_stats(db: Session = Depends(get_db)):
        by_type = {name: 0 for name in EVENT_TYPES}
        by_decision = {name: 0 for name in DECISIONS}
        total = 0
        for event_type, decision in db.query(McpEventDB.event_type, McpEventDB.decision).all():
            total += 1
            by_type[event_type] = by_type.get(event_type, 0) + 1
            by_decision[decision] = by_decision.get(decision, 0) + 1
        _expire_pending(db, _utcnow())
        pending = db.query(McpApprovalDB).filter(McpApprovalDB.status == "pending").count()
        return {
            "total_events": total,
            "by_event_type": by_type,
            "by_decision": by_decision,
            "pending_approvals": pending,
        }

    # --- approvals ----------------------------------------------------------

    @router.post("/mcp/approvals", status_code=201, dependencies=proxy_only)
    def create_approval(approval: ApprovalIn, db: Session = Depends(get_db)):
        if not _SHA256.match(approval.args_sha256):
            raise HTTPException(
                status_code=422, detail={"error": "args_sha256 must be 64 lowercase hex characters"}
            )
        now = _utcnow()
        row = McpApprovalDB(
            id=str(uuid.uuid4()),
            created_at=now,
            expires_at=now + timedelta(seconds=approval.timeout_seconds),
            server_name=approval.server_name,
            tool_name=approval.tool_name,
            args_masked=safe_for_approval(approval.args_masked),
            args_sha256=approval.args_sha256,
            reason=safe_for_storage(approval.reason),
            status="pending",
        )
        db.add(row)
        db.commit()
        return {"id": row.id, "expires_at": _iso(row.expires_at)}

    @router.get("/mcp/approvals")
    def list_approvals(status: Optional[str] = None, db: Session = Depends(get_db)):
        if status is not None and status not in APPROVAL_STATUSES:
            raise HTTPException(
                status_code=400, detail=f"status must be one of {', '.join(APPROVAL_STATUSES)}"
            )
        _expire_pending(db, _utcnow())
        query = db.query(McpApprovalDB)
        if status is not None:
            query = query.filter(McpApprovalDB.status == status)
        rows = query.order_by(McpApprovalDB.created_at.desc()).all()
        return {"approvals": [_approval_dict(row) for row in rows]}

    @router.get("/mcp/approvals/{approval_id}", dependencies=proxy_only)
    def get_approval(approval_id: str, db: Session = Depends(get_db)):
        _expire_pending(db, _utcnow())
        row = db.get(McpApprovalDB, approval_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"error": "Approval not found"})
        return _approval_dict(row)

    @router.post("/mcp/approvals/{approval_id}/decision")
    def decide_approval(approval_id: str, body: DecisionIn, db: Session = Depends(get_db)):
        now = _utcnow()
        _expire_pending(db, now)
        row = db.get(McpApprovalDB, approval_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"error": "Approval not found"})
        new_status = "approved" if body.decision == "approve" else "denied"
        # one conditional UPDATE: two approvers racing cannot both win
        updated = (
            db.query(McpApprovalDB)
            .filter(
                McpApprovalDB.id == approval_id,
                McpApprovalDB.status == "pending",
                McpApprovalDB.expires_at > now,
            )
            .update({"status": new_status, "decided_at": now}, synchronize_session=False)
        )
        db.commit()
        if updated == 0:
            db.refresh(row)
            raise HTTPException(
                status_code=409,
                detail={"error": "Approval is not pending", "status": row.status},
            )
        db.refresh(row)
        return _approval_dict(row)

    return router
