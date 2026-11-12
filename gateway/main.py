#backend
import io
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import Boolean, Column, DateTime, Integer, String, create_engine, or_
from sqlalchemy.orm import Session, sessionmaker

from db_base import Base
from detection import DLP_THREAT_TYPES, DetectionResult, analyze_prompt
from dlp import engine as dlp_engine
from llm import LLMProvider, build_provider_from_env
from mcp_security import create_mcp_router
from migrations import migrate_schema

logger = logging.getLogger("gateway")

# 1. create a SQLite database connection and session factory
SQLALCHEMY_DATABASE_URL = os.environ.get(
    "DATABASE_URL", "sqlite:///./security_gateway.db"
)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# longest prompt / chat message accepted, in characters
MAX_PROMPT_CHARS = int(os.environ.get("MAX_PROMPT_CHARS", "20000"))


# 2.  organize the database table structure for request logs
class RequestLogDB(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    # never the raw text when the DLP engine found something: see _audit_view
    prompt = Column(String, nullable=False)
    is_blocked = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)
    threat_type = Column(String, default="None")
    # TODO: datetime.utcnow() is deprecated; switching to timezone-aware
    # datetimes changes stored data, so it is deliberately left as is for now.
    timestamp = Column(DateTime, default=datetime.utcnow)
    # added by migrations.migrate_schema for databases created before DLP
    action = Column(String, default="allow")
    direction = Column(String, default="input")  # "input" | "output"
    data_types = Column(String, default="")  # comma-separated


@asynccontextmanager
async def lifespan(app: FastAPI):
    # create the database tables if they don't exist (on startup, not on import)
    Base.metadata.create_all(bind=engine)
    migrate_schema(engine)
    # validate the DLP policy and LLM settings now: a bad config stops the app
    dlp_engine.init_policy()
    app.state.llm_provider = build_provider_from_env()
    yield


app = FastAPI(title="GenAI Security Gateway", lifespan=lifespan)


def get_db():
    """Yield a database session for the duration of a request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# /scan, /mcp/events, /mcp/stats, /mcp/approvals: the MCP security proxy API
app.include_router(create_mcp_router(get_db))


def get_llm_provider(request: Request) -> LLMProvider:
    """The provider chosen at startup; tests override this dependency."""
    provider = getattr(request.app.state, "llm_provider", None)
    return provider if provider is not None else build_provider_from_env()


# data models for the request bodies
class PromptRequest(BaseModel):
    prompt: str


class ChatRequest(BaseModel):
    message: str


# Helper function to save request logs using the given session
def save_log_to_db(
    db: Session,
    prompt: str,
    is_blocked: bool,
    risk_score: int,
    threat_type: str,
    action: str = "allow",
    direction: str = "input",
    data_types=(),
):
    db_log = RequestLogDB(
        prompt=prompt,
        is_blocked=is_blocked,
        risk_score=risk_score,
        threat_type=threat_type,
        action=action,
        direction=direction,
        data_types=",".join(data_types),
    )
    db.add(db_log)
    db.commit()


def _check_length(text: str):
    if len(text) > MAX_PROMPT_CHARS:
        raise HTTPException(
            status_code=413,
            detail={"error": "Input too long", "max_chars": MAX_PROMPT_CHARS},
        )


def _audit_view(text: str, result: DetectionResult):
    """(text, data types) that are safe to store in the audit log.

    Every DLP finding is masked, including alert-only ones. For an injection
    the DLP engine did not run during detection, so it runs here, for the
    audit log only, so credentials pasted into an attack are not stored raw.
    """
    scan = result.dlp if result.dlp is not None else dlp_engine.scan(text)
    if not scan.findings:
        return text, []
    return dlp_engine.mask_text(text, scan.findings), scan.data_types


def _blocked_exception(result: DetectionResult) -> HTTPException:
    detail = {
        "error": "Request blocked by GenAI Security Gateway",
        "threat": result.threat_type,
    }
    if result.dlp is not None:
        detail["data_types"] = result.dlp.data_types
    return HTTPException(status_code=403, detail=detail)


def _log_input(db: Session, text: str, result: DetectionResult):
    audit_text, data_types = _audit_view(text, result)
    save_log_to_db(
        db,
        audit_text,
        result.is_blocked,
        result.risk_score,
        result.threat_type,
        result.action,
        "input",
        data_types,
    )


# Liveness probe (used by the Docker healthcheck); does not touch the database
@app.get("/health")
def health():
    return {"status": "ok"}


# Endpoint for receiving prompts, inspection, and direct synchronous logging
@app.post("/inspect")
def inspect_prompt(request: PromptRequest, db: Session = Depends(get_db)):
    _check_length(request.prompt)
    result = analyze_prompt(request.prompt)

    # log first, so blocked requests are recorded before the 403 is raised
    _log_input(db, request.prompt, result)

    if result.is_blocked:
        raise _blocked_exception(result)

    if result.action == "redact":
        return {
            "status": "Redacted",
            "risk_score": result.risk_score,
            "redacted_prompt": result.dlp.redacted_text,
            "data_types": result.dlp.data_types,
        }

    response = {
        "status": "Allowed",
        "risk_score": result.risk_score,
        "message": "Prompt passed security checks successfully",
    }
    if result.action == "alert":
        response["alerts"] = result.dlp.data_types
    return response


# Chat endpoint: input scan -> LLM -> output scan
@app.post("/chat")
def chat(
    request: ChatRequest,
    db: Session = Depends(get_db),
    provider: LLMProvider = Depends(get_llm_provider),
):
    _check_length(request.message)

    # 1. input scan (injection + DLP, same rules as /inspect)
    result = analyze_prompt(request.message)
    _log_input(db, request.message, result)
    if result.is_blocked:
        raise _blocked_exception(result)

    # a redacted message is what the model gets to see
    model_input = (
        result.dlp.redacted_text if result.action == "redact" else request.message
    )

    # 2. call the provider; never expose provider internals to the client
    try:
        answer = provider.complete(model_input)
    except Exception as exc:
        logger.warning("LLM provider call failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail={"error": "LLM provider error"})

    # 3. output scan: whatever the policy flags is redacted
    output = dlp_engine.scan(answer, direction="output")
    save_log_to_db(
        db,
        dlp_engine.mask_text(answer, output.findings),
        False,
        output.risk_score,
        DLP_THREAT_TYPES[output.action],
        output.action,
        "output",
        output.data_types,
    )

    return {
        "response": output.redacted_text,
        "input_action": result.action,
        "output_action": output.action,
        "data_types": {
            "input": result.dlp.data_types if result.dlp is not None else [],
            "output": output.data_types,
        },
    }


#  Statistics endpoint for the dashboard
@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    # "requests" are input events; /chat also logs an output event per turn
    total_requests = (
        db.query(RequestLogDB)
        .filter(or_(RequestLogDB.direction == "input", RequestLogDB.direction.is_(None)))
        .count()
    )
    blocked_injections = (
        db.query(RequestLogDB)
        .filter(RequestLogDB.threat_type == "Prompt Injection")
        .count()
    )
    # DLP blocks + DLP redactions, on either direction
    dlp_prevented = (
        db.query(RequestLogDB)
        .filter(
            RequestLogDB.threat_type.in_(
                [DLP_THREAT_TYPES["block"], DLP_THREAT_TYPES["redact"]]
            )
        )
        .count()
    )
    redactions = db.query(RequestLogDB).filter(RequestLogDB.action == "redact").count()
    alerts = db.query(RequestLogDB).filter(RequestLogDB.action == "alert").count()

    return {
        "total_requests": total_requests,
        "blocked_injections": blocked_injections,
        "data_leaks_prevented": dlp_prevented,
        "redactions": redactions,
        "alerts": alerts,
        "status": "Active & Secure",
    }


#  History endpoint powering the dashboard's activity chart
@app.get("/history")
def get_history(hours: int = 24, db: Session = Depends(get_db)):
    if hours < 1 or hours > 720:
        raise HTTPException(
            status_code=400, detail="hours must be between 1 and 720"
        )

    # timestamps are written with datetime.utcnow(), so compare against UTC
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    rows = (
        db.query(RequestLogDB)
        .filter(RequestLogDB.timestamp >= cutoff)
        .order_by(RequestLogDB.timestamp)
        .all()
    )

    records = []
    for row in rows:
        if row.timestamp is None:
            continue

        # The column is naive UTC. Without an explicit "Z" the browser would
        # read the ISO string as local time and shift every chart bucket by
        # the viewer's UTC offset.
        stamp = row.timestamp.replace(tzinfo=timezone.utc)

        records.append({
            "timestamp": stamp.isoformat().replace("+00:00", "Z"),
            "blocked": bool(row.is_blocked),
            "threat_type": row.threat_type,
            "risk_score": row.risk_score,
            "prompt": row.prompt,
            # rows from before the DLP migration may hold NULLs
            "action": row.action or ("block" if row.is_blocked else "allow"),
            "direction": row.direction or "input",
            "data_types": [t for t in (row.data_types or "").split(",") if t],
        })

    return {"records": records}


@app.get("/export-excel")
def export_logs_to_excel(db: Session = Depends(get_db)):
    df = pd.read_sql("SELECT * FROM request_logs", con=db.connection())

    # Build the workbook in memory; nothing is written to the filesystem
    buffer = io.BytesIO()
    df.to_excel(buffer, index=False)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type=(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ),
        headers={
            "Content-Disposition": 'attachment; filename="security_audit_logs.xlsx"'
        },
    )
