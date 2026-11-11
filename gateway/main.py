#backend
import io
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import Boolean, Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from detection import analyze_prompt

# 1. create a SQLite database connection and session factory
SQLALCHEMY_DATABASE_URL = os.environ.get(
    "DATABASE_URL", "sqlite:///./security_gateway.db"
)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# 2.  organize the database table structure for request logs
class RequestLogDB(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    prompt = Column(String, nullable=False)
    is_blocked = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)
    threat_type = Column(String, default="None")
    # TODO: datetime.utcnow() is deprecated; switching to timezone-aware
    # datetimes changes stored data, so it is deliberately left as is for now.
    timestamp = Column(DateTime, default=datetime.utcnow)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # create the database tables if they don't exist (on startup, not on import)
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="GenAI Security Gateway", lifespan=lifespan)


def get_db():
    """Yield a database session for the duration of a request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# data model for the request body
class PromptRequest(BaseModel):
    prompt: str


# Helper function to save request logs using the given session
def save_log_to_db(
    db: Session,
    prompt: str,
    is_blocked: bool,
    risk_score: int,
    threat_type: str,
):
    db_log = RequestLogDB(
        prompt=prompt,
        is_blocked=is_blocked,
        risk_score=risk_score,
        threat_type=threat_type,
    )
    db.add(db_log)
    db.commit()


# Liveness probe (used by the Docker healthcheck); does not touch the database
@app.get("/health")
def health():
    return {"status": "ok"}


# Endpoint for receiving prompts, inspection, and direct synchronous logging
@app.post("/inspect")
def inspect_prompt(request: PromptRequest, db: Session = Depends(get_db)):
    result = analyze_prompt(request.prompt)

    # log first, so blocked requests are recorded before the 403 is raised
    save_log_to_db(
        db,
        request.prompt,
        result.is_blocked,
        result.risk_score,
        result.threat_type,
    )

    if result.is_blocked:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Request blocked by GenAI Security Gateway",
                "threat": result.threat_type,
            },
        )

    return {
        "status": "Allowed",
        "risk_score": result.risk_score,
        "message": "Prompt passed security checks successfully",
    }


#  Statistics endpoint for the dashboard
@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total_requests = db.query(RequestLogDB).count()
    blocked_injections = (
        db.query(RequestLogDB)
        .filter(RequestLogDB.threat_type == "Prompt Injection")
        .count()
    )
    dlp_prevented = (
        db.query(RequestLogDB)
        .filter(RequestLogDB.threat_type == "DLP Violation")
        .count()
    )

    return {
        "total_requests": total_requests,
        "blocked_injections": blocked_injections,
        "data_leaks_prevented": dlp_prevented,
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
