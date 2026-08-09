#backend
from datetime import datetime
from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import Boolean, Column, DateTime, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# 1. create a SQLite database connection and session
SQLALCHEMY_DATABASE_URL = "sqlite:///./security_gateway.db"
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
  timestamp = Column(DateTime, default=datetime.utcnow)


# create the database tables if they don't exist
Base.metadata.create_all(bind=engine)

app = FastAPI(title="GenAI Security Gateway")


# data model for the request body
class PromptRequest(BaseModel):
  prompt: str


# Helper function to save request logs directly to the database
def save_log_to_db(
    prompt: str, is_blocked: bool, risk_score: int, threat_type: str
):
  db = SessionLocal()
  try:
    db_log = RequestLogDB(
        prompt=prompt,
        is_blocked=is_blocked,
        risk_score=risk_score,
        threat_type=threat_type,
    )
    db.add(db_log)
    db.commit()
  finally:
    db.close()


# Endpoint for receiving prompts, inspection, and direct synchronous logging@app.post("/inspect")
def inspect_prompt(request: PromptRequest):

  prompt_text = request.prompt.lower()
  is_blocked = False
  risk_score = 10
  threat_type = "Safe"

  if "ignore previous" in prompt_text or "system prompt" in prompt_text:
    is_blocked = True
    risk_score = 95
    threat_type = "Prompt Injection"

  elif "credit card" in prompt_text or "password" in prompt_text:
    is_blocked = True
    risk_score = 80
    threat_type = "DLP Violation"

  save_log_to_db(request.prompt, is_blocked, risk_score, threat_type)

  if is_blocked:
    raise HTTPException(
        status_code=403,
        detail={
            "error": "Request blocked by GenAI Security Gateway",
            "threat": threat_type,
        },
    )

  return {
      "status": "Allowed",
      "risk_score": risk_score,
      "message": "Prompt passed security checks successfully",
  }


#  Statistics endpoint for the dashboard
@app.get("/stats")
def get_stats():
  db = SessionLocal()
  try:
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
  finally:
    db.close()


#______________________________________________________________________________________

import os
from fastapi.responses import FileResponse
import pandas as pd


@app.get("/export-excel")
def export_logs_to_excel():

    df = pd.read_sql("SELECT * FROM request_logs", con=engine)

    # file name for the Excel file
    file_path = "security_audit_logs.xlsx"

    # save as Excel file
    df.to_excel(file_path, index=False)

    # return the Excel file as a response
    return FileResponse(
        path=file_path,
        filename="security_audit_logs.xlsx",
        media_type=(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ),
    )