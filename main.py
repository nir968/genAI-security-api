from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

app = FastAPI(title="GenAI Security API")

class PromptRequest(BaseModel):
    text: str

class SecurityAnalysisResponse(BaseModel):
    received_text: str
    risk_score: int
    severity: str
    threat_categories: List[str]
    message: str

# מילוני מילות מפתח לפי קטגוריות איום
PROMPT_INJECTION_KEYWORDS = ["ignore previous instructions", "bypass", "jailbreak", "override"]
SYSTEM_EXPOSURE_KEYWORDS = ["system prompt", "developer mode", "reveal instructions"]
DATA_EXFILTRATION_KEYWORDS = ["show passwords", "api key", "database dump", "secret key"]

@app.post("/analyze", response_model=SecurityAnalysisResponse)
def analyze_prompt(request: PromptRequest):
    text_lower = request.text.lower()
    
    detected_categories = []
    score = 0
    
    # 1. זיהוי ניסיון עקיפה (Prompt Injection)
    if any(kw in text_lower for kw in PROMPT_INJECTION_KEYWORDS):
        detected_categories.append("Prompt Injection")
        score += 40
        
    # 2. זיהוי ניסיון חשיפה (System Prompt Exposure)
    if any(kw in text_lower for kw in SYSTEM_EXPOSURE_KEYWORDS):
        detected_categories.append("System Prompt Exposure")
        score += 35

    # 3. זיהוי ניסיון גניבת מידע רגיש (Data Exfiltration)
    if any(kw in text_lower for kw in DATA_EXFILTRATION_KEYWORDS):
        detected_categories.append("Data Exfiltration")
        score += 50

    # חישוב ציון סיכון כולל (עד מקסימום 100)
    risk_score = min(score, 100)
    
    # קביעת רמת חומרה (Severity Level)
    if risk_score == 0:
        severity = "SAFE"
        message = "Prompt appears safe."
    elif risk_score <= 40:
        severity = "LOW"
        message = "Low risk detected. Proceed with caution."
    elif risk_score <= 70:
        severity = "MEDIUM"
        message = "Medium risk detected! Potential jailbreak or manipulation attempt."
    else:
        severity = "HIGH"
        message = "HIGH RISK DETECTED! Potential severe exploit attempt."

    return {
        "received_text": request.text,
        "risk_score": risk_score,
        "severity": severity,
        "threat_categories": detected_categories,
        "message": message
    }

@app.get("/")
def read_root():
    return {"status": "API is up and running!"}