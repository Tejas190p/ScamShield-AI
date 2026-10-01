from fastapi import FastAPI
from pydantic import BaseModel

from app import analyze_message, calculate_risk


# ============================================================
# SCAMSHIELD AI - FASTAPI BACKEND
# ============================================================

app = FastAPI(
    title="ScamShield AI API",
    description="API for analyzing suspicious messages.",
    version="1.0.0"
)


# ============================================================
# REQUEST MODEL
# ============================================================

class ScanRequest(BaseModel):
    message: str


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def home():
    return {
        "name": "ScamShield AI",
        "status": "online",
        "version": "1.0.0"
    }


# ============================================================
# SCAN ENDPOINT
# ============================================================

@app.post("/scan")
def scan_message(request: ScanRequest):

    result = analyze_message(request.message)

    score, level, reasons = calculate_risk(result)

    return {
        "message": request.message,
        "risk_level": level,
        "risk_score": score,
        "reasons": reasons
    }