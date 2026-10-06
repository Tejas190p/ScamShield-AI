from datetime import datetime, timezone
import sqlite3

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app import analyze_message, calculate_risk
from ai_service import analyze_with_ai
from decision_engine import build_final_assessment


DATABASE_NAME = "scans.db"


app = FastAPI(
    title="ScamShield AI API",
    description="AI-assisted API for analyzing suspicious messages.",
    version="1.4.0",
)


class ScanRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Message to analyze",
        examples=[
            "Your bank account will be suspended. Send your OTP immediately."
        ],
    )


class ScanResponse(BaseModel):
    message: str
    final_risk_level: str
    risk_score: int
    assessment: str
    warning_indicators: list
    ai_analysis: str
    recommended_action: str
    saved_to_history: bool


@app.get("/")
def home():
    return {
        "name": "ScamShield AI",
        "status": "online",
        "version": app.version,
    }


@app.get("/health")
def health():
    try:
        with sqlite3.connect(DATABASE_NAME) as connection:
            connection.execute("SELECT 1")

        return {
            "status": "healthy",
            "database": "connected",
        }

    except sqlite3.Error:
        raise HTTPException(
            status_code=503,
            detail="Database is unavailable",
        )


@app.post("/scan", response_model=ScanResponse)
def scan_message(request: ScanRequest):
    message = request.message.strip()

    if not message:
        raise HTTPException(
            status_code=422,
            detail="Message cannot be empty or whitespace only",
        )

    # 1. Python rule-based detection
    result = analyze_message(message)
    score, level, reasons = calculate_risk(result)

    # 2. Gemini AI analysis
    ai_analysis = analyze_with_ai(message)

    # 3. Build combined final assessment
    final_result = build_final_assessment(
        risk_level=level,
        risk_score=score,
        reasons=reasons,
        ai_analysis=ai_analysis,
    )

    # 4. Save scan to SQLite
    try:
        with sqlite3.connect(DATABASE_NAME) as connection:
            connection.execute(
                """
                INSERT INTO scans
                    (scanned_at, message, risk_level, risk_score)
                VALUES (?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    message,
                    level,
                    score,
                ),
            )

    except sqlite3.Error:
        raise HTTPException(
            status_code=500,
            detail="Could not save scan history",
        )

    return ScanResponse(
        message=message,
        final_risk_level=final_result["final_risk_level"],
        risk_score=final_result["risk_score"],
        assessment=final_result["assessment"],
        warning_indicators=final_result["warning_indicators"],
        ai_analysis=final_result["ai_analysis"],
        recommended_action=final_result["recommended_action"],
        saved_to_history=True,
    )


@app.get("/history")
def scan_history(limit: int = 20):
    if not 1 <= limit <= 100:
        raise HTTPException(
            status_code=422,
            detail="Limit must be between 1 and 100",
        )

    try:
        with sqlite3.connect(DATABASE_NAME) as connection:
            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT id, scanned_at, message, risk_level, risk_score
                FROM scans
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return {
            "count": len(rows),
            "scans": [dict(row) for row in rows],
        }

    except sqlite3.Error:
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve scan history",
        )