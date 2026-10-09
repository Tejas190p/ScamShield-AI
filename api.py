
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import analyze_message, calculate_risk
from ai_service import analyze_with_ai
from decision_engine import build_final_assessment
from category_engine import detect_category
from category_signals import detect_category_signals
from risk_engine import merge_risk_signals, get_risk_level


# ==========================================
# CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATABASE_NAME = str(BASE_DIR / "scans.db")


app = FastAPI(
    title="ScamShield AI API",
    description="AI-assisted API for analyzing suspicious messages.",
    version="1.7.0",
)


# ==========================================
# WEBSITE FRONTEND
# ==========================================

if not STATIC_DIR.is_dir():
    raise RuntimeError(
        f"Static website folder was not found: {STATIC_DIR}"
    )

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static",
)


@app.get("/", include_in_schema=False)
def serve_homepage():
    return FileResponse(STATIC_DIR / "index.html")


# ==========================================
# REQUEST AND RESPONSE MODELS
# ==========================================

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
    category: str
    assessment: str
    warning_indicators: list
    ai_analysis: str
    recommended_action: str
    saved_to_history: bool


# ==========================================
# HOME AND HEALTH
# ==========================================

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


# ==========================================
# MESSAGE SCANNING
# ==========================================

@app.post("/scan", response_model=ScanResponse)
def scan_message(request: ScanRequest):

    message = request.message.strip()

    if not message:
        raise HTTPException(
            status_code=422,
            detail="Message cannot be empty or whitespace only",
        )

    # 1. BASE RULE-BASED DETECTION
    result = analyze_message(message)
    score, level, reasons = calculate_risk(result)

    # 2. DETECT SCAM CATEGORY
    category = detect_category(
        message,
        result,
    )

    # 3. CATEGORY-SPECIFIC SIGNALS
    category_signals = detect_category_signals(
        message,
        category,
    )

    # 4. MERGE SIGNALS WITHOUT DOUBLE-COUNTING
    score, reasons = merge_risk_signals(
        base_score=score,
        base_reasons=reasons,
        category_signals=category_signals,
    )

    level = get_risk_level(score)

    # 5. GEMINI AI ANALYSIS
    ai_analysis = analyze_with_ai(message)

    # 6. BUILD FINAL ASSESSMENT
    final_result = build_final_assessment(
        risk_level=level,
        risk_score=score,
        reasons=reasons,
        ai_analysis=ai_analysis,
    )

    # 7. SAVE SCAN TO SQLITE
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

    # 8. RETURN FINAL RESULT
    return ScanResponse(
        message=message,
        final_risk_level=final_result["final_risk_level"],
        risk_score=final_result["risk_score"],
        category=category,
        assessment=final_result["assessment"],
        warning_indicators=final_result["warning_indicators"],
        ai_analysis=ai_analysis,
        recommended_action=final_result["recommended_action"],
        saved_to_history=True,
    )


# ==========================================
# SCAN HISTORY
# ==========================================

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
                SELECT
                    id,
                    scanned_at,
                    message,
                    risk_level,
                    risk_score
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