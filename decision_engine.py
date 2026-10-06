def build_final_assessment(
    risk_level: str,
    risk_score: int,
    reasons: list,
    ai_analysis: str,
) -> dict:
    """
    Combines the rule-based detection result with
    the AI explanation into one final assessment.
    """

    if risk_level == "HIGH":
        recommendation = (
            "Do not respond, click links, send money, or share sensitive "
            "information. Verify the request through an official source."
        )

        assessment = (
            "High-risk indicators were detected. The message should be "
            "treated with strong caution."
        )

    elif risk_level == "MEDIUM":
        recommendation = (
            "Do not act immediately. Verify the sender and request through "
            "an independent, trusted source before taking action."
        )

        assessment = (
            "Several suspicious indicators were detected. Verify the "
            "message carefully before taking action."
        )

    elif risk_level == "LOW":
        recommendation = (
            "Review the message carefully and verify unexpected requests "
            "before taking action."
        )

        assessment = (
            "A small number of warning indicators were detected."
        )

    else:
        recommendation = (
            "No obvious warning indicators were detected, but remain "
            "careful with unexpected requests."
        )

        assessment = (
            "No obvious warning indicators were detected by the rule engine."
        )

    return {
        "final_risk_level": risk_level,
        "risk_score": risk_score,
        "assessment": assessment,
        "warning_indicators": reasons,
        "ai_analysis": ai_analysis,
        "recommended_action": recommendation,
    }