
def merge_risk_signals(
    base_score: int,
    base_reasons: list,
    category_signals: list,
) -> tuple:
    """
    Merge base and category-specific risk signals.
    Avoid counting the same evidence twice.
    """

    reasons = list(base_reasons)
    score = base_score

    existing_reasons = {
        reason["reason"].lower()
        for reason in base_reasons
    }

    has_sensitive_info = any(
        "request for sensitive personal information" in reason
        for reason in existing_reasons
    )

    for signal in category_signals:
        signal_reason = signal["reason"]
        signal_key = signal_reason.lower()

        # Skip signals already represented by base evidence.
        duplicate = False

        if any(term in signal_key for term in ("otp", "cvv", "pin")):
            duplicate = has_sensitive_info

        elif "account suspension" in signal_key:
            duplicate = any(
                "threat" in reason or "suspension" in reason
                for reason in existing_reasons
            )

        elif "delivery fee request" in signal_key:
            duplicate = any(
                "money or payment-related language" in reason
                for reason in existing_reasons
            )

        if duplicate:
            continue

        score += signal["points"]
        reasons.append({
            "reason": signal_reason,
            "points": signal["points"],
        })
        existing_reasons.add(signal_key)

    return score, reasons


def get_risk_level(score: int) -> str:
    """Convert the final risk score into a risk level."""

    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score >= 1:
        return "LOW"

    return "NO OBVIOUS INDICATORS"