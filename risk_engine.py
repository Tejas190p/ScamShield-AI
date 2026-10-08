from category_signals import detect_category_signals


def merge_risk_signals(
    base_score: int,
    base_reasons: list,
    category_signals: list,
) -> tuple:
    """
    Merge base detection signals with category-specific signals.

    Category signals that represent the same evidence already detected
    by the base engine are not counted twice.
    """

    reasons = list(base_reasons)
    score = base_score

    existing_reasons = {
        reason["reason"].lower()
        for reason in base_reasons
    }

    for signal in category_signals:

        signal_reason = signal["reason"]
        signal_key = signal_reason.lower()

        # Avoid duplicate evidence
        duplicate = False

        if "otp" in signal_key:
            duplicate = any(
                "sensitive personal information" in reason
                for reason in existing_reasons
            )

        elif "cvv" in signal_key:
            duplicate = any(
                "sensitive personal information" in reason
                for reason in existing_reasons
            )

        elif "account suspension" in signal_key:
            duplicate = any(
                "threat" in reason or
                "suspension" in reason
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
    """
    Convert the final risk score into a risk level.
    """

    if score >= 7:
        return "HIGH"

    if score >= 4:
        return "MEDIUM"

    if score >= 1:
        return "LOW"

    return "NO OBVIOUS INDICATORS"