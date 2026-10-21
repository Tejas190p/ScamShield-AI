
def get_risk_level(score):
    if score == 0:
        return "NO OBVIOUS INDICATORS"
    elif score <= 3:
        return "LOW"
    elif score <= 5:
        return "MEDIUM"
    else:
        return "HIGH"


def merge_risk_signals(
    base_score,
    base_reasons,
    category_signals,
    message="",
):
    score = base_score
    reasons = list(base_reasons)

    def reason_text(item):
        if isinstance(item, dict):
            return str(item.get("reason", "")).strip().lower()
        return str(item).strip().lower()

    existing = {
        reason_text(item)
        for item in reasons
        if reason_text(item)
    }

    # Detect risks already represented by the base reasons.
    has_sensitive_info = any(
        "sensitive personal information" in text
        or "sensitive information" in text
        for text in existing
    )

    has_suspension_threat = any(
        "suspension" in text
        or "threat or account" in text
        for text in existing
    )

    has_payment_language = any(
        "money or payment-related language" in text
        for text in existing
    )

    for signal in category_signals:
        if not isinstance(signal, dict):
            continue

        text = reason_text(signal)
        if not text or text in existing:
            continue

        # Avoid double-counting the same underlying risk.
        if (
            has_sensitive_info
            and any(term in text for term in ("pin", "otp", "cvv"))
        ):
            continue

        if (
            has_suspension_threat
            and ("suspension" in text or "deactivation" in text)
        ):
            continue

        if has_payment_language and any(
            term in text for term in ("delivery fee request", "customs fee request")
        ):
            continue

        reasons.append(signal)
        existing.add(text)
        score += signal.get("points", 0)

    return score, reasons
