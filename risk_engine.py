import re

def merge_risk_signals(base_score, base_reasons, category_signals, message=""):
    score = base_score
    reasons = list(base_reasons)

    # Extract reason descriptions normalized to lowercase strings
    existing_reasons = {
        (r.get("reason", "") if isinstance(r, dict) else str(r)).strip().lower()
        for r in reasons
    }

    for sig in category_signals:
        sig_reason = (sig.get("reason", "") if isinstance(sig, dict) else str(sig)).strip().lower()
        if sig_reason and sig_reason not in existing_reasons:
            reasons.append(sig)
            existing_reasons.add(sig_reason)
            score += sig.get("points", 0) if isinstance(sig, dict) else 0

    if message:
        msg_lower = message.lower()

        if re.search(r'\b(disconnected|deactivated|cut off|power will be|sim.*deactivat)\b', msg_lower):
            if not any("disconnection" in t or "suspension" in t for t in existing_reasons):
                r = {"reason": "Service disconnection or account deactivation threat", "points": 3}
                reasons.append(r)
                existing_reasons.add(r["reason"].lower())
                score += 3

        if re.search(r'\b(card number|cvv|expiry|card details|16-digit)\b', msg_lower):
            if not any("card" in t or "sensitive" in t for t in existing_reasons):
                r = {"reason": "Request for sensitive card or payment details", "points": 4}
                reasons.append(r)
                existing_reasons.add(r["reason"].lower())
                score += 4

        if re.search(r'\b(trojan|virus|infected|infection|tech support|microsoft detected)\b', msg_lower):
            if not any("malware" in t for t in existing_reasons):
                r = {"reason": "Fake security or malware threat claim", "points": 4}
                reasons.append(r)
                existing_reasons.add(r["reason"].lower())
                score += 4

        if re.search(r'\b(tax refund|e-challan|traffic fine|challan notice|scholarship.*fee)\b', msg_lower):
            if not any("government" in t or "tax" in t for t in existing_reasons):
                r = {"reason": "Government, tax, or penalty notice demand", "points": 3}
                reasons.append(r)
                existing_reasons.add(r["reason"].lower())
                score += 3

        if re.search(r'https?://[^\s]+\.(top|xyz|site|club|info|click|online)\b', msg_lower):
            if not any("top-level domain" in t or "tld" in t for t in existing_reasons):
                r = {"reason": "URL uses a high-risk or non-standard top-level domain", "points": 3}
                reasons.append(r)
                existing_reasons.add(r["reason"].lower())
                score += 3

    return score, reasons


def get_risk_level(score: int) -> str:
    """Convert the final risk score into a risk level."""

    if score >= 6:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score >= 1:
        return "LOW"

    return "NO OBVIOUS INDICATORS"