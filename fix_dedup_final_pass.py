from pathlib import Path
import re

risk_path = Path("risk_engine.py")
src = risk_path.read_text(encoding="utf-8")

clean_merge = '''def merge_risk_signals(base_score, base_reasons, category_signals, message=""):
    score = base_score
    reasons = list(base_reasons)

    # 1. Build a set of existing reason descriptions (normalized)
    def get_reason_text(r):
        if isinstance(r, dict):
            return str(r.get("reason", "")).strip().lower()
        return str(r).strip().lower()

    existing_texts = {get_reason_text(r) for r in reasons if get_reason_text(r)}

    # 2. Add category signals only if their reason description is not already present
    for sig in category_signals:
        sig_text = get_reason_text(sig)
        if sig_text and sig_text not in existing_texts:
            reasons.append(sig)
            existing_texts.add(sig_text)
            # Only increment score if sig is a new signal not covered in base_score
            score += sig.get("points", 0) if isinstance(sig, dict) else 0

    # 3. Only run pattern regexes on raw message text if message is explicitly provided
    if message:
        msg_lower = message.lower()

        if re.search(r'\\b(disconnected|deactivated|cut off|power will be|sim.*deactivat)\\b', msg_lower):
            if not any("disconnection" in t or "deactivation" in t or "suspension" in t for t in existing_texts):
                r = {"reason": "Service disconnection or account deactivation threat", "points": 3}
                reasons.append(r)
                existing_texts.add(get_reason_text(r))
                score += 3

        if re.search(r'\\b(card number|cvv|expiry|card details|16-digit)\\b', msg_lower):
            if not any("card" in t or "sensitive" in t for t in existing_texts):
                r = {"reason": "Request for sensitive card or payment details", "points": 4}
                reasons.append(r)
                existing_texts.add(get_reason_text(r))
                score += 4

        if re.search(r'\\b(trojan|virus|infected|infection|tech support|microsoft detected)\\b', msg_lower):
            if not any("malware" in t or "trojan" in t for t in existing_texts):
                r = {"reason": "Fake security or malware threat claim", "points": 4}
                reasons.append(r)
                existing_texts.add(get_reason_text(r))
                score += 4

        if re.search(r'\\b(tax refund|e-challan|traffic fine|challan notice|scholarship.*fee)\\b', msg_lower):
            if not any("government" in t or "tax" in t or "penalty" in t for t in existing_texts):
                r = {"reason": "Government, tax, or penalty notice demand", "points": 3}
                reasons.append(r)
                existing_texts.add(get_reason_text(r))
                score += 3

        if re.search(r'https?://[^\\s]+\\.(top|xyz|site|club|info|click|online)\\b', msg_lower):
            if not any("top-level domain" in t or "tld" in t for t in existing_texts):
                r = {"reason": "URL uses a high-risk or non-standard top-level domain", "points": 3}
                reasons.append(r)
                existing_texts.add(get_reason_text(r))
                score += 3

    return score, reasons
'''

# Find def merge_risk_signals and replace it completely
pattern = r'def merge_risk_signals\(.*?\):\n(?:    .*\n)*'
if re.search(pattern, src):
    new_src = re.sub(pattern, clean_merge + "\n", src)
    risk_path.write_text(new_src, encoding="utf-8")
    print("Replaced merge_risk_signals function successfully.")
else:
    print("Could not locate merge_risk_signals with regex pattern.")
