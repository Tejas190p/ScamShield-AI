def detect_category_signals(message: str, category: str) -> list:
    """
    Detect category-specific warning signals.

    These signals strengthen the rule-based assessment.
    They are warning indicators, not proof of fraud.
    """

    text = message.lower()

    signals = []

    # ========================================================
    # FINANCIAL / BANK
    # ========================================================

    if category == "Financial / Bank":

        if "otp" in text:
            signals.append({
                "reason": "Request for an OTP",
                "points": 3,
            })

        if "cvv" in text:
            signals.append({
                "reason": "Request for a CVV",
                "points": 3,
            })

        if "pin" in text:
            signals.append({
                "reason": "Request for a PIN",
                "points": 3,
            })

        if "kyc" in text:
            signals.append({
                "reason": "KYC verification request",
                "points": 2,
            })

        if "account suspended" in text or "account will be suspended" in text:
            signals.append({
                "reason": "Account suspension threat",
                "points": 3,
            })

        if "unauthorized transaction" in text:
            signals.append({
                "reason": "Unauthorized transaction claim",
                "points": 2,
            })

    # ========================================================
    # JOB / INTERNSHIP
    # ========================================================

    elif category == "Job / Internship":

        payment_words = [
            "registration fee",
            "registration fees",
            "security deposit",
            "training fee",
            "processing fee",
            "joining fee",
            "pay ₹",
            "pay rs",
            "pay inr",
        ]

        if any(word in text for word in payment_words):
            signals.append({
                "reason": "Upfront payment requested for a job",
                "points": 3,
            })

        if "guaranteed job" in text or "guaranteed employment" in text:
            signals.append({
                "reason": "Guaranteed employment claim",
                "points": 2,
            })

        if "selected" in text and (
            "job" in text or
            "position" in text or
            "work from home" in text
        ):
            signals.append({
                "reason": "Job selection without clear hiring context",
                "points": 2,
            })

        if "high salary" in text or "₹50,000" in text:
            signals.append({
                "reason": "Unusually attractive salary claim",
                "points": 2,
            })

    # ========================================================
    # PRIZE / REWARD
    # ========================================================

    elif category == "Prize / Reward":

        if "you won" in text or "winner" in text:
            signals.append({
                "reason": "Unexpected prize or winning claim",
                "points": 3,
            })

        if "claim your reward" in text or "claim prize" in text:
            signals.append({
                "reason": "Prize claim request",
                "points": 2,
            })

        if "lucky draw" in text or "lottery" in text:
            signals.append({
                "reason": "Lottery or lucky-draw claim",
                "points": 2,
            })

        if "claim immediately" in text or "claim now" in text:
            signals.append({
                "reason": "Pressure to claim a reward immediately",
                "points": 2,
            })

    # ========================================================
    # DELIVERY / PARCEL
    # ========================================================

    elif category == "Delivery / Parcel":

        if "delivery failed" in text or "delivery has failed" in text:
            signals.append({
                "reason": "Delivery failure claim",
                "points": 2,
            })

        if "reschedule" in text:
            signals.append({
                "reason": "Delivery rescheduling request",
                "points": 1,
            })

        if "delivery fee" in text or "shipping fee" in text:
            signals.append({
                "reason": "Delivery fee request",
                "points": 2,
            })

        if "tracking number" not in text and "tracking id" not in text:
            signals.append({
                "reason": "No tracking information provided",
                "points": 1,
            })

        if "customs fee" in text:
            signals.append({
                "reason": "Customs fee request",
                "points": 2,
            })

    # ========================================================
    # ACCOUNT / VERIFICATION
    # ========================================================

    elif category == "Account / Verification":

        if "verify your account" in text:
            signals.append({
                "reason": "Account verification request",
                "points": 2,
            })

        if "account suspended" in text:
            signals.append({
                "reason": "Account suspension threat",
                "points": 3,
            })

        if "password reset" in text:
            signals.append({
                "reason": "Password reset request",
                "points": 2,
            })

        if "login verification" in text:
            signals.append({
                "reason": "Login verification request",
                "points": 2,
            })

    # ========================================================
    # PHISHING / SUSPICIOUS LINK
    # ========================================================

    elif category == "Phishing / Suspicious Link":

        if "http://" in text:
            signals.append({
                "reason": "Unencrypted HTTP link",
                "points": 2,
            })

        if "click" in text:
            signals.append({
                "reason": "Request to click a link",
                "points": 2,
            })

        if "login" in text:
            signals.append({
                "reason": "Link associated with login activity",
                "points": 2,
            })

        if "verify" in text:
            signals.append({
                "reason": "Link associated with verification",
                "points": 2,
            })

    return signals