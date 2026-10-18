def detect_category(message: str, analysis: dict) -> str:
    msg_lower = message.lower() if message else ""
    if any(p in msg_lower for p in ["hey mom", "hey dad", "lost my phone", "lost my wallet"]):
        return "Impersonation"
    if any(p in msg_lower for p in [".top/", ".xyz/", "secure-bank"]):
        return "Phishing / Suspicious Link"
    if "salary" in msg_lower and ("credited" in msg_lower or "bank" in msg_lower or "rs" in msg_lower):
        return "Financial / Bank"
    """
    Classify a message using its strongest contextual indicators.
    A category is a clue, not proof of fraud.
    """
    text = message.lower()

    # Specific contexts take priority over generic financial terms.
    reward_words = [
        "congratulations", "you won", "winner", "prize",
        "reward", "lottery", "cash prize", "gift", "lucky draw",
    ]
    job_words = [
        "job offer", "job opportunity", "internship",
        "work from home", "part time job", "salary",
        "hiring", "selected for the job", "recruitment",
    ]
    delivery_words = [
        "delivery", "parcel", "package", "courier",
        "shipment", "delivery fee", "customs fee",
    ]
    account_words = [
        "verify your account", "account verification",
        "account needs verification",
        "account suspended", "account will be suspended",
        "account blocked", "login verification", "security verification",
        "password reset", "password", "login credentials",
        "sign in", "sign-in",
    ]
    impersonation_words = [
        "bank officer", "police officer", "government officer",
        "income tax department", "customer support",
        "official representative", "support team",
    ]
    bank_words = [
        "bank", "account", "otp", "cvv", "pin", "debit card",
        "credit card", "upi", "kyc", "transaction", "payment",
        "bank details", "account number", "atm", "net banking",
        "refund", "reimbursement",
    ]

    # Prioritize job-related fee requests over generic congratulations.
    job_fee_terms = (
        "registration fee", "registration fees", "security deposit",
        "training fee", "processing fee", "joining fee",
    )
    has_job_context = any(word in text for word in job_words) or (
        "job selection" in text or "job selected" in text
    )
    if has_job_context and any(term in text for term in job_fee_terms):
        return "Job / Internship"
    if any(word in text for word in reward_words):
        return "Prize / Reward"

    if any(word in text for word in job_words):
        return "Job / Internship"

    # Sensitive card-verification requests need specific classification.
    if any(word in text for word in ["cvv", "security code"]):
        return "Account / Verification"

    if any(word in text for word in account_words):
        return "Account / Verification"

    if any(word in text for word in delivery_words):
        return "Delivery / Parcel"

    if any(word in text for word in impersonation_words):
        return "Impersonation"

    if any(word in text for word in bank_words):
        return "Financial / Bank"

    # A URL alone is not evidence of phishing.
    return "General / Unknown"

    return "General / Unknown"

