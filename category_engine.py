def detect_category(message: str, analysis: dict) -> str:
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
    ]

    if any(word in text for word in reward_words):
        return "Prize / Reward"

    if any(word in text for word in job_words):
        return "Job / Internship"

    if any(word in text for word in account_words):
        return "Account / Verification"

    if any(word in text for word in delivery_words):
        return "Delivery / Parcel"

    if any(word in text for word in impersonation_words):
        return "Impersonation"

    if any(word in text for word in bank_words):
        return "Financial / Bank"

    if analysis.get("urls"):
        return "Phishing / Suspicious Link"

    return "General / Unknown"
