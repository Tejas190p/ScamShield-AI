
def detect_category(message: str, analysis: dict) -> str:
    """
    Detect the most likely scam category using
    message patterns and existing analysis results.

    This is a classification aid, not proof that
    a message is fraudulent.
    """

    text = message.lower()

    # ========================================================
    # BANK / FINANCIAL
    # ========================================================

    bank_words = [
        "bank",
        "account",
        "otp",
        "cvv",
        "pin",
        "debit card",
        "credit card",
        "upi",
        "kyc",
        "transaction",
        "payment",
        "bank details",
        "account number",
        "atm",
        "net banking",
    ]

    if any(word in text for word in bank_words):
        return "Financial / Bank"

    # ========================================================
    # JOB / INTERNSHIP SCAMS
    # ========================================================

    job_words = [
        "job offer",
        "job opportunity",
        "internship",
        "work from home",
        "part time job",
        "salary",
        "hiring",
        "selected for the job",
        "recruitment",
    ]

    if any(word in text for word in job_words):
        return "Job / Internship"

    # ========================================================
    # PRIZE / REWARD SCAMS
    # ========================================================

    reward_words = [
        "congratulations",
        "you won",
        "winner",
        "prize",
        "reward",
        "lottery",
        "cash prize",
        "gift",
        "lucky draw",
    ]

    if any(word in text for word in reward_words):
        return "Prize / Reward"

    # ========================================================
    # ACCOUNT / VERIFICATION
    # ========================================================

    account_words = [
        "verify your account",
        "account verification",
        "account suspended",
        "account blocked",
        "login verification",
        "security verification",
        "password reset",
        "password",
        "login credentials",
        "sign in",
        "sign-in",
    ]

    if any(word in text for word in account_words):
        return "Account / Verification"

    # ========================================================
    # DELIVERY / PARCEL
    # ========================================================

    delivery_words = [
        "delivery",
        "parcel",
        "package",
        "courier",
        "shipment",
        "delivery fee",
        "customs fee",
    ]

    if any(word in text for word in delivery_words):
        return "Delivery / Parcel"

    # ========================================================
    # IMPERSONATION
    # ========================================================

    impersonation_words = [
        "bank officer",
        "police officer",
        "government officer",
        "income tax department",
        "customer support",
        "official representative",
        "support team",
    ]

    if any(word in text for word in impersonation_words):
        return "Impersonation"

    # ========================================================
    # URL-BASED PHISHING
    # ========================================================

    if analysis.get("urls"):
        return "Phishing / Suspicious Link"

    return "General / Unknown"

