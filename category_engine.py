import re


def detect_category(message: str, analysis: dict) -> str:
    text = (message or "").lower()

    # High-return crypto investment schemes.
    crypto_scam_terms = [
        "guaranteed 500%", "guaranteed returns", "crypto bot",
        "crypto trading scheme", "double-crypto-returns",
        "500% returns", "ai automated crypto",
    ]
    if any(term in text for term in crypto_scam_terms):
        return "Prize / Reward"

    # Fake WhatsApp Gold branding paired with a download link.
    if "whatsapp gold" in text and (
        "http://" in text or "https://" in text or "www." in text
    ):
        return "Phishing / Suspicious Link"

    # Specific impersonation and suspicious-link patterns.
    if any(p in text for p in [
        "hey mom", "hey dad", "lost my phone", "lost my wallet"
    ]):
        return "Impersonation"

    if any(p in text for p in [".top/", ".xyz/", "secure-bank"]):
        return "Phishing / Suspicious Link"

    # Payslips and payroll notifications are financial messages,
    # but these terms alone are not evidence of fraud.
    if any(term in text for term in [
        "payslip", "pay slip", "salary slip", "payroll",
        "salary statement"
    ]):
        return "Financial / Bank"

    if "salary" in text and any(
        term in text for term in ["credited", "bank", "rs", "inr"]
    ):
        return "Financial / Bank"

    reward_words = [
        "congratulations", "you won", "winner", "prize",
        "reward", "lottery", "cash prize", "gift", "lucky draw",
    ]
    job_words = [
        "job offer", "job opportunity", "internship",
        "work from home", "part time job", "salary",
        "hiring", "selected for the job", "recruitment",
        "scholarship", "student scholarship", "merit scholarship",
    ]
    delivery_words = [
        "delivery", "parcel", "package", "courier",
        "shipment", "delivery fee", "customs fee",
    ]
    account_words = [
        "verify your account", "account verification",
        "account needs verification", "account suspended",
        "account will be suspended", "account blocked",
        "login verification", "security verification",
        "password reset", "password", "login credentials",
        "sign in", "sign-in", "kyc",
        "account frozen", "account freeze", "frozen",
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

    job_fee_terms = (
        "registration fee", "registration fees", "security deposit",
        "training fee", "processing fee", "joining fee",
    )
    has_job_context = any(word in text for word in job_words) or any(
        phrase in text for phrase in ["job selection", "job selected"]
    )

    # A job or scholarship fee request takes priority over generic
    # prize/reward wording.
    if has_job_context and any(term in text for term in job_fee_terms):
        return "Job / Internship"

    # Loan approval plus an upfront fee is a financial scam pattern.
    if (
        any(term in text for term in [
            "personal loan", "pre-approved loan", "loan approved",
        ])
        and any(term in text for term in [
            "processing fee", "file processing fee", "security deposit",
            "registration fee",
        ])
    ):
        return "Financial / Bank"

    # Crypto recovery offers with a clearance fee and release promise.
    if (
        any(term in text for term in [
            "btc", "bitcoin", "crypto",
        ])
        and any(term in text for term in [
            "clearance fee", "network fee", "release funds",
        ])
        and any(term in text for term in [
            "inactive account", "pay", "fee",
        ])
    ):
        return "Prize / Reward"

    has_prize_amount_claim = bool(
        re.search(
            r"\byou win\b.{0,30}\b\d+(?:[.,]\d+)?\s*k?\b",
            text,
        )
    )

    if any(word in text for word in reward_words) or has_prize_amount_claim:
        return "Prize / Reward"

    if has_job_context:
        return "Job / Internship"

    if any(word in text for word in ["cvv", "security code"]):
        return "Account / Verification"

    if any(word in text for word in account_words):
        return "Account / Verification"

    # Handle SIM deactivation and utility disconnection threats
    # before the generic financial fallback.
    if re.search(r"\b(sim|electricity|power)\b", text) and re.search(
        r"\b(deactivat\w*|disconnect\w*|suspend\w*|block\w*)\b", text
    ):
        return "Account / Verification"

    if any(word in text for word in delivery_words):
        return "Delivery / Parcel"

    if any(word in text for word in impersonation_words):
        return "Impersonation"

    # OTP messages about an actual login belong to account verification.
    if (
        ("otp" in text or "one-time password" in text)
        and any(term in text for term in [
            "login", "log in", "netbanking", "net banking",
        ])
    ):
        return "Account / Verification"

    if any(word in text for word in bank_words):
        return "Financial / Bank"

    if re.search(r"\b(trojan|virus|infection|tech support|microsoft)\b", text):
        return "Impersonation"

    if re.search(r"\b(tax|refund|challan|fine|loan|crypto|btc)\b", text):
        return "Financial / Bank"

    # A URL by itself is not proof of phishing.
    return "General / Unknown"
