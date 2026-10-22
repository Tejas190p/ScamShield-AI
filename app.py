
import re
import ipaddress
from urllib.parse import urlparse

from sensitive_detection import is_sensitive_request


URGENT_WORDS = [
    "urgent",
    "immediately",
    "now",
    "today",
    "act fast",
    "within 24 hours",
    "limited time",
]

MONEY_WORDS = [
    "money",
    "payment",
    "pay",
    "transfer",
    "fee",
    "cash",
    "amount",
    "â‚¹",
    "rs",
    "inr",
]

REWARD_WORDS = [
    "congratulations",
    "you won",
    "winner",
    "prize",
    "reward",
    "lottery",
    "cash prize",
    "gift",
]

THREAT_WORDS = [
    "suspended",
    "account suspended",
    "account will be suspended",
    "blocked",
    "legal action",
    "police",
    "penalty",
    "fine",
    "deactivated",
    "deactivation",
    "will be deactivated",
    "disconnected",
    "disconnection",
    "power will be disconnected",
]

PERSONAL_INFO_WORDS = [
    "otp",
    "cvv",
    "password",
    "pin",
    "credit card",
    "debit card",
    "bank details",
    "personal information",
]

CONTACT_WORDS = [
    "call me",
    "call us",
    "contact us",
    "contact immediately",
    "whatsapp",
    "telegram",
    "call customer executive",
]

BANK_IMPERSONATION_WORDS = [
    "bank officer",
    "customer support",
    "official representative",
]

TOO_GOOD_WORDS = [
    "guaranteed",
    "easy money",
    "risk free",
    "double your money",
    "free money",
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
]

SUSPICIOUS_HOST_TERMS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "claim",
    "free",
    "prize",
]

URL_PATTERN = r"https?://[^\s<>]+|www\.[^\s<>]+"


def analyze_url(url: str) -> dict:
    """Analyze a URL for suspicious characteristics."""

    findings = []
    clean_url = url.rstrip(".,!?;:)]}")

    parsed = urlparse(
        clean_url
        if clean_url.lower().startswith(("http://", "https://"))
        else "http://" + clean_url
    )

    hostname = parsed.hostname or ""

    # Direct IP address
    try:
        ipaddress.ip_address(hostname)
        findings.append({
            "message": "URL uses a direct IP address",
            "points": 2,
        })
    except ValueError:
        pass

    # URL shortener
    if hostname.lower() in SHORTENERS:
        findings.append({
            "message": "URL uses a known link-shortening service",
            "points": 1,
        })

    # Punycode
    if "xn--" in hostname.lower():
        findings.append({
            "message": "URL contains punycode",
            "points": 2,
        })

    # HTTP instead of HTTPS
    if clean_url.lower().startswith("http://"):
        findings.append({
            "message": "URL uses HTTP instead of HTTPS",
            "points": 1,
        })

    # Username/password embedded in URL
    if parsed.username or parsed.password:
        findings.append({
            "message": (
                "URL contains embedded username or password information"
            ),
            "points": 2,
        })

    # @ symbol
    if "@" in clean_url:
        findings.append({
            "message": "URL contains an @ symbol",
            "points": 2,
        })

    # Suspicious hostname terms
    matched_terms = [
        term
        for term in SUSPICIOUS_HOST_TERMS
        if term in hostname.lower()
    ]

    if matched_terms:
        findings.append({
            "message": (
                "URL hostname contains attention-grabbing terms: "
                + ", ".join(matched_terms)
            ),
            "points": 1,
        })

    return {
        "url": clean_url,
        "findings": findings,
    }


def analyze_message(message: str) -> dict:
    """Analyze a message for common scam warning patterns."""

    text = message.lower()

    categories = {
        "urgent": [],
        "money": [],
        "reward": [],
        "threat": [],
        "personal_info": [],
        "contact": [],
        "bank_impersonation": [],
        "too_good": [],
    }

    for word in URGENT_WORDS:
        if word in text:
            categories["urgent"].append(word)

    for word in MONEY_WORDS:
        if word in text:
            categories["money"].append(word)

    for word in REWARD_WORDS:
        if word in text:
            categories["reward"].append(word)

    for word in THREAT_WORDS:
        if word in text:
            categories["threat"].append(word)

    # Only match sensitive terms when the message appears to request them.
    for word in PERSONAL_INFO_WORDS:
        if word in text and is_sensitive_request(text, word):
            categories["personal_info"].append(word)

    for word in CONTACT_WORDS:
        if word in text:
            categories["contact"].append(word)

    for word in BANK_IMPERSONATION_WORDS:
        if word in text:
            categories["bank_impersonation"].append(word)

    for word in TOO_GOOD_WORDS:
        if word in text:
            categories["too_good"].append(word)

    urls = re.findall(URL_PATTERN, message)

    url_results = [
        analyze_url(url)
        for url in urls
    ]

    return {
        "message": message,
        "categories": categories,
        "urls": urls,
        "url_results": url_results,
    }


def calculate_risk(result: dict) -> tuple:
    """Calculate the base rule-based risk score."""

    categories = result["categories"]
    score = 0
    reasons = []

    # Urgency counts only when paired with a risky context.
    message_text = result.get("message", "").lower()
    has_urgency = bool(categories.get("urgent"))
    has_threat_context = bool(categories.get("threat"))
    has_sensitive_context = bool(categories.get("personal_info"))

    payment_phrases = (
        "pay now",
        "pay immediately",
        "payment required",
        "send money",
        "transfer money",
        "registration fee",
        "processing fee",
        "joining fee",
        "training fee",
        "security deposit",
    )
    has_payment_demand = any(
        phrase in message_text for phrase in payment_phrases
    )

    if has_urgency and (
        has_threat_context or has_payment_demand or has_sensitive_context
    ):
        score += 2
        reasons.append({
            "reason": "Urgency combined with a threat, payment demand, or sensitive-information request",
            "points": 2,
        })

    # Money: ordinary payment mentions are not risk indicators by themselves.
    money_context_words = (
        "pay a fee",
        "processing fee",
        "registration fee",
        "registration fees",
        "security deposit",
        "joining fee",
        "training fee",
        "send money",
        "transfer money",
        "pay immediately",
        "pay now",
        "payment required",
        "claim fee",
    )
    if any(phrase in result.get("message", "").lower()
           for phrase in money_context_words):
        score += 2
        reasons.append({
            "reason": "Potential payment demand",
            "points": 2,
        })

    # Reward
    if categories["reward"]:
        score += 2
        reasons.append({
            "reason": "Prize or unexpected-benefit language",
            "points": 2,
        })

    # Threat
    if categories["threat"]:
        score += 3
        reasons.append({
            "reason": "Threat or account-suspension language",
            "points": 3,
        })

    # Sensitive information request
    if categories["personal_info"]:
        score += 3
        reasons.append({
            "reason": "Request for sensitive personal information",
            "points": 3,
        })

    # Contact
    if categories["contact"]:
        score += 1
        reasons.append({
            "reason": "Unusual contact request",
            "points": 1,
        })

    # Bank impersonation
    if categories["bank_impersonation"]:
        score += 2
        reasons.append({
            "reason": "Bank or support impersonation language",
            "points": 2,
        })

    # Too-good-to-be-true
    if categories["too_good"]:
        score += 2
        reasons.append({
            "reason": "Unusually attractive or guaranteed claim",
            "points": 2,
        })

    # URL analysis
    for url_result in result["url_results"]:
        for finding in url_result["findings"]:
            score += finding["points"]
            reasons.append({
                "reason": finding["message"],
                "points": finding["points"],
            })

    # Emergency family impersonation / urgency payment
    if "lost my phone" in message_text or ("upi" in message_text and ("urgent" in message_text or "help" in message_text)):
        score += 5
        reasons.append({"reason": "Urgent emergency payment request from unrecognized number", "points": 5})

    
    # Shortener link combined with action/fee
    if ("bit.ly" in message_text or "tinyurl" in message_text) and ("fee" in message_text or "pay" in message_text or "failed" in message_text):
        score += 2
        reasons.append({"reason": "Shortened link combined with action demand", "points": 2})

    # Extreme crypto-return promises combined with an upfront deposit.
    crypto_investment_terms = (
        "crypto bot",
        "crypto trading",
        "automated crypto",
        "bitcoin investment",
    )
    extreme_return_terms = (
        "guaranteed 500%",
        "500% returns",
        "guaranteed returns",
        "double-crypto-returns",
    )
    deposit_terms = (
        "deposit",
        "registration fee",
        "processing fee",
        "send money",
        "transfer money",
    )

    if (
        any(term in message_text for term in crypto_investment_terms)
        and any(term in message_text for term in extreme_return_terms)
        and any(term in message_text for term in deposit_terms)
    ):
        score += 4
        reasons.append({
            "reason": "Extreme crypto-return promise combined with an upfront deposit",
            "points": 4,
        })

    # Fake WhatsApp Gold download link.
    if (
        "whatsapp gold" in message_text
        and ("http://" in message_text or "https://" in message_text)
    ):
        score += 4
        reasons.append({
            "reason": "Fake WhatsApp Gold branding combined with a download link",
            "points": 4,
        })

    # Card-blocking threat combined with a request for card credentials.
    if (
        any(term in message_text for term in [
            "debit card", "credit card", "card is blocked",
        ])
        and any(term in message_text for term in [
            "cvv", "16-digit card number", "card number",
        ])
        and any(term in message_text for term in [
            "share", "send", "provide", "unblock",
        ])
    ):
        score += 3
        reasons.append({
            "reason": "Card-blocking threat combined with a request for card credentials",
            "points": 3,
        })

    # A delivery PIN notification is a mild caution signal, not proof of fraud.
    if (
        "out for delivery" in message_text
        and "delivery pin" in message_text
        and not any(term in message_text for term in [
            "share your pin", "send your pin", "tell us your pin",
            "provide your pin", "pay a fee", "delivery fee",
        ])
    ):
        score += 1
        reasons.append({
            "reason": "Delivery PIN mentioned in a shipment notification",
            "points": 1,
        })

    # Fake social-media verification badge asking for credentials.
    if (
        "blue verification badge" in message_text
        and "password" in message_text
        and ("http://" in message_text or "https://" in message_text)
    ):
        score += 1
        reasons.append({
            "reason": "Verification badge impersonation with a credential request and link",
            "points": 1,
        })

    # Fake WhatsApp lucky-draw prize requiring direct contact to claim.
    if (
        "lucky draw" in message_text
        and "whatsapp" in message_text
        and "won" in message_text
        and "claim" in message_text
        and any(term in message_text for term in [
            "contact manager", "claim manager", "contact mr."
        ])
    ):
        score += 3
        reasons.append({
            "reason": "Large lucky-draw claim with a direct-contact request",
            "points": 3,
        })

    # Fake traffic challan combining a court threat and payment link.
    if (
        ("challan" in message_text or "traffic violation" in message_text)
        and ("court referral" in message_text or "court" in message_text)
        and ("http://" in message_text or "https://" in message_text)
        and any(term in message_text for term in ["pay fine", "pending fine"])
    ):
        score += 2
        reasons.append({
            "reason": "Traffic-fine threat combined with a payment link",
            "points": 2,
        })

    # A delivery-fee demand gains extra weight when paired with a URL.
    if (
        any(term in message_text for term in [
            "delivery fee", "redelivery fee",
        ])
        and any(term in message_text for term in [
            "failed", "reschedule", "redelivery", "cannot be delivered",
        ])
        and any(term in message_text for term in [
            "pay", "payment", "fee",
        ])
        and bool(result.get("urls"))
    ):
        score += 3
        reasons.append({
            "reason": "Delivery problem and fee demand combined with a link",
            "points": 3,
        })

    # Utility-disconnection threats combined with payment pressure.
    if (
        any(term in message_text for term in [
            "disconnected", "disconnection",
        ])
        and any(term in message_text for term in [
            "electricity", "power bill", "utility bill",
        ])
        and any(term in message_text for term in [
            "pay", "payment", "tonight", "immediately",
        ])
    ):
        score += 2
        reasons.append({
            "reason": "Utility-disconnection threat with payment pressure",
            "points": 2,
        })

    # Tech-support scareware: malware warning plus an urgent support call.
    if (
        any(term in message_text for term in [
            "trojan", "virus infection", "malware",
        ])
        and any(term in message_text for term in [
            "technical support", "tech support",
        ])
        and any(term in message_text for term in [
            "call", "contact",
        ])
    ):
        score += 6
        reasons.append({
            "reason": "Malware warning combined with an urgent tech-support call",
            "points": 6,
        })

    # Loan approval plus an upfront processing fee.
    if (
        any(term in message_text for term in [
            "personal loan", "pre-approved loan", "loan is approved",
        ])
        and any(term in message_text for term in [
            "processing fee", "file processing fee", "security deposit",
        ])
    ):
        score += 2
        reasons.append({
            "reason": "Loan approval paired with an upfront fee",
            "points": 2,
        })

    # Fake tax-refund links requesting account details.
    if (
        any(term in message_text for term in [
            "tax refund", "income tax refund",
        ])
        and bool(result.get("urls"))
        and any(term in message_text for term in [
            "account details", "bank details", "submit account",
        ])
    ):
        score += 5
        reasons.append({
            "reason": "Tax-refund claim with a link requesting account details",
            "points": 5,
        })

    # Crypto recovery offers demanding clearance fees to release funds.
    if (
        any(term in message_text for term in [
            "btc", "bitcoin", "crypto",
        ])
        and any(term in message_text for term in [
            "clearance fee", "network fee",
        ])
        and any(term in message_text for term in [
            "release funds", "inactive account",
        ])
    ):
        score += 5
        reasons.append({
            "reason": "Crypto recovery offer demanding a clearance fee",
            "points": 5,
        })

    # Risk level
    if score >= 6:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    elif score >= 1:
        level = "LOW"
    else:
        level = "NO OBVIOUS INDICATORS"

    

    return score, level, reasons




