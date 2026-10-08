import re
import ipaddress
from urllib.parse import urlparse


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
    "₹",
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
]

BANK_IMPERSONATION_WORDS = [
    "bank",
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
    """
    Analyze a URL for suspicious characteristics.
    """

    findings = []

    clean_url = url.rstrip(".,!?;:)]}")
    parsed = urlparse(
        clean_url if clean_url.startswith(("http://", "https://"))
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

    # Username/password inside URL
    if parsed.username or parsed.password:
        findings.append({
            "message": "URL contains embedded username or password information",
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
    """
    Analyze a message for common scam warning patterns.
    """

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

    for word in PERSONAL_INFO_WORDS:
        if word in text:
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
        "categories": categories,
        "urls": urls,
        "url_results": url_results,
    }


def calculate_risk(result: dict) -> tuple:
    """
    Calculate the base rule-based risk score.
    """

    categories = result["categories"]

    score = 0
    reasons = []

    # Urgency
    if categories["urgent"]:
        score += 2
        reasons.append({
            "reason": "Urgent or pressure-based language",
            "points": 2,
        })

    # Money
    if categories["money"]:
        score += 2
        reasons.append({
            "reason": "Money or payment-related language",
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

    # Personal information
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

    # Risk level
    if score >= 7:
        level = "HIGH"

    elif score >= 4:
        level = "MEDIUM"

    elif score >= 1:
        level = "LOW"

    else:
        level = "NO OBVIOUS INDICATORS"

    return score, level, reasons