import re
import ipaddress
from urllib.parse import urlparse


# ============================================================
# SCAMSHIELD AI - INDICATOR DATABASE
# ============================================================

URGENT_WORDS = [
    "urgent",
    "immediately",
    "act now",
    "hurry",
    "last chance",
    "expires today",
    "within 24 hours",
]

MONEY_WORDS = [
    "pay",
    "payment",
    "fee",
    "deposit",
    "transfer money",
    "send money",
    "bank account",
    "upi",
]

REWARD_WORDS = [
    "you won",
    "winner",
    "congratulations",
    "prize",
    "reward",
    "lottery",
    "cashback",
    "free money",
]

THREAT_WORDS = [
    "account will be blocked",
    "account suspended",
    "account will be suspended",
    "legal action",
    "police",
    "arrest",
    "penalty",
]

PERSONAL_INFO_WORDS = [
    "password",
    "otp",
    "verification code",
    "cvv",
    "card number",
    "aadhaar",
    "pan number",
]

CONTACT_WORDS = [
    "call me",
    "call this number",
    "contact me",
    "whatsapp me",
    "message me on whatsapp",
    "send a message",
]

BANK_WORDS = [
    "bank security",
    "bank verification",
    "account verification",
    "customer support",
    "official bank",
    "bank officer",
    "income tax department",
    "government officer",
]

TOO_GOOD_WORDS = [
    "guaranteed profit",
    "double your money",
    "100% guaranteed",
    "risk free",
    "easy money",
    "instant money",
    "free gift",
]

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
}

URL_PATTERN = r"https?://[^\s<>]+|www\.[^\s<>]+"


# ============================================================
# TEXT HELPERS
# ============================================================

def contains_pattern(text, patterns):
    text = text.lower()

    return [
        pattern
        for pattern in patterns
        if pattern in text
    ]


def find_urls(text):
    matches = re.findall(
        URL_PATTERN,
        text,
        re.IGNORECASE
    )

    return [
        url.rstrip(".,!?;:)]}\"'")
        for url in matches
    ]


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(raw_url):
    findings = []

    candidate = raw_url

    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if not hostname:
            return [
                "Could not reliably parse this URL."
            ]

        hostname = hostname.lower().rstrip(".")

        # IP address
        try:
            ipaddress.ip_address(hostname)

            findings.append({
                "message":
                    "URL uses a direct IP address instead of a domain name.",
                "points": 2
            })

        except ValueError:
            pass

        # URL shortener
        if hostname in SHORTENERS:
            findings.append({
                "message":
                    "URL uses a link-shortening service; destination is hidden.",
                "points": 1
            })

        # Punycode
        if "xn--" in hostname:
            findings.append({
                "message":
                    "Domain contains punycode; inspect the domain carefully.",
                "points": 2
            })

        # HTTP
        if parsed.scheme.lower() == "http":
            findings.append({
                "message":
                    "URL uses HTTP rather than HTTPS.",
                "points": 1
            })

        # Username/password section
        if (
            parsed.username is not None
            or parsed.password is not None
        ):
            findings.append({
                "message":
                    "URL contains an unexpected username/password section.",
                "points": 2
            })

        # @ symbol
        if "@" in candidate:
            findings.append({
                "message":
                    "URL contains an @ symbol that can make the destination confusing.",
                "points": 2
            })

        # Attention-grabbing terms
        suspicious_terms = [
            "login",
            "verify",
            "secure",
            "account",
            "update",
            "claim",
            "free",
            "prize",
        ]

        matched_terms = [
            term
            for term in suspicious_terms
            if term in hostname
        ]

        if matched_terms:
            findings.append({
                "message":
                    "Domain contains attention-grabbing terms: "
                    + ", ".join(matched_terms) + ".",
                "points": 1
            })

        if not findings:
            findings.append({
                "message":
                    "No listed URL warning patterns detected.",
                "points": 0
            })

    except (ValueError, UnicodeError):
        findings.append({
            "message":
                "URL could not be analyzed reliably.",
            "points": 0
        })

    return findings


# ============================================================
# MESSAGE ANALYSIS
# ============================================================

def analyze_message(message):

    categories = {
        "urgent": contains_pattern(
            message,
            URGENT_WORDS
        ),

        "money": contains_pattern(
            message,
            MONEY_WORDS
        ),

        "reward": contains_pattern(
            message,
            REWARD_WORDS
        ),

        "threat": contains_pattern(
            message,
            THREAT_WORDS
        ),

        "personal_info": contains_pattern(
            message,
            PERSONAL_INFO_WORDS
        ),

        "contact": contains_pattern(
            message,
            CONTACT_WORDS
        ),

        "bank": contains_pattern(
            message,
            BANK_WORDS
        ),

        "too_good": contains_pattern(
            message,
            TOO_GOOD_WORDS
        ),
    }

    urls = find_urls(message)

    url_results = []

    for url in urls:

        url_results.append({
            "url": url,
            "findings": analyze_url(url)
        })

    return {
        **categories,
        "urls": urls,
        "url_results": url_results
    }


# ============================================================
# RISK SCORING
# ============================================================

def calculate_risk(result):

    score = 0
    reasons = []

    weights = {
        "urgent": 2,
        "money": 2,
        "reward": 2,
        "threat": 3,
        "personal_info": 3,
        "contact": 1,
        "bank": 2,
        "too_good": 2,
    }

    explanations = {
        "urgent":
            "Urgent or pressure-based language",

        "money":
            "Money or payment-related language",

        "reward":
            "Prize or unexpected-benefit language",

        "threat":
            "Threat or account-consequence language",

        "personal_info":
            "Request for sensitive personal information",

        "contact":
            "Unusual contact or communication request",

        "bank":
            "Possible financial institution or authority impersonation",

        "too_good":
            "Potentially unrealistic financial or promotional claim",
    }

    for category, weight in weights.items():

        if result[category]:

            score += weight

            reasons.append({
                "reason": explanations[category],
                "points": weight
            })

    # URL score
    for url_result in result["url_results"]:

        for finding in url_result["findings"]:

            points = finding["points"]

            if points > 0:

                score += points

                reasons.append({
                    "reason":
                        finding["message"],
                    "points":
                        points
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


# ============================================================
# RESULT DISPLAY
# ============================================================

def display_result(result, score, level, reasons):

    print("\n" + "=" * 60)
    print("                 SCAMSHIELD AI")
    print("=" * 60)

    print(f"\nRisk level: {level}")
    print(f"Risk score: {score}")

    print("\nWhy this score?")

    if reasons:

        for number, reason in enumerate(
            reasons,
            start=1
        ):

            print(
                f"{number}. "
                f"{reason['reason']} "
                f"(+{reason['points']} points)"
            )

    else:

        print(
            "No warning indicators contributed to the score."
        )

    if result["url_results"]:

        print("\nURL ANALYSIS")

        for item in result["url_results"]:

            print(f"\nURL: {item['url']}")

            for finding in item["findings"]:

                print(
                    f"- {finding['message']}"
                )

    print("\nAssessment:")

    if level == "HIGH":

        print(
            "Multiple warning indicators were detected. "
            "Use strong caution and verify the message "
            "through an independent source."
        )

    elif level == "MEDIUM":

        print(
            "Several warning indicators were detected. "
            "Verify the sender and request before taking action."
        )

    elif level == "LOW":

        print(
            "A small number of warning indicators were detected. "
            "Review the message carefully."
        )

    else:

        print(
            "No obvious warning indicators were detected."
        )

    print("\nImportant:")

    print(
        "This tool checks known warning patterns. "
        "It does not prove that a message is safe or fraudulent."
    )

    print("=" * 60)


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print("=" * 60)
    print("                 SCAMSHIELD AI")
    print("=" * 60)

    print(
        "\nPaste a suspicious message below."
    )

    print(
        "Press Enter twice when finished."
    )

    lines = []

    while True:

        line = input()

        if not line:
            break

        lines.append(line)

    message = " ".join(lines).strip()

    if not message:

        print("\nNo message entered.")
        return

    print("\nAnalyzing message...")

    result = analyze_message(message)

    score, level, reasons = calculate_risk(
        result
    )

    display_result(
        result,
        score,
        level,
        reasons
    )


if __name__ == "__main__":
    main()