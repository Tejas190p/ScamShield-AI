
import re
import ipaddress
from urllib.parse import urlparse


# Existing scam indicator patterns
URGENT_WORDS = [
    "urgent", "immediately", "act now", "hurry",
    "last chance", "expires today", "within 24 hours",
]

MONEY_WORDS = [
    "pay", "payment", "fee", "deposit",
    "transfer money", "send money", "bank account", "upi",
]

REWARD_WORDS = [
    "you won", "winner", "congratulations", "prize",
    "reward", "lottery", "cashback", "free money",
]

THREAT_WORDS = [
    "account will be blocked", "account suspended",
    "legal action", "police", "arrest", "penalty",
    "account will be suspended",
]

PERSONAL_INFO_WORDS = [
    "password", "otp", "verification code", "cvv",
    "card number", "aadhaar", "pan number",
]

CONTACT_WORDS = [
    "call me", "call this number", "contact me",
    "whatsapp me", "message me on whatsapp", "send a message",
]

BANK_WORDS = [
    "bank security", "bank verification", "account verification",
    "customer support", "official bank", "bank officer",
    "income tax department", "government officer",
]

TOO_GOOD_WORDS = [
    "guaranteed profit", "double your money", "100% guaranteed",
    "risk free", "easy money", "instant money", "free gift",
]

# Known URL-shortening services.
# A short link is a caution indicator, not proof of a scam.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rebrand.ly", "shorturl.at",
}

URL_PATTERN = r"https?://[^\s<>]+|www\.[^\s<>]+"


def contains_pattern(text, patterns):
    text = text.lower()
    return [p for p in patterns if p in text]


def find_urls(text):
    matches = re.findall(URL_PATTERN, text, re.IGNORECASE)

    # Remove common punctuation that follows a link in a sentence.
    return [
        url.rstrip(".,!?;:)]}\"'")
        for url in matches
    ]


def analyze_url(raw_url):
    findings = []
    candidate = raw_url

    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if not hostname:
            return ["Could not reliably parse this URL."]

        hostname = hostname.lower().rstrip(".")

        # URLs containing usernames/passwords before the host
        if parsed.username is not None or parsed.password is not None:
            findings.append(
                "URL contains an unexpected username/password section."
            )

        # IP address used instead of a regular domain
        try:
            ipaddress.ip_address(hostname)
            findings.append(
                "URL uses a direct IP address instead of a domain name."
            )
        except ValueError:
            pass

        # URL shorteners can hide the final destination.
        if hostname in SHORTENERS:
            findings.append(
                "URL uses a link-shortening service; destination is hidden."
            )

        # Internationalized domains can use punycode.
        if "xn--" in hostname:
            findings.append(
                "Domain contains punycode; inspect the domain carefully."
            )

        # A secure connection is not proof that a site is trustworthy.
        if parsed.scheme.lower() == "http":
            findings.append(
                "URL uses HTTP rather than HTTPS; the connection may not be encrypted."
            )

        # Look for common deceptive URL structures.
        if "@" in candidate:
            findings.append(
                "URL contains an @ symbol, which can make its destination confusing."
            )

        # Look for words commonly used in deceptive links.
        suspicious_terms = [
            "login", "verify", "secure", "account",
            "update", "claim", "free", "prize",
        ]

        matched_terms = [
            term for term in suspicious_terms
            if term in hostname
        ]

        if matched_terms:
            findings.append(
                "Domain contains attention-grabbing terms: "
                + ", ".join(matched_terms)
                + "."
            )

        if not findings:
            findings.append(
                "No listed URL warning patterns detected. "
                "This does not prove the link is safe."
            )

    except (ValueError, UnicodeError):
        findings.append("URL could not be analyzed reliably.")

    return findings


def analyze_message(message):
    indicators = []

    categories = {
        "urgent": contains_pattern(message, URGENT_WORDS),
        "money": contains_pattern(message, MONEY_WORDS),
        "reward": contains_pattern(message, REWARD_WORDS),
        "threat": contains_pattern(message, THREAT_WORDS),
        "personal_info": contains_pattern(message, PERSONAL_INFO_WORDS),
        "contact": contains_pattern(message, CONTACT_WORDS),
        "bank": contains_pattern(message, BANK_WORDS),
        "too_good": contains_pattern(message, TOO_GOOD_WORDS),
    }

    urls = find_urls(message)
    url_results = []

    for url in urls:
        url_results.append({
            "url": url,
            "findings": analyze_url(url),
        })

    explanations = {
        "urgent": "Urgent or pressure-based language detected.",
        "money": "Money or payment-related language detected.",
        "reward": "Prize, reward, or unexpected-benefit language detected.",
        "threat": "Threat or account-consequence language detected.",
        "personal_info": "Sensitive personal information may be requested.",
        "contact": "Unusual contact or communication request detected.",
        "bank": "Possible financial institution or authority impersonation language detected.",
        "too_good": "Potentially unrealistic financial or promotional claim detected.",
    }

    for category, matches in categories.items():
        if matches:
            indicators.append(explanations[category])

    for result in url_results:
        for finding in result["findings"]:
            if not finding.startswith("No listed URL warning"):
                indicators.append(f"URL warning: {finding}")

    return {
        **categories,
        "urls": urls,
        "url_results": url_results,
        "indicators": indicators,
    }


def calculate_risk(result):
    score = 0

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

    for category, weight in weights.items():
        if result[category]:
            score += weight

    # Add points for specific URL warning patterns.
    for url_result in result["url_results"]:
        for finding in url_result["findings"]:
            if "IP address" in finding:
                score += 2
            elif "shortening service" in finding:
                score += 1
            elif "username/password section" in finding:
                score += 2
            elif "punycode" in finding:
                score += 2
            elif "HTTP rather than HTTPS" in finding:
                score += 1
            elif "@ symbol" in finding:
                score += 2
            elif "attention-grabbing terms" in finding:
                score += 1

    if score >= 7:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    elif score >= 1:
        level = "LOW"
    else:
        level = "NO OBVIOUS INDICATORS"

    return score, level


def display_result(result, score, level):
    print("\n" + "=" * 60)
    print("                 SCAMSHIELD AI")
    print("=" * 60)

    print(f"\nRisk level: {level}")
    print(f"Risk score: {score}")

    print("\nMessage indicators:")

    if result["indicators"]:
        for number, indicator in enumerate(
            result["indicators"], start=1
        ):
            print(f"{number}. {indicator}")
    else:
        print("No obvious message or URL warning patterns detected.")

    if result["url_results"]:
        print("\nURL ANALYSIS")

        for item in result["url_results"]:
            print(f"\nURL: {item['url']}")

            for finding in item["findings"]:
                print(f"- {finding}")

    print("\nImportant:")
    print(
        "This tool checks known warning patterns. "
        "It does not verify a website's reputation or prove a link is safe."
    )
    print("=" * 60)


def main():
    print("=" * 60)
    print("                 SCAMSHIELD AI")
    print("=" * 60)
    print("\nPaste a suspicious message below.")
    print("Press Enter twice when finished.")

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
    score, level = calculate_risk(result)
    display_result(result, score, level)


if __name__ == "__main__":
    main()