import re
import ipaddress
import sqlite3
from datetime import datetime
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

DATABASE_NAME = "scans.db"


# ============================================================
# DATABASE
# ============================================================

def init_database():
    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            message TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_scan(message, level, score):
    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    scanned_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute("""
        INSERT INTO scans
        (scanned_at, message, risk_level, risk_score)
        VALUES (?, ?, ?, ?)
    """, (
        scanned_at,
        message,
        level,
        score
    ))

    connection.commit()
    connection.close()


def view_history():
    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, scanned_at, risk_level, risk_score, message
        FROM scans
        ORDER BY id DESC
    """)

    scans = cursor.fetchall()

    connection.close()

    print("\n" + "=" * 60)
    print("                 SCAN HISTORY")
    print("=" * 60)

    if not scans:
        print("\nNo previous scans found.")
        return

    for scan in scans:

        scan_id = scan[0]
        scanned_at = scan[1]
        level = scan[2]
        score = scan[3]
        message = scan[4]

        print(f"\nScan #{scan_id}")
        print(f"Date: {scanned_at}")
        print(f"Risk level: {level}")
        print(f"Risk score: {score}")
        print(f"Message: {message}")

    print("\n" + "=" * 60)


# ============================================================
# REPORTS & STATISTICS
# ============================================================

def view_reports():
    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    # Total scans
    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
    """)

    total_scans = cursor.fetchone()[0]

    if total_scans == 0:
        connection.close()

        print("\n" + "=" * 60)
        print("                 SCAMSHIELD REPORT")
        print("=" * 60)
        print("\nNo scan data available yet.")
        print("Run some scans first.")
        return

    # Risk-level counts
    cursor.execute("""
        SELECT risk_level, COUNT(*)
        FROM scans
        GROUP BY risk_level
    """)

    level_counts = dict(cursor.fetchall())

    high_count = level_counts.get("HIGH", 0)
    medium_count = level_counts.get("MEDIUM", 0)
    low_count = level_counts.get("LOW", 0)
    no_indicator_count = level_counts.get(
        "NO OBVIOUS INDICATORS",
        0
    )

    # Average score
    cursor.execute("""
        SELECT AVG(risk_score)
        FROM scans
    """)

    average_score = cursor.fetchone()[0]

    # Highest score
    cursor.execute("""
        SELECT MAX(risk_score)
        FROM scans
    """)

    highest_score = cursor.fetchone()[0]

    # Lowest score
    cursor.execute("""
        SELECT MIN(risk_score)
        FROM scans
    """)

    lowest_score = cursor.fetchone()[0]

    connection.close()

    print("\n" + "=" * 60)
    print("                 SCAMSHIELD REPORT")
    print("=" * 60)

    print("\nOverall Statistics")

    print(f"\nTotal scans: {total_scans}")

    print(f"Average risk score: {average_score:.2f}")

    print(f"Highest risk score: {highest_score}")

    print(f"Lowest risk score: {lowest_score}")

    print("\nRisk Distribution")

    print(f"HIGH: {high_count}")

    print(f"MEDIUM: {medium_count}")

    print(f"LOW: {low_count}")

    print(
        f"NO OBVIOUS INDICATORS: "
        f"{no_indicator_count}"
    )

    print("\n" + "=" * 60)


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
                {
                    "message":
                        "Could not reliably parse this URL.",
                    "points": 0
                }
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

        # Username/password
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

        # Suspicious hostname terms
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
                "reason":
                    explanations[category],

                "points":
                    weight
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

def display_result(
    result,
    score,
    level,
    reasons
):

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

    # URL analysis
    if result["url_results"]:

        print("\nURL ANALYSIS")

        for item in result["url_results"]:

            print(
                f"\nURL: {item['url']}"
            )

            for finding in item["findings"]:

                print(
                    f"- {finding['message']}"
                )

    # Assessment
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
# SCAN MESSAGE
# ============================================================

def scan_message():

    print("\n" + "=" * 60)
    print("                 NEW SCAN")
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

    # Save scan
    save_scan(
        message,
        level,
        score
    )

    print(
        "\nScan saved to SQLite history."
    )


# ============================================================
# MAIN MENU
# ============================================================

def main():

    # Create database if it doesn't exist
    init_database()

    while True:

        print("\n" + "=" * 60)
        print("                 SCAMSHIELD AI")
        print("=" * 60)

        print("\n1. Scan a message")
        print("2. View scan history")
        print("3. View reports")
        print("4. Exit")

        choice = input(
            "\nChoose an option: "
        ).strip()

        if choice == "1":

            scan_message()

        elif choice == "2":

            view_history()

        elif choice == "3":

            view_reports()

        elif choice == "4":

            print(
                "\nThanks for using ScamShield AI."
            )

            break

        else:

            print(
                "\nInvalid choice. "
                "Please select 1, 2, 3, or 4."
            )


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":
    main()