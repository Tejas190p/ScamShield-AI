import re


# Common warning patterns
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


def contains_pattern(text, patterns):
    text = text.lower()

    return [
        pattern
        for pattern in patterns
        if pattern in text
    ]


def find_urls(text):
    url_pattern = r"https?://\S+|www\.\S+"

    return re.findall(
        url_pattern,
        text,
        re.IGNORECASE
    )


def analyze_message(message):
    indicators = []

    urgent_matches = contains_pattern(
        message,
        URGENT_WORDS
    )

    money_matches = contains_pattern(
        message,
        MONEY_WORDS
    )

    reward_matches = contains_pattern(
        message,
        REWARD_WORDS
    )

    threat_matches = contains_pattern(
        message,
        THREAT_WORDS
    )

    personal_info_matches = contains_pattern(
        message,
        PERSONAL_INFO_WORDS
    )

    urls = find_urls(message)

    if urgent_matches:
        indicators.append(
            "Urgent or pressure-based language detected."
        )

    if money_matches:
        indicators.append(
            "Money or payment-related language detected."
        )

    if reward_matches:
        indicators.append(
            "Prize, reward, or unexpected-benefit language detected."
        )

    if threat_matches:
        indicators.append(
            "Threat or account-consequence language detected."
        )

    if personal_info_matches:
        indicators.append(
            "Request for sensitive personal information detected."
        )

    if urls:
        indicators.append(
            f"Link detected ({len(urls)} link(s))."
        )

    return {
        "urgent": urgent_matches,
        "money": money_matches,
        "reward": reward_matches,
        "threat": threat_matches,
        "personal_info": personal_info_matches,
        "urls": urls,
        "indicators": indicators,
    }


def calculate_risk(result):
    score = 0

    if result["urgent"]:
        score += 2

    if result["money"]:
        score += 2

    if result["reward"]:
        score += 2

    if result["threat"]:
        score += 3

    if result["personal_info"]:
        score += 3

    if result["urls"]:
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

    print("\nRisk indicators:")

    if result["indicators"]:

        for number, indicator in enumerate(
            result["indicators"],
            start=1
        ):
            print(f"{number}. {indicator}")

    else:
        print("No obvious scam indicators detected.")

    if result["urls"]:
        print("\nLinks found:")

        for url in result["urls"]:
            print(f"- {url}")

    print("\nImportant:")
    print(
        "This is an indicator-based analysis, "
        "not proof that a message is legitimate or fraudulent."
    )

    print("=" * 60)


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

    score, level = calculate_risk(result)

    display_result(
        result,
        score,
        level
    )


if __name__ == "__main__":
    main()