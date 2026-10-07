import os
from google import genai


def analyze_with_ai(message: str) -> str:
    """
    Generate an AI explanation for a suspicious message.

    If the AI service is temporarily unavailable,
    return a safe fallback instead of exposing
    provider errors to the user.
    """

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return (
            "AI explanation is unavailable because the Gemini API key "
            "is not configured. The assessment is based on ScamShield's "
            "rule-based detection engine."
        )

    try:
        client = genai.Client(api_key=api_key)

        prompt = f"""
You are a scam-awareness assistant.

Analyze the following message for suspicious or potentially fraudulent
indicators.

Message:
{message}

Give a short explanation covering:

1. Whether the message contains suspicious indicators.
2. The main warning signs.
3. What the user should do safely.

Do not claim with certainty that the message is a scam.
Do not ask the user to share passwords, OTPs, CVVs, or other sensitive data.
Keep the response clear and practical.
"""

        interaction = client.interactions.create(
            model="gemini-3.8-flash",
            input=prompt,
        )

        return interaction.output_text.strip()

    except Exception:
        return (
            "AI explanation is temporarily unavailable. "
            "The assessment below is based on ScamShield's "
            "rule-based detection engine."
        )