import os
from google import genai


def analyze_with_ai(message: str) -> str:
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return "AI analysis unavailable: GEMINI_API_KEY is not configured."

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
2. The main warning signs you found.
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

    except Exception as error:
        return f"AI analysis unavailable: {error}"