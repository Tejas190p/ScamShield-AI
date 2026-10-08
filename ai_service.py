import os

from google import genai


def analyze_with_ai(message: str) -> str:
    """
    Generate a concise AI explanation for a suspicious message.

    The AI provides supporting analysis only.
    The rule-based engine remains responsible for the risk score.
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
You are ScamShield AI, a concise scam-awareness assistant.

Analyze this message:

{message}

Return a short response using EXACTLY this structure:

Suspicious indicators:
- Write 2 to 4 important warning signs.
- Keep each point short.

Safe action:
- Give 2 or 3 practical safety actions.

Rules:
- Do not claim with certainty that the message is a scam.
- Do not ask the user for passwords, OTPs, CVVs, PINs, or other sensitive data.
- Do not invent facts about the sender or company.
- Focus only on evidence present in the message.
- Keep the complete response under 150 words.
"""

        interaction = client.interactions.create(
            model="gemini-3.8-flash",
            input=prompt,
        )

        response = interaction.output_text.strip()

        if not response:
            return (
                "AI explanation was empty. The assessment is based on "
                "ScamShield's rule-based detection engine."
            )

        return response

    except Exception:
        return (
            "AI explanation is temporarily unavailable. "
            "The assessment below is based on ScamShield's "
            "rule-based detection engine."
        )