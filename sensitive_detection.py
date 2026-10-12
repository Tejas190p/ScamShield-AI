
import re

REQUEST_VERBS = (
    "send",
    "share",
    "provide",
    "give",
    "tell",
    "forward",
    "submit",
    "enter",
    "type",
    "disclose",
    "reveal",
    "confirm",
)

WARNING_PATTERNS = (
    r"\bnever\s+(?:share|send|give|disclose|provide|reveal)\b",
    r"\bdo\s+not\s+(?:share|send|give|disclose|provide|reveal)\b",
    r"\bdon't\s+(?:share|send|give|disclose|provide|reveal)\b",
    r"\bshould\s+not\s+(?:share|send|give|disclose|provide|reveal)\b",
    r"\bshouldn't\s+(?:share|send|give|disclose|provide|reveal)\b",
    r"\bavoid\s+(?:sharing|sending|giving|disclosing|providing|revealing)\b",
)


def is_sensitive_request(message: str, term: str) -> bool:
    """
    Detect a possible request for sensitive information.

    This is a heuristic, not proof of fraud.
    """

    escaped_term = re.escape(term.lower())
    verbs = "|".join(re.escape(verb) for verb in REQUEST_VERBS)

    # Split the message into individual sentences.
    sentences = re.split(r"[.!?\n;]+", message.lower())

    for sentence in sentences:
        # Ignore sentences that do not mention the sensitive term.
        if not re.search(r"\b" + escaped_term + r"\b", sentence):
            continue

        # Avoid flagging common protective warnings.
        if any(
            re.search(pattern, sentence)
            for pattern in WARNING_PATTERNS
        ):
            continue

        # Example: "Send me your OTP."
        # Example: "Please enter your PIN."
        before_term = (
            r"\b(?:"
            + verbs
            + r")\b"
            r"(?:\W+\w+){0,5}\W+\b"
            + escaped_term
            + r"\b"
        )

        # Example: "OTP is required."
        # Example: "Your CVV is requested."
        after_term = (
            r"\b"
            + escaped_term
            + r"\b"
            r"(?:\W+\w+){0,3}\W+"
            r"\b(?:requested|required|needed)\b"
        )

        if re.search(before_term, sentence) or re.search(
            after_term, sentence
        ):
            return True

    return False

