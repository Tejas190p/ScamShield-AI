from app import analyze_message, calculate_risk
from sensitive_detection import is_sensitive_request
from category_engine import detect_category
from category_signals import detect_category_signals

messages = [
    "send the otp",
    "Never share your OTP with anyone.",
    "Congratulations! You won a cash prize. Claim your reward now.",
    "Your college Python lecture starts at 10 AM tomorrow in Room 204.",
]

for message in messages:
    analysis = analyze_message(message)
    score, level, reasons = calculate_risk(analysis)
    category = detect_category(message, analysis)
    signals = detect_category_signals(message, category)

    print("\nMESSAGE:", message)
    print("OTP request:", is_sensitive_request(message, "otp"))
    print("Base score:", score, "| Level:", level)
    print("Category:", category)
    print("Category signals:", signals)
