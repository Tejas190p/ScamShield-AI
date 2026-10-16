from app import analyze_message, calculate_risk
from category_engine import detect_category
from category_signals import detect_category_signals
from risk_engine import merge_risk_signals, get_risk_level

TEST_CASES = [
    {"name": "Fake prize with processing fee", "message": "Congratulations! You won a prize. Pay a 999 processing fee to claim it.", "expected_category": "Prize / Reward", "expected_risk": "HIGH"},
    {"name": "Job registration fee", "message": "Job offer: pay a registration fee to apply for this position.", "expected_category": "Job / Internship", "expected_risk": "MEDIUM"},
    {"name": "Account suspension threat", "message": "Your account will be suspended today. Verify your account immediately.", "expected_category": "Account / Verification", "expected_risk": "HIGH"},
    {"name": "Parcel delivery fee", "message": "Your parcel delivery has failed. Pay the delivery fee to reschedule.", "expected_category": "Delivery / Parcel", "expected_risk": "MEDIUM"},
    {"name": "Bank OTP request", "message": "Your bank account needs verification. Send your OTP now.", "expected_category": "Account / Verification", "expected_risk": "MEDIUM"},
    {"name": "Ordinary college announcement", "message": "Reminder: the computer science lecture begins tomorrow at 10 AM in Room 204.", "expected_category": "General / Unknown", "expected_risk": "NO OBVIOUS INDICATORS"},
    {"name": "Ordinary internship announcement", "message": "The college placement cell will share internship opportunities during Friday's meeting.", "expected_category": "Job / Internship", "expected_risk": "NO OBVIOUS INDICATORS"},
    {"name": "General banking information", "message": "The bank will be closed on Sunday. Regular services resume Monday.", "expected_category": "Financial / Bank", "expected_risk": "NO OBVIOUS INDICATORS"},
    {"name": "Plain URL without suspicious indicators", "message": "Please visit this link: https://example.com", "expected_category": "Phishing / Suspicious Link", "expected_risk": "NO OBVIOUS INDICATORS"},
    {"name": "Fake refund message", "message": "Your refund is pending. Pay a processing fee to receive your money.", "expected_category": "Financial / Bank", "expected_risk": "MEDIUM"},
    {"name": "Impersonation with payment request", "message": "A police officer demands payment immediately to avoid a penalty.", "expected_category": "Impersonation", "expected_risk": "MEDIUM"},
    {"name": "Protective OTP warning", "message": "Never share your OTP with anyone. Your bank will never ask for it.", "expected_category": "Financial / Bank", "expected_risk": "NO OBVIOUS INDICATORS"},
    {"name": "Ordinary parcel update", "message": "Your package will arrive tomorrow. No action is required.", "expected_category": "Delivery / Parcel", "expected_risk": "NO OBVIOUS INDICATORS"},
    {"name": "Ordinary payment receipt", "message": "Your payment of 500 rupees was successful. Thank you for your purchase.", "expected_category": "Financial / Bank", "expected_risk": "NO OBVIOUS INDICATORS"},
    {"name": "Suspicious CVV request", "message": "Send your CVV immediately to verify your card and prevent account closure.", "expected_category": "Account / Verification", "expected_risk": "MEDIUM"},
    {"name": "Fake work-from-home offer", "message": "Work from home and earn a salary. Pay an upfront registration fee to get started.", "expected_category": "Job / Internship", "expected_risk": "MEDIUM"},
]

def main():
    category_passed = 0
    risk_passed = 0

    print("\nSCAMSHIELD AI — CATEGORY AND RISK EVALUATION")
    print("=" * 72)

    for case in TEST_CASES:
        analysis = analyze_message(case["message"])
        actual_category = detect_category(case["message"], analysis)
        score, _, reasons = calculate_risk(analysis)

        category_signals = detect_category_signals(
            case["message"],
            actual_category,
        )

        score, reasons = merge_risk_signals(
            base_score=score,
            base_reasons=reasons,
            category_signals=category_signals,
        )
        actual_risk = get_risk_level(score)

        category_ok = actual_category == case["expected_category"]
        risk_ok = actual_risk == case["expected_risk"]

        category_passed += category_ok
        risk_passed += risk_ok

        print(f"\n{case['name']}")
        print(
            f"  Category: {'PASS' if category_ok else 'FAIL'}"
            f" | expected={case['expected_category']}"
            f" | actual={actual_category}"
        )
        print(
            f"  Risk:     {'PASS' if risk_ok else 'FAIL'}"
            f" | expected={case['expected_risk']}"
            f" | actual={actual_risk} | score={score}"
        )

        if reasons:
            print(f"  Reasons: {', '.join(map(str, reasons))}")

    total = len(TEST_CASES)
    print("\n" + "=" * 72)
    print(f"Category matches: {category_passed}/{total}")
    print(f"Risk matches:     {risk_passed}/{total}")
    print(f"Combined checks:  {category_passed + risk_passed}/{total * 2}")

if __name__ == "__main__":
    main()
