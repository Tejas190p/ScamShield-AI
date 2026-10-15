
import unittest
from category_signals import detect_category_signals

from sensitive_detection import is_sensitive_request
from risk_engine import merge_risk_signals, get_risk_level


class TestSensitiveDetection(unittest.TestCase):

    def test_otp_request_is_detected(self):
        self.assertTrue(
            is_sensitive_request(
                "Send me your OTP immediately or your account will be blocked.",
                "otp",
            )
        )

    def test_pin_request_is_detected(self):
        self.assertTrue(is_sensitive_request("Please enter your PIN.", "pin"))

    def test_cvv_request_is_detected(self):
        self.assertTrue(
            is_sensitive_request("Send me your CVV immediately.", "cvv")
        )

    def test_protective_otp_warning_is_not_a_request(self):
        message = (
            "Never share your OTP with anyone. "
            "Your bank will never ask for it."
        )
        self.assertFalse(is_sensitive_request(message, "otp"))

    def test_otp_value_alone_is_not_a_request(self):
        self.assertFalse(is_sensitive_request("Your OTP is 482193.", "otp"))

    def test_unrelated_message_is_not_a_sensitive_request(self):
        message = "Your package will arrive tomorrow."
        for term in ("otp", "pin", "cvv"):
            with self.subTest(term=term):
                self.assertFalse(is_sensitive_request(message, term))


class TestRiskEngine(unittest.TestCase):

    def test_duplicate_pin_signal_is_not_added_twice(self):
        base_reasons = [
            {
                "reason": "Request for sensitive personal information",
                "points": 3,
            }
        ]
        category_signals = [
            {"reason": "Request for a PIN", "points": 3}
        ]

        score, reasons = merge_risk_signals(
            3, base_reasons, category_signals
        )

        self.assertEqual(score, 3)
        self.assertEqual(len(reasons), 1)

    def test_unique_category_signal_is_added(self):
        base_reasons = [
            {"reason": "Urgent or pressure-based language", "points": 2}
        ]
        category_signals = [
            {"reason": "Suspicious payment link", "points": 2}
        ]

        score, reasons = merge_risk_signals(
            2, base_reasons, category_signals
        )

        self.assertEqual(score, 4)
        self.assertEqual(len(reasons), 2)

    def test_duplicate_account_suspension_signal_is_skipped(self):
        base_reasons = [
            {
                "reason": "Threat or account-suspension language",
                "points": 3,
            }
        ]
        category_signals = [
            {"reason": "Account suspension warning", "points": 3}
        ]

        score, reasons = merge_risk_signals(
            3, base_reasons, category_signals
        )

        self.assertEqual(score, 3)
        self.assertEqual(len(reasons), 1)

    def test_risk_level_thresholds(self):
        cases = [
            (0, "NO OBVIOUS INDICATORS"),
            (1, "LOW"),
            (3, "LOW"),
            (4, "MEDIUM"),
            (6, "MEDIUM"),
            (7, "HIGH"),
            (10, "HIGH"),
        ]

        for score, expected in cases:
            with self.subTest(score=score):
                self.assertEqual(get_risk_level(score), expected)




class TestDeliverySignals(unittest.TestCase):

    def test_delivery_fee_message_reports_fee_signal(self):
        signals = detect_category_signals(
            "Your parcel delivery has failed. "
            "Pay the delivery fee to reschedule.",
            "Delivery / Parcel",
        )
        reasons = [signal["reason"] for signal in signals]
        self.assertIn("Delivery fee request", reasons)

    def test_ordinary_delivery_update_has_no_fee_signal(self):
        signals = detect_category_signals(
            "Your package will arrive tomorrow.",
            "Delivery / Parcel",
        )
        reasons = [signal["reason"] for signal in signals]
        self.assertNotIn("Delivery fee request", reasons)
        self.assertNotIn("Customs fee request", reasons)


class TestDuplicateDeliveryFeeScoring(unittest.TestCase):

    def test_delivery_fee_is_not_counted_twice(self):
        from risk_engine import merge_risk_signals

        base_reasons = [{
            "reason": "Money or payment-related language",
            "points": 2,
        }]
        category_signals = [{
            "reason": "Delivery fee request",
            "points": 2,
        }]

        score, reasons = merge_risk_signals(
            base_score=2,
            base_reasons=base_reasons,
            category_signals=category_signals,
        )

        self.assertEqual(score, 2)
        self.assertEqual(len(reasons), 1)
if __name__ == "__main__":
    unittest.main(verbosity=2)
