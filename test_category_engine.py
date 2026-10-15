import unittest
from category_engine import detect_category


class TestCategoryPriority(unittest.TestCase):

    def test_prize_takes_priority_over_bank_terms(self):
        message = "You won a prize. Provide your bank details to claim it."
        self.assertEqual(
            detect_category(message, {}),
            "Prize / Reward",
        )

    def test_job_takes_priority_over_payment_terms(self):
        message = "Job offer: pay a registration fee to apply."
        self.assertEqual(
            detect_category(message, {}),
            "Job / Internship",
        )

    def test_delivery_category_is_detected(self):
        message = "Your parcel delivery has failed."
        self.assertEqual(
            detect_category(message, {}),
            "Delivery / Parcel",
        )

    def test_account_suspension_category_is_detected(self):
        message = "Your account will be suspended today."
        self.assertEqual(
            detect_category(message, {}),
            "Account / Verification",
        )


    def test_bank_otp_request_is_account_verification(self):
        message = "Your bank account needs verification. Send your OTP now."
        self.assertEqual(
            detect_category(message, {}),
            "Account / Verification",
        )

    def test_url_falls_back_to_phishing_category(self):
        message = "Please visit this link."
        self.assertEqual(
            detect_category(message, {"urls": ["https://example.com"]}),
            "Phishing / Suspicious Link",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
