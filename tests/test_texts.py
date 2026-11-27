"""Text message checks. Messages are read but never stored."""
import unittest

from tests import support

from app import models
from app.services.message_wording import find_signals
from app.services.text_analysis import analyze_text, find_links
from app.services.trusted_domains import TrustedContext, TrustedEntry


def keys(text):
    return [signal.key for signal in find_signals(text)]


class Wording(unittest.TestCase):

    def test_advice_is_not_a_request(self):
        self.assertEqual(keys("Your code is 482913. Never share this code with anyone."), [])
        self.assertEqual(keys("Do not share it. We will never ask for this code."), [])

    def test_scam_wording(self):
        self.assertIn("codes", keys("Can you send me the code please?"))
        self.assertIn("codes", keys("Please approve the sign-in request on your phone."))
        self.assertIn("gift_cards", keys("Can you buy 5 Apple gift cards?"))
        self.assertIn("toll_fine", keys("You have an unpaid toll balance of $6.99."))
        self.assertIn("payment_change", keys("Our bank details have changed."))

    def test_ordinary_messages(self):
        for text in ["Lunch at 12:30? I booked a table.", "Your appointment is tomorrow at 9am. Reply C to confirm."]:
            with self.subTest(text=text):
                self.assertEqual(keys(text), [])

    def test_finding_links(self):
        self.assertEqual(
            find_links("Pay at ez-tollpay.com/pay now. See https://x.com/a. Attached file.pdf"),
            ["ez-tollpay.com/pay", "https://x.com/a"],
        )


class TextDecisions(unittest.TestCase):

    trusted = TrustedContext([TrustedEntry("acme-supply.com", "Acme Supply", "vendor")])

    def decision(self, text):
        return analyze_text(text, trusted=self.trusted)["decision"]

    def test_scams(self):
        for text in [
            "Toll Services: unpaid toll balance of $6.99. Pay now: ez-tollpay.com/pay",
            "Hi, this is IT. Please approve the sign-in request on your phone.",
            "Are you available? Quick favor, I'm in a meeting. Buy 5 Apple gift cards.",
            "Acme Supply: our bank details changed. Update at acme-supply-billing.com",
        ]:
            with self.subTest(text=text):
                self.assertEqual(self.decision(text), "DO_NOT_OPEN")

    def test_real_company_link_with_a_story_is_a_caution(self):
        self.assertEqual(
            self.decision("USPS: your package is on hold. Track it at https://www.usps.com/tracking"),
            "USE_CAUTION",
        )

    def test_ordinary(self):
        self.assertEqual(self.decision("Lunch at 12:30?"), "LOOKS_SAFE")
        self.assertEqual(self.decision("Your code is 4412. Never share it."), "LOOKS_SAFE")


class TextRoute(unittest.TestCase):

    def test_message_is_never_stored(self):
        client = support.signed_in_client()
        text = "Toll Services: unpaid toll balance of $6.99 for plate 7XKL. Pay now: ez-tollpay.com/pay"
        response = client.post(
            "/analyze/text",
            data={"message": text, "environment": support.account()["environment_id"], "source": "text_message"},
            headers=support.ORIGIN,
        )
        self.assertEqual(response.status_code, 303)
        db = support.account()["db"]
        db.expire_all()
        for row in db.query(models.Analysis).filter(models.Analysis.analysis_type == "text"):
            stored = " ".join(filter(None, [row.filename, row.target, row.reasons, row.details_json]))
            self.assertNotIn("plate 7XKL", stored)


if __name__ == "__main__":
    unittest.main()
