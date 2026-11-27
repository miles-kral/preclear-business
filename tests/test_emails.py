"""Email checks: uploaded files, pasted originals and saved pages."""
import unittest

from tests import support

from app.services.email_analysis import (
    analyze_email,
    email_from_saved_page,
    looks_like_email,
    starts_with_headers,
)
from app.services.trusted_domains import TrustedContext, TrustedEntry

EXE = b"MZ" + bytes(64)

PHISH = support.email_bytes(
    sender='"PayPal Security service@paypal.com" <alert@paypa1.com>',
    subject="Your account has been suspended",
    body="Verify your account within 24 hours.",
    html='<a href="https://paypa1-secure.top/login">https://www.paypal.com/signin</a>',
    auth="mx; spf=fail; dkim=none; dmarc=fail header.from=paypa1.com",
    attachments=[("Statement.pdf", EXE, "application", "pdf")],
)

LEGIT = support.email_bytes(
    sender="Microsoft <no-reply@microsoft.com>",
    subject="Your monthly security report",
    body="See https://www.microsoft.com/en-us/security",
    auth="mx; spf=pass; dkim=pass; dmarc=pass header.from=microsoft.com",
)


class EmailChecks(unittest.TestCase):

    def test_phishing_email(self):
        result = analyze_email("x.eml", PHISH)
        self.assertEqual(result["decision"], "DO_NOT_OPEN")
        reasons = " ".join(result["reasons"])
        self.assertIn("DMARC", reasons)
        self.assertIn("link's text shows www.paypal.com", reasons)
        self.assertIn("Statement.pdf", reasons)

    def test_invoice_fraud_from_free_account(self):
        bec = support.email_bytes(
            sender='"Rocky Mountain Supply Billing" <rmsupply.billing@gmail.com>',
            reply_to="accounts@rmsupply-payments.co",
            body="Our bank account details have changed. Send today's payment to the new account.",
            auth="mx; spf=pass; dkim=pass; dmarc=pass header.from=gmail.com",
        )
        self.assertEqual(analyze_email("x.eml", bec)["decision"], "DO_NOT_OPEN")

    def test_legitimate_email(self):
        self.assertEqual(analyze_email("x.eml", LEGIT)["decision"], "LOOKS_SAFE")

    def test_genuine_sign_in_code_email_is_not_flagged(self):
        code = support.email_bytes(
            sender="Microsoft <account-security-noreply@accountprotection.microsoft.com>",
            body="Your security code is 482913. Never share this code.",
            auth="mx; spf=pass; dkim=pass; dmarc=pass header.from=accountprotection.microsoft.com",
        )
        self.assertEqual(analyze_email("x.eml", code)["decision"], "LOOKS_SAFE")

    def test_businesses_named_with_everyday_brand_words(self):
        for sender in [
            '"Apple Valley Dental" <office@applevalleydental.com>',
            "Billing <ar@chase-ridge-apartments.com>",
        ]:
            with self.subTest(sender=sender):
                email = support.email_bytes(sender=sender)
                self.assertEqual(analyze_email("x.eml", email)["decision"], "LOOKS_SAFE")
        fake = support.email_bytes(sender='"Apple Support" <help@apple-care-team.com>')
        self.assertEqual(analyze_email("x.eml", fake)["decision"], "DO_NOT_OPEN")

    def test_trusted_vendor_failing_verification(self):
        trusted = TrustedContext([TrustedEntry("acme-supply.com", "Acme Supply", "vendor")])
        spoof = support.email_bytes(
            sender="Acme Supply <ar@acme-supply.com>",
            auth="mx; spf=fail; dkim=none; dmarc=fail header.from=acme-supply.com",
        )
        self.assertEqual(analyze_email("x.eml", spoof, trusted=trusted)["decision"], "DO_NOT_OPEN")

    def test_recognized_by_headers_not_by_body(self):
        html_bodied = support.email_bytes(html="<html><body><p>Hi</p></body></html>")
        for name in ["original.eml", "original.txt", "original"]:
            with self.subTest(name=name):
                self.assertTrue(looks_like_email(name, html_bodied))
        self.assertFalse(starts_with_headers(b"Hi, please pay the invoice.\nFrom: me"))

    def test_saved_show_original_page_is_unwrapped(self):
        escaped = LEGIT.replace(b"&", b"&amp;").replace(b"<", b"&lt;").replace(b">", b"&gt;")
        page = b"<html><body><pre class='raw_message_text'>" + escaped + b"</pre></body></html>"
        self.assertIsNotNone(email_from_saved_page(page))
        self.assertIsNone(email_from_saved_page(b"<html><body><pre>print(1)</pre></body></html>"))


class PastedEmailRoute(unittest.TestCase):

    def setUp(self):
        self.client = support.signed_in_client()
        self.environment = support.account()["environment_id"]

    def paste(self, text):
        return self.client.post(
            "/analyze/email",
            data={"email_source": text, "environment": self.environment, "source": "email"},
            headers=support.ORIGIN,
        )

    def test_pasted_original_is_checked_and_body_not_stored(self):
        response = self.paste(PHISH.decode())
        self.assertEqual(response.status_code, 303)
        page = self.client.get(response.headers["location"]).text
        self.assertIn("Do Not Trust", page)
        self.assertIn("Pasted original", page)
        self.assertNotIn("Verify your account within 24 hours", page)

    def test_message_without_headers_keeps_the_text(self):
        response = self.paste("Please update our bank details for invoice 22.")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Please update our bank details for invoice 22.", response.text)

    def test_large_paste_is_accepted(self):
        big = LEGIT.decode() + "\n" + "A" * (3 * 1024 * 1024)
        self.assertEqual(self.paste(big).status_code, 303)


if __name__ == "__main__":
    unittest.main()
