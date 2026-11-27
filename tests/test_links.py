"""Link checks. Links are never visited; these run fully offline."""
import unittest

from tests import support  # noqa: F401

from app.services.link_analysis import InvalidLinkError, analyze_link
from app.services.trusted_domains import TrustedContext, TrustedEntry, normalize_domain


def decision(url, trusted=None):
    return analyze_link(url, trusted=trusted)["decision"]


class LinkChecks(unittest.TestCase):

    def test_ordinary_links_look_safe(self):
        for url in [
            "https://www.microsoft.com/en-us/security",
            "https://login.microsoftonline.com/common",
            "https://www.amazon.co.uk/orders",
            "https://apply.com",
            "https://chaser.com",
        ]:
            with self.subTest(url=url):
                self.assertEqual(decision(url), "LOOKS_SAFE")

    def test_lookalikes_and_tricks(self):
        for url in [
            "https://paypa1.com/signin",
            "https://rnicrosoft.com",
            "https://paypa1-security.com",
            "https://secure-docusign.web.app/view",
            "https://www.google.com@evil.example/login",
            "http://3232235777/admin",
            "javascript:alert(1)",
            "https://example.com/files/invoice.pdf.exe",
        ]:
            with self.subTest(url=url):
                self.assertEqual(decision(url), "DO_NOT_OPEN")

    def test_hidden_destinations_need_caution(self):
        self.assertEqual(decision("https://bit.ly/3abcXYZ"), "USE_CAUTION")

    def test_safe_links_are_unwrapped(self):
        wrapped = (
            "https://nam12.safelinks.protection.outlook.com/?url="
            "https%3A%2F%2Fpaypa1.com%2Fsignin&data=05"
        )
        result = analyze_link(wrapped)
        self.assertEqual(result["decision"], "DO_NOT_OPEN")
        self.assertEqual(result["details"]["inner"]["host"], "paypa1.com")

    def test_defanged_links_are_restored(self):
        result = analyze_link("hxxps://evil[.]example[.]com/path")
        self.assertEqual(result["target"], "https://evil.example.com/path")

    def test_not_a_link(self):
        with self.assertRaises(InvalidLinkError):
            analyze_link("   ")


class EverydayBrandWords(unittest.TestCase):
    """Brand names that are everyday words count only with account words."""

    def test_ordinary_businesses_are_not_flagged(self):
        for url in [
            "https://apple-orchard-farm.com",
            "https://chase-ridge-apartments.com",
            "https://outlook-hotel.com/rooms",
            "https://zoom-dance-studio.com",
            "https://amazon-rainforest-tours.com",
            "https://pop-ups.com",
            "https://amazon.fr",
            "https://docs.google.com/document/d/abc/edit",
        ]:
            with self.subTest(url=url):
                self.assertEqual(decision(url), "LOOKS_SAFE")

    def test_impersonations_are_still_caught(self):
        for url in [
            "https://apple-id-verify.com",
            "https://chase-secure-login.com",
            "https://outlook-account-update.com",
            "https://ups-package-tracking.top",
            "https://amaz0n-rainforest.com",
        ]:
            with self.subTest(url=url):
                self.assertEqual(decision(url), "DO_NOT_OPEN")
        self.assertEqual(decision("https://amazon-delivery.info"), "USE_CAUTION")
        self.assertEqual(decision("https://docs.google.com/forms/d/e/abc/viewform"), "USE_CAUTION")


class TrustedDomainChecks(unittest.TestCase):

    trusted = TrustedContext([TrustedEntry("acme-supply.com", "Acme Supply", "vendor")])

    def test_lookalikes_of_a_vendor(self):
        for url in [
            "https://acrne-supply.com/invoice",
            "https://acme-supply.co/pay",
            "https://acmesupply-billing.com",
        ]:
            with self.subTest(url=url):
                self.assertEqual(decision(url, self.trusted), "DO_NOT_OPEN")
                self.assertEqual(decision(url), decision(url))  # stable

    def test_the_real_vendor(self):
        result = analyze_link("https://portal.acme-supply.com/pay", trusted=self.trusted)
        self.assertEqual(result["decision"], "LOOKS_SAFE")
        self.assertEqual(result["details"]["trusted"]["label"], "Acme Supply")

    def test_normalizing_what_people_type(self):
        self.assertEqual(normalize_domain("https://www.Acme-Supply.com/invoices"), "acme-supply.com")
        self.assertEqual(normalize_domain("ap@billing.acme-supply.com"), "acme-supply.com")
        self.assertIsNone(normalize_domain("not a domain"))


if __name__ == "__main__":
    unittest.main()
