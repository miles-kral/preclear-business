"""QR code checks in images, PDFs and emails."""
import unittest

from tests import support

from app.services.analysis_service import analyze_file
from app.services.email_analysis import analyze_email
from app.services.qr_analysis import analyze_payload, analyze_qr_in_file, combine_with_file_result


def check_image(content, name="code.png"):
    file_result = analyze_file(name, content)
    qr = analyze_qr_in_file(content, file_result)
    return combine_with_file_result(file_result, qr)


class QRChecks(unittest.TestCase):

    def test_phishing_link_in_an_image(self):
        result, kind = check_image(support.qr_png("https://micros0ft-login.top/verify"))
        self.assertEqual(kind, "qr")
        self.assertEqual(result["decision"], "DO_NOT_OPEN")

    def test_ordinary_link(self):
        result, kind = check_image(support.qr_png("https://www.microsoft.com"))
        self.assertEqual(result["decision"], "LOOKS_SAFE")

    def test_qr_code_on_a_pdf_page(self):
        result, kind = check_image(support.pdf_with_qr("https://paypa1.com/pay"), "invoice.pdf")
        self.assertEqual(kind, "qr")
        self.assertEqual(result["details"]["codes"][0]["page"], 2)

    def test_secrets_are_removed(self):
        wifi = analyze_payload("WIFI:T:WPA;S:Acme-Office;P:SuperSecret123;;")
        self.assertNotIn("SuperSecret123", wifi["display"] + " ".join(wifi["reasons"]))
        otp = analyze_payload("otpauth://totp/ACME:me@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME")
        self.assertEqual(otp["risk_level"], "HIGH")
        self.assertNotIn("JBSWY3DPEHPK3PXP", otp["display"] + " ".join(otp["reasons"]))

    def test_image_without_a_code(self):
        from io import BytesIO
        from PIL import Image
        buffer = BytesIO()
        Image.new("RGB", (200, 200), "white").save(buffer, "PNG")
        result, kind = check_image(buffer.getvalue())
        self.assertEqual(kind, "file")

    def test_qr_code_inside_an_email(self):
        email = support.email_bytes(
            body="Scan the code to review your benefits.",
            attachments=[("benefits.png", support.qr_png("https://micros0ft-login.top/hr"), "image", "png")],
        )
        result = analyze_email("x.eml", email)
        self.assertEqual(result["decision"], "DO_NOT_OPEN")
        self.assertTrue(result["details"].get("has_qr"))


if __name__ == "__main__":
    unittest.main()
