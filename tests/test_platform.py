"""Pages, exports, security headers, migrations and the reputation cache."""
import json
import unittest
from datetime import datetime, timedelta, timezone

from tests import support

from app import models


class Pages(unittest.TestCase):

    def test_public_pages(self):
        client = support.signed_out_client()
        for path in ["/", "/about", "/pricing", "/security", "/privacy", "/terms", "/contact", "/login"]:
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 200)

    def test_app_pages(self):
        client = support.signed_in_client()
        for path in [
            "/dashboard", "/analyze", "/ledger", "/reports", "/activity",
            "/environments", "/settings", "/settings/subscription",
            "/settings/trusted-domains",
        ]:
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 200)

    def test_every_check_type_appears_in_the_ledger(self):
        client = support.signed_in_client()
        environment = support.account()["environment_id"]
        form = {"environment": environment, "source": "email"}
        client.post("/analyze", files={"file": ("a.pdf", b"%PDF-1.4")}, data=form, headers=support.ORIGIN)
        client.post("/analyze/link", data={**form, "url": "https://paypa1.com"}, headers=support.ORIGIN)
        client.post("/analyze/text", data={**form, "source": "text_message", "message": "Lunch?"}, headers=support.ORIGIN)
        client.post("/analyze", files={"file": ("m.eml", support.email_bytes())}, data=form, headers=support.ORIGIN)
        client.post("/analyze", files={"file": ("q.png", support.qr_png("https://example.com"))}, data=form, headers=support.ORIGIN)
        ledger = client.get("/ledger").text
        for kind in ["file", "link", "text", "email", "qr"]:
            with self.subTest(kind=kind):
                self.assertIn(f'data-type="{kind}"', ledger)

    def test_phone_menus_exist(self):
        self.assertIn("business-app-nav-toggle", support.signed_in_client().get("/dashboard").text)
        self.assertIn("business-mobile-nav-toggle", support.signed_out_client().get("/").text)


class Exports(unittest.TestCase):

    def test_pdf_exports(self):
        client = support.signed_in_client()
        for path in ["/ledger/export/pdf", "/activity/export/pdf", "/reports/security-summary/pdf"]:
            with self.subTest(path=path):
                response = client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.content.startswith(b"%PDF"))

    def test_crafted_file_names_cannot_change_an_evidence_pdf(self):
        client = support.signed_in_client()
        name = "x<img src='/etc/passwd'/><font size=40>FAKE</font>.pdf"
        response = client.post(
            "/analyze",
            files={"file": (name, b"%PDF-1.4")},
            data={"environment": support.account()["environment_id"], "source": "email"},
            headers=support.ORIGIN,
        )
        analysis_id = response.headers["location"].rsplit("/", 1)[-1]
        pdf = client.get(f"/ledger/{analysis_id}/pdf")
        self.assertEqual(pdf.status_code, 200)


class SecurityHeaders(unittest.TestCase):

    def test_stripe_is_allowed_for_checkout_redirects(self):
        policy = support.signed_out_client().get("/pricing").headers["content-security-policy"]
        self.assertIn("https://checkout.stripe.com", policy)
        self.assertIn("https://billing.stripe.com", policy)

    def test_oversized_uploads_are_refused(self):
        response = support.signed_in_client().post(
            "/analyze",
            content=b"x",
            headers={**support.ORIGIN, "content-length": str(200 * 1024 * 1024), "content-type": "multipart/form-data; boundary=x"},
        )
        self.assertEqual(response.status_code, 413)


class Migrations(unittest.TestCase):

    def test_migrations_match_the_models(self):
        from alembic.autogenerate import compare_metadata
        from alembic.migration import MigrationContext

        from app.database import Base, engine

        with engine.connect() as connection:
            differences = compare_metadata(MigrationContext.configure(connection), Base.metadata)
        self.assertEqual(differences, [], "Models changed without a migration")


class ReputationCache(unittest.TestCase):

    def test_results_are_reused_and_expire(self):
        import app.services.virustotal_service as vt
        from app.database import SessionLocal

        calls = []
        original_key, original_report = vt.VIRUSTOTAL_API_KEY, vt._get_report
        vt.VIRUSTOTAL_API_KEY = "test-key"
        vt._get_report = lambda url: calls.append(url) or {"available": True, "found": True, "malicious": 0}
        try:
            vt.lookup_host("cache-test.example")
            self.assertTrue(vt.lookup_host("cache-test.example").get("cached"))
            self.assertEqual(len(calls), 1)

            with SessionLocal() as db:
                row = db.query(models.ReputationCache).filter_by(lookup_key="cache-test.example").one()
                row.fetched_at = datetime.now(timezone.utc) - timedelta(hours=25)
                db.commit()
            vt.lookup_host("cache-test.example")
            self.assertEqual(len(calls), 2)

            vt._get_report = lambda url: calls.append(url) or {"available": False, "error": "http_429"}
            vt.lookup_host("rate-limited.example")
            vt.lookup_host("rate-limited.example")
            self.assertEqual(len(calls), 4, "errors must not be cached")
        finally:
            vt.VIRUSTOTAL_API_KEY, vt._get_report = original_key, original_report


if __name__ == "__main__":
    unittest.main()


class WhatWasChecked(unittest.TestCase):

    def test_each_type_lists_its_checks(self):
        from app.services.analysis_service import analyze_file
        from app.services.coverage import summarize
        from app.services.email_analysis import analyze_email
        from app.services.link_analysis import analyze_link
        from app.services.text_analysis import analyze_text

        file_checks = analyze_file("a.pdf", b"%PDF-1.4")["checks"]
        self.assertEqual(
            [c["name"] for c in file_checks],
            ["File contents", "File name", "Threat intelligence"],
        )
        # VirusTotal isn't configured in tests, so the result is partial.
        self.assertEqual(file_checks[-1]["status"], "unavailable")
        self.assertTrue(summarize(file_checks).startswith("Partial check"))

        link_checks = {c["name"]: c["status"] for c in analyze_link("https://example.com")["checks"]}
        self.assertEqual(link_checks["Destination page"], "not_needed")

        no_headers = support.email_bytes(auth=None, received=False)
        email_checks = {c["name"]: c["status"] for c in analyze_email("x.eml", no_headers)["details"]["checks"]}
        self.assertEqual(email_checks["Sender verification"], "limited")

        text_checks = {c["name"]: c["status"] for c in analyze_text("Lunch?")["details"]["checks"]}
        self.assertEqual(text_checks["Links"], "not_needed")

    def test_shown_on_the_result_page_and_pdf(self):
        client = support.signed_in_client()
        response = client.post(
            "/analyze",
            files={"file": ("a.pdf", b"%PDF-1.4")},
            data={"environment": support.account()["environment_id"], "source": "email"},
            headers=support.ORIGIN,
        )
        location = response.headers["location"]
        page = client.get(location).text
        self.assertIn("What Was Checked", page)
        self.assertIn("Partial check", page)
        analysis_id = location.rsplit("/", 1)[-1]
        self.assertIn("What Was Checked", client.get(f"/ledger/{analysis_id}").text)
        self.assertEqual(client.get(f"/ledger/{analysis_id}/pdf").status_code, 200)
