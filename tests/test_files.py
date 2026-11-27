"""File checks: disguises, risky types and filename tricks."""
import unittest

from tests import support  # noqa: F401  (sets up the test environment)

from app.services.analysis_service import analyze_file

EXE = b"MZ" + bytes(64)


class FileChecks(unittest.TestCase):

    def decision(self, name, content):
        return analyze_file(name, content)["decision"]

    def test_ordinary_pdf_looks_safe(self):
        self.assertEqual(self.decision("report.pdf", b"%PDF-1.7 hello"), "LOOKS_SAFE")

    def test_program_disguised_as_pdf(self):
        result = analyze_file("invoice.pdf", EXE)
        self.assertEqual(result["decision"], "DO_NOT_OPEN")
        self.assertTrue(any("Windows program" in r for r in result["reasons"]))

    def test_double_extension(self):
        self.assertEqual(self.decision("invoice.pdf.exe", EXE), "DO_NOT_OPEN")

    def test_hidden_reversing_character_removed_and_flagged(self):
        result = analyze_file("invoice\u202efdp.exe", EXE)
        self.assertEqual(result["decision"], "DO_NOT_OPEN")
        self.assertNotIn("\u202e", result["filename"])

    def test_risky_types(self):
        for name in ["shortcut.lnk", "page.hta", "setup.msi", "script.ps1"]:
            with self.subTest(name=name):
                self.assertEqual(self.decision(name, b"data"), "DO_NOT_OPEN")
        for name in ["disk.iso", "budget.xlsm", "notes.one", "login.html"]:
            with self.subTest(name=name):
                self.assertEqual(self.decision(name, b"data"), "USE_CAUTION")

    def test_password_protected_office_file(self):
        ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(64)
        self.assertEqual(self.decision("contract.docx", ole), "USE_CAUTION")

    def test_web_page_disguised_as_image(self):
        self.assertEqual(self.decision("photo.jpg", b"<!DOCTYPE html><form></form>"), "USE_CAUTION")

    def test_long_names_fit_the_database(self):
        result = analyze_file("a" * 400 + ".pdf", b"%PDF-", "x" * 500)
        self.assertLessEqual(len(result["filename"]), 255)
        self.assertTrue(result["filename"].endswith(".pdf"))


if __name__ == "__main__":
    unittest.main()
