"""The feedback form and the admin review page."""
import unittest
from unittest.mock import patch

from tests import support

from app import models
import app.routes.feedback as feedback_routes


class FeedbackForm(unittest.TestCase):

    def setUp(self):
        self.client = support.signed_in_client()
        db = support.account()["db"]
        db.query(models.Feedback).delete()
        db.commit()

    def send(self, **fields):
        data = {"category": "bug", "message": "The ledger filter forgot my choice after going Back.", "rating": "4",
                "page": "/ledger", "may_contact": "1"}
        data.update(fields)
        return self.client.post("/feedback", data=data, headers=support.ORIGIN)

    def stored(self):
        db = support.account()["db"]
        db.expire_all()
        return db.query(models.Feedback).all()

    def test_feedback_is_saved_even_without_email_set_up(self):
        response = self.send()
        self.assertEqual(response.headers["location"], "/feedback?sent=1")
        entry = self.stored()[0]
        self.assertEqual((entry.category, entry.rating, entry.page, entry.status), ("bug", 4, "/ledger", "new"))
        self.assertIn("Thank you", self.client.get("/feedback?sent=1").text)

    def test_too_short_is_refused(self):
        self.send(message="bad")
        self.assertEqual(self.stored(), [])
        self.assertIn("at least a sentence", self.client.get("/feedback").text)

    def test_only_pages_within_preclear_are_recorded(self):
        self.send(page="//evil.example/steal")
        self.send(page="/analysis/12?token=abc#x")
        pages = sorted(str(e.page) for e in self.stored())
        self.assertEqual(pages, ["/analysis/12", "None"])

    def test_bad_ratings_are_ignored(self):
        self.send(rating="11")
        self.assertIsNone(self.stored()[0].rating)

    def test_daily_limit(self):
        for _ in range(feedback_routes.MAX_PER_DAY + 2):
            self.send()
        self.assertEqual(len(self.stored()), feedback_routes.MAX_PER_DAY)

    def test_the_page_opens_from_the_sidebar_link(self):
        page = self.client.get("/feedback?from=/ledger").text
        self.assertIn("Share Your Feedback", page)
        self.assertIn("(/ledger)", page)
        self.assertIn("/feedback?from=", self.client.get("/dashboard").text)


class FeedbackReview(unittest.TestCase):

    def test_only_platform_admins_can_review(self):
        client = support.signed_in_client()
        self.assertEqual(client.get("/admin/feedback").headers["location"], "/dashboard")

    def test_admins_see_feedback_safely_escaped(self):
        client = support.signed_in_client()
        client.post(
            "/feedback",
            data={"category": "other", "message": "<script>alert('x')</script> looks odd"},
            headers=support.ORIGIN,
        )
        with patch.object(feedback_routes, "is_platform_admin", return_value=True):
            page = client.get("/admin/feedback").text
            self.assertIn("&lt;script&gt;", page)
            self.assertNotIn("<script>alert", page)

            entry = support.account()["db"].query(models.Feedback).order_by(models.Feedback.id.desc()).first()
            client.post(f"/admin/feedback/{entry.id}/status", data={"status": "planned"}, headers=support.ORIGIN)
            support.account()["db"].expire_all()
            self.assertEqual(support.account()["db"].get(models.Feedback, entry.id).status, "planned")


if __name__ == "__main__":
    unittest.main()
