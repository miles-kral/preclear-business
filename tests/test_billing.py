"""Stripe webhooks and checkout. Stripe itself is replaced by stand-ins."""
import unittest
from unittest.mock import patch

from tests import support

import stripe

import app.routes.billing as billing


def subscription(sid, status, price, created, customer="cus_test"):
    return {
        "id": sid, "status": status, "customer": customer, "created": created,
        "metadata": {}, "items": {"data": [{"price": {"id": price}}]},
        "cancel_at_period_end": False, "current_period_end": 1900000000,
    }


class Event(dict):
    def to_dict(self):
        return dict(self)


class Webhooks(unittest.TestCase):

    def setUp(self):
        self.client = support.signed_out_client()
        org = support.organization()
        org.subscription_status, org.stripe_subscription_id = "active", "sub_new"
        org.plan, org.stripe_customer_id = "small_business", "cus_test"
        support.account()["db"].commit()
        self.subscriptions = [
            subscription("sub_old", "canceled", "price_sb_monthly", 100),
            subscription("sub_new", "active", "price_ent_monthly", 200),
        ]

    def fire(self, event_type, obj, stripe_down=False):
        def listing(**kwargs):
            if stripe_down:
                raise stripe.APIConnectionError("down")
            return {"data": self.subscriptions}

        with patch.object(stripe.Subscription, "list", side_effect=listing), \
             patch.object(stripe.Webhook, "construct_event",
                          return_value=Event(type=event_type, data={"object": obj})):
            return self.client.post(
                "/billing/webhook", content=b"{}",
                headers={"stripe-signature": "t=1,v1=test"},
            )

    def test_late_event_for_an_old_subscription_keeps_access(self):
        response = self.fire("customer.subscription.deleted", subscription("sub_old", "canceled", "price_sb_monthly", 100))
        self.assertEqual(response.status_code, 200)
        org = support.organization()
        self.assertEqual((org.subscription_status, org.stripe_subscription_id, org.plan), ("active", "sub_new", "enterprise"))

    def test_stripe_unreachable_asks_for_a_retry(self):
        response = self.fire("invoice.paid", {"customer": "cus_test"}, stripe_down=True)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(support.organization().subscription_status, "active")

    def test_missing_secret_asks_for_a_retry(self):
        with patch.object(billing, "STRIPE_WEBHOOK_SECRET", ""):
            self.assertEqual(self.fire("invoice.paid", {"customer": "cus_test"}).status_code, 503)


class PublicCheckout(unittest.TestCase):

    def test_signed_in_subscriber_is_not_charged_twice(self):
        client = support.signed_in_client()
        org = support.organization()
        org.subscription_status, org.stripe_subscription_id = "active", "sub_new"
        support.account()["db"].commit()
        with patch.object(stripe.checkout.Session, "create") as create:
            response = client.post(
                "/purchase/checkout",
                data={"plan": "enterprise", "billing_interval": "monthly"},
                headers=support.ORIGIN,
            )
        self.assertEqual(response.headers["location"], "/settings/subscription")
        create.assert_not_called()


if __name__ == "__main__":
    unittest.main()
