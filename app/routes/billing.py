from fastapi import (
    APIRouter,
    Depends,
    Form,
    Request,
)
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,   
    RedirectResponse,
)
from sqlalchemy.orm import Session

from datetime import datetime, timezone

import logging
import secrets

import stripe

from app.config import (
    APP_BASE_URL,
    STRIPE_ENTERPRISE_ANNUAL_PRICE_ID,
    STRIPE_ENTERPRISE_MONTHLY_PRICE_ID,
    STRIPE_SECRET_KEY,
    STRIPE_SMALL_BUSINESS_ANNUAL_PRICE_ID,
    STRIPE_SMALL_BUSINESS_MONTHLY_PRICE_ID,
    STRIPE_BUSINESS_PORTAL_CONFIGURATION_ID,
    STRIPE_WEBHOOK_SECRET,
)
from app.database import get_db
from app.dependencies import (
    get_current_membership,
    get_current_organization,
    get_current_user,
)
from app.models import (
    Membership,
    Organization,
    PendingPurchase,
    User,
    EvaluationInvitation,
)


router = APIRouter()


stripe.api_key = STRIPE_SECRET_KEY

logger = logging.getLogger("uvicorn.error")

# Organizations whose access is set by hand (for example PreClear's own
# accounts). Stripe events never change these.
MANUALLY_MANAGED_STATUSES = {
    "internal",
}

# When a customer has several subscriptions (an old canceled one and a new
# active one, say), the one that should decide their access, best first.
SUBSCRIPTION_STATUS_PRIORITY = {
    "active": 0,
    "trialing": 1,
    "past_due": 2,
    "unpaid": 3,
    "incomplete": 4,
    "paused": 5,
    "incomplete_expired": 6,
    "canceled": 7,
}


PRICE_MAP = {
    (
        "small_business",
        "monthly",
    ): STRIPE_SMALL_BUSINESS_MONTHLY_PRICE_ID,
    (
        "small_business",
        "annual",
    ): STRIPE_SMALL_BUSINESS_ANNUAL_PRICE_ID,
    (
        "enterprise",
        "monthly",
    ): STRIPE_ENTERPRISE_MONTHLY_PRICE_ID,
    (
        "enterprise",
        "annual",
    ): STRIPE_ENTERPRISE_ANNUAL_PRICE_ID,
}

PRICE_TO_PLAN = {
    STRIPE_SMALL_BUSINESS_MONTHLY_PRICE_ID: (
        "small_business"
    ),
    STRIPE_SMALL_BUSINESS_ANNUAL_PRICE_ID: (
        "small_business"
    ),
    STRIPE_ENTERPRISE_MONTHLY_PRICE_ID: (
        "enterprise"
    ),
    STRIPE_ENTERPRISE_ANNUAL_PRICE_ID: (
        "enterprise"
    ),
}

def mark_evaluation_converted(
    db: Session,
    organization: Organization,
) -> None:
    if organization.subscription_status not in {
        "active",
        "trialing",
    }:
        return

    evaluation = (
        db.query(EvaluationInvitation)
        .filter(
            EvaluationInvitation.organization_id
            == organization.id,
            EvaluationInvitation.status.in_(
                {
                    "accepted",
                    "expired",
                    "revoked",
                }
            ),
        )
        .order_by(
            EvaluationInvitation.id.desc()
        )
        .first()
    )

    if evaluation is None:
        return

    evaluation.status = "converted"

    db.add(evaluation)
    db.commit()

def sync_subscription_to_organization(
    db: Session,
    subscription,
) -> Organization | None:
    if hasattr(
        subscription,
        "to_dict",
    ):
        subscription = subscription.to_dict()
    metadata = subscription.get(
        "metadata",
        {},
    )

    organization_id = metadata.get(
        "organization_id"
    )

    organization = None

    if organization_id:
        try:
            organization = (
                db.query(Organization)
                .filter(
                    Organization.id
                    == int(organization_id)
                )
                .first()
            )
        except (
            TypeError,
            ValueError,
        ):
            organization = None

    customer_id = subscription.get(
        "customer"
    )

    if (
        organization is None
        and customer_id
    ):
        organization = (
            db.query(Organization)
            .filter(
                Organization.stripe_customer_id
                == customer_id
            )
            .first()
        )

    if organization is None:
        return None

    if organization.subscription_status in MANUALLY_MANAGED_STATUSES:
        logger.info(
            "Stripe sync skipped for organization %s: access is managed "
            "manually (%s).",
            organization.id,
            organization.subscription_status,
        )
        return organization

    items = subscription.get(
        "items",
        {},
    )

    item_data = items.get(
        "data",
        [],
    )

    price_id = None

    if item_data:
        price = item_data[0].get(
            "price",
            {},
        )

        price_id = price.get(
            "id"
        )

    plan = PRICE_TO_PLAN.get(
        price_id
    )

    organization.stripe_customer_id = (
        customer_id
    )

    organization.stripe_subscription_id = (
        subscription.get("id")
    )

    organization.stripe_price_id = (
        price_id
    )

    organization.subscription_status = (
        subscription.get("status")
    )

    cancel_at = subscription.get(
        "cancel_at"
    )

    cancel_at_period_end = subscription.get(
        "cancel_at_period_end",
        False,
    )

    organization.subscription_cancel_at_period_end = (
        bool(
            cancel_at_period_end
            or cancel_at
        )
    )

    current_period_end = subscription.get(
        "current_period_end"
    )

    effective_period_end = (
        current_period_end
        or cancel_at
    )

    if effective_period_end:
        organization.subscription_current_period_end = (
            datetime.fromtimestamp(
                effective_period_end,
                tz=timezone.utc,
            )
        )
    else:
        organization.subscription_current_period_end = (
            None
        )

    if plan:
        organization.plan = plan

    db.commit()
    db.refresh(
        organization
    )

    mark_evaluation_converted(
        db,
        organization,
    )

    return organization


def _current_subscription(customer_id: str):
    """
    Asks Stripe for all of a customer's subscriptions and returns the one
    that should decide their access: the best status, then the newest.
    Raises stripe.StripeError if Stripe can't be reached.
    """
    subscriptions = stripe.Subscription.list(
        customer=customer_id,
        status="all",
        limit=20,
    )

    if hasattr(subscriptions, "to_dict"):
        subscriptions = subscriptions.to_dict()

    candidates = list(subscriptions.get("data", []))

    if not candidates:
        return None

    return min(
        candidates,
        key=lambda item: (
            SUBSCRIPTION_STATUS_PRIORITY.get(item.get("status"), 9),
            -(item.get("created") or 0),
        ),
    )


def sync_customer_subscription(
    db: Session,
    customer_id: str | None,
    fallback_subscription=None,
) -> Organization | None:
    """
    Updates an organization from its customer's current subscription as
    Stripe reports it now, rather than from whatever an individual event
    says. Webhook events can arrive late or out of order, and an event for
    an old subscription (a canceled one, say) must not override a newer
    active one or grant access before payment.
    """
    if not customer_id:
        if fallback_subscription is not None:
            return sync_subscription_to_organization(db, fallback_subscription)
        return None

    current = _current_subscription(customer_id)

    if current is None:
        return None

    return sync_subscription_to_organization(db, current)


@router.post("/purchase/checkout")
def create_purchase_checkout_session(
    request: Request,
    plan: str = Form(...),
    billing_interval: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(
        get_current_user
    ),
    current_organization: Organization | None = Depends(
        get_current_organization
    ),
    current_membership: Membership | None = Depends(
        get_current_membership
    ),
):
    # Someone already signed in who buys from the public pricing page
    # would otherwise get a second, unlinked Stripe customer and a plan
    # that never appears on their account. Their purchase goes through
    # the account checkout instead, which also stops a second
    # subscription if they already have one.
    if (
        current_user is not None
        and current_organization is not None
        and current_membership is not None
    ):
        return create_checkout_session(
            request=request,
            plan=plan,
            billing_interval=billing_interval,
            db=db,
            current_user=current_user,
            current_organization=current_organization,
            current_membership=current_membership,
        )

    price_id = PRICE_MAP.get(
        (
            plan,
            billing_interval,
        )
    )

    if not price_id:
        return RedirectResponse(
            url="/pricing",
            status_code=303,
        )

    if not STRIPE_SECRET_KEY:
        raise RuntimeError(
            "STRIPE_SECRET_KEY is not configured."
        )

    purchase_token = secrets.token_urlsafe(
        32
    )

    pending_purchase = PendingPurchase(
        token=purchase_token,
        plan=plan,
        billing_interval=billing_interval,
        status="pending",
        stripe_price_id=price_id,
    )

    db.add(pending_purchase)
    db.commit()
    db.refresh(pending_purchase)

    checkout_session = (
        stripe.checkout.Session.create(
            mode="subscription",
            line_items=[
                {
                    "price": price_id,
                    "quantity": 1,
                }
            ],
            client_reference_id=(
                purchase_token
            ),
            metadata={
                "purchase_token": (
                    purchase_token
                ),
                "plan": plan,
                "billing_interval": (
                    billing_interval
                ),
            },
            subscription_data={
                "metadata": {
                    "purchase_token": (
                        purchase_token
                    ),
                    "plan": plan,
                    "billing_interval": (
                        billing_interval
                    ),
                }
            },
            success_url=(
                f"{APP_BASE_URL}"
                "/purchase/complete"
                f"?purchase_token={purchase_token}"
                "&session_id={CHECKOUT_SESSION_ID}"
            ),
            cancel_url=(
                f"{APP_BASE_URL}"
                "/pricing?checkout=cancelled"
            ),
        )
    )

    pending_purchase.stripe_checkout_session_id = (
        checkout_session.id
    )

    db.commit()

    return RedirectResponse(
        url=checkout_session.url,
        status_code=303,
    )

@router.get(
    "/purchase/complete",
    response_class=HTMLResponse,
)
def purchase_complete_page(
    request: Request,
    purchase_token: str,
    session_id: str | None = None,
    db: Session = Depends(get_db),
):
    pending_purchase = (
        db.query(PendingPurchase)
        .filter(
            PendingPurchase.token
            == purchase_token
        )
        .first()
    )

    if pending_purchase is None:
        return RedirectResponse(
            url="/pricing",
            status_code=303,
        )

    if (
        pending_purchase.status == "pending"
        and session_id
    ):
        if (
            pending_purchase
            .stripe_checkout_session_id
            != session_id
        ):
            return RedirectResponse(
                url="/pricing",
                status_code=303,
            )

        try:
            checkout_session = (
                stripe.checkout.Session.retrieve(
                    session_id
                )
            )

            checkout_session = checkout_session.to_dict()

        except stripe.StripeError:
            return RedirectResponse(
                url="/pricing",
                status_code=303,
            )

        metadata = checkout_session.get(
            "metadata",
            {},
        )

        session_purchase_token = (
            metadata.get(
                "purchase_token"
            )
        )

        if (
            checkout_session.get("status")
            != "complete"
            or session_purchase_token
            != purchase_token
        ):
            return RedirectResponse(
                url="/pricing",
                status_code=303,
            )

        subscription_id = (
            checkout_session.get(
                "subscription"
            )
        )

        customer_id = (
            checkout_session.get(
                "customer"
            )
        )

        customer_details = (
            checkout_session.get(
                "customer_details",
                {},
            )
            or {}
        )

        customer_email = (
            customer_details.get(
                "email"
            )
        )

        if (
            not subscription_id
            or not customer_id
        ):
            return RedirectResponse(
                url="/pricing",
                status_code=303,
            )

        pending_purchase.status = "paid"

        pending_purchase.stripe_customer_id = (
            customer_id
        )

        pending_purchase.stripe_subscription_id = (
            subscription_id
        )

        pending_purchase.customer_email = (
            customer_email
        )

        pending_purchase.completed_at = (
            datetime.now(timezone.utc)
        )

        db.commit()

    if pending_purchase.status != "paid":
        return RedirectResponse(
            url="/pricing",
            status_code=303,
        )

    return RedirectResponse(
        url=(
            "/signup"
            f"?purchase_token={purchase_token}"
        ),
        status_code=303,
    )

@router.post("/billing/checkout")
def create_checkout_session(
    request: Request,
    plan: str = Form(...),
    billing_interval: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(
        get_current_user
    ),
    current_organization: Organization | None = Depends(
        get_current_organization
    ),
    current_membership: Membership | None = Depends(
        get_current_membership
    ),
):
    if (
        current_user is None
        or current_organization is None
        or current_membership is None
    ):
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    if current_membership.role not in {
        "owner",
        "admin",
    }:
        return RedirectResponse(
            url="/settings/subscription",
            status_code=303,
        )

    if (
        current_organization.stripe_subscription_id
        and current_organization.subscription_status
        in {
            "active",
            "trialing",
            "past_due",
        }
    ) or (
        current_organization.subscription_status
        in MANUALLY_MANAGED_STATUSES
    ):
        return RedirectResponse(
            url="/settings/subscription",
            status_code=303,
        )

    price_id = PRICE_MAP.get(
        (
            plan,
            billing_interval,
        )
    )

    if not price_id:
        return RedirectResponse(
            url="/settings/subscription",
            status_code=303,
        )

    if not STRIPE_SECRET_KEY:
        raise RuntimeError(
            "STRIPE_SECRET_KEY is not configured."
        )

    if not current_organization.stripe_customer_id:

        customer = stripe.Customer.create(
            name=current_organization.name,
            email=current_user.email,
            metadata={
                "organization_id": str(
                    current_organization.id
                ),
            },
        )

        current_organization.stripe_customer_id = (
            customer.id
        )

        db.commit()

    checkout_session = (
        stripe.checkout.Session.create(
            mode="subscription",
            customer=(
                current_organization.stripe_customer_id
            ),
            line_items=[
                {
                    "price": price_id,
                    "quantity": 1,
                }
            ],
            success_url=(
                f"{APP_BASE_URL}"
                "/settings/subscription"
                "?checkout=success"
                "&session_id={CHECKOUT_SESSION_ID}"
            ),
            cancel_url=(
                f"{APP_BASE_URL}"
                "/settings/subscription"
                "?checkout=cancelled"
            ),
            client_reference_id=str(
                current_organization.id
            ),
            metadata={
                "organization_id": str(
                    current_organization.id
                ),
                "plan": plan,
                "billing_interval": (
                    billing_interval
                ),
            },
            subscription_data={
                "metadata": {
                    "organization_id": str(
                        current_organization.id
                    ),
                    "plan": plan,
                    "billing_interval": (
                        billing_interval
                    ),
                }
            },
        )
    )

    return RedirectResponse(
        url=checkout_session.url,
        status_code=303,
    )

def _sync_or_retry(db: Session, customer_id, fallback=None) -> bool:
    """Syncs a customer's subscription. Returns False if Stripe couldn't be
    reached, so the webhook can ask Stripe to send the event again."""
    try:
        sync_customer_subscription(db, customer_id, fallback)
    except stripe.StripeError as error:
        db.rollback()
        logger.warning(
            "Stripe webhook: couldn't load subscriptions for customer %s: %s",
            customer_id,
            error,
        )
        return False
    return True


def _retry_later() -> JSONResponse:
    # Any non-2xx reply makes Stripe resend the event later.
    return JSONResponse(
        status_code=503,
        content={
            "received": False,
            "error": "Temporarily unable to reach Stripe.",
        },
    )


@router.post("/billing/webhook")
async def stripe_webhook(
    request: Request,
    db: Session = Depends(get_db),
):
    if not STRIPE_WEBHOOK_SECRET:
        # 503 tells Stripe to retry later, once the secret is set.
        logger.error(
            "Stripe webhook received but STRIPE_WEBHOOK_SECRET is not set; "
            "the event was not processed."
        )
        return JSONResponse(
            status_code=503,
            content={
                "received": False,
                "error": (
                    "Webhook secret not configured."
                ),
            },
        )

    payload = await request.body()

    signature = request.headers.get(
        "stripe-signature"
    )

    if not signature:
        return JSONResponse(
            status_code=400,
            content={
                "received": False,
                "error": (
                    "Missing Stripe signature."
                ),
            },
        )

    try:
        event = (
            stripe.Webhook.construct_event(
                payload,
                signature,
                STRIPE_WEBHOOK_SECRET,
            )
        )

        event = event.to_dict()

    except (
        ValueError,
        stripe.SignatureVerificationError,
    ):
        return JSONResponse(
            status_code=400,
            content={
                "received": False,
                "error": (
                    "Invalid webhook signature."
                ),
            },
        )

    event_type = event.get(
        "type"
    )

    event_object = (
        event.get(
            "data",
            {},
        )
        .get(
            "object",
            {},
        )
    )

    if event_type == (
        "checkout.session.completed"
    ):
        metadata = event_object.get(
            "metadata",
            {},
        )

        purchase_token = metadata.get(
            "purchase_token"
        )

        if purchase_token:

            pending_purchase = (
                db.query(PendingPurchase)
                .filter(
                    PendingPurchase.token
                    == purchase_token
                )
                .first()
            )

            if pending_purchase is not None:

                subscription_id = (
                    event_object.get(
                        "subscription"
                    )
                )

                customer_id = (
                    event_object.get(
                        "customer"
                    )
                )

                customer_details = (
                    event_object.get(
                        "customer_details",
                        {},
                    )
                )

                customer_email = (
                    customer_details.get(
                        "email"
                    )
                )

                pending_purchase.status = "paid"

                pending_purchase.stripe_customer_id = (
                    customer_id
                )

                pending_purchase.stripe_subscription_id = (
                    subscription_id
                )

                pending_purchase.customer_email = (
                    customer_email
                )

                pending_purchase.completed_at = (
                    datetime.now(timezone.utc)
                )

                db.commit()

        elif event_object.get("customer"):
            if not _sync_or_retry(db, event_object.get("customer")):
                return _retry_later()

    elif event_type in {
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.paid",
        "invoice.payment_failed",
    }:
        fallback = (
            event_object
            if event_type.startswith("customer.subscription")
            else None
        )

        if not _sync_or_retry(
            db,
            event_object.get("customer"),
            fallback,
        ):
            return _retry_later()

    return {
        "received": True,
    }

@router.post("/billing/portal")
def create_billing_portal_session(
    current_user: User | None = Depends(
        get_current_user
    ),
    current_organization: Organization | None = Depends(
        get_current_organization
    ),
    current_membership: Membership | None = Depends(
        get_current_membership
    ),
):
    if (
        current_user is None
        or current_organization is None
        or current_membership is None
    ):
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    if current_membership.role not in {
        "owner",
        "admin",
    }:
        return RedirectResponse(
            url="/settings/subscription",
            status_code=303,
        )

    if not current_organization.stripe_customer_id:
        return RedirectResponse(
            url="/settings/subscription",
            status_code=303,
        )

    if not STRIPE_BUSINESS_PORTAL_CONFIGURATION_ID:
        return RedirectResponse(
            url="/settings/subscription",
            status_code=303,
        )

    portal_session = (
        stripe.billing_portal.Session.create(
            customer=(
                current_organization.stripe_customer_id
            ),
            configuration=(
                STRIPE_BUSINESS_PORTAL_CONFIGURATION_ID
            ),
            return_url=(
                f"{APP_BASE_URL}"
                "/settings/subscription"
            ),
        )
    )
    

    return RedirectResponse(
        url=portal_session.url,
        status_code=303,
    )