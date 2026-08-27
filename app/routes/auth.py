import re
import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.auth import hash_password, verify_password
from app.database import get_db
from app.models import (
    AuditEvent,
    Membership,
    Organization,
    PendingPurchase,
    TeamInvitation,
    User,
)
from app.plans import get_plan_config
from app.routes.billing import (
    sync_subscription_to_organization,
)


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")


def make_unique_slug(
    db: Session,
    organization_name: str,
) -> str:
    base_slug = slugify(organization_name) or "organization"
    slug = base_slug
    counter = 2

    while db.scalar(
        select(Organization).where(
            Organization.slug == slug
        )
    ):
        slug = f"{base_slug}-{counter}"
        counter += 1

    return slug


@router.get(
    "/signup",
    response_class=HTMLResponse,
)
def signup_page(
    request: Request,
    purchase_token: str | None = None,
    db: Session = Depends(get_db),
):
    if not purchase_token:
        return RedirectResponse(
            url="/pricing",
            status_code=303,
        )

    pending_purchase = (
        db.query(PendingPurchase)
        .filter(
            PendingPurchase.token
            == purchase_token
        )
        .first()
    )

    if (
        pending_purchase is None
        or pending_purchase.status
        != "paid"
    ):
        return RedirectResponse(
            url="/pricing",
            status_code=303,
        )

    claim_error = (
        request.query_params.get("claim_error")
        == "1"
    )

    existing_subscription = (
        request.query_params.get(
            "existing_subscription"
        )
        == "1"
    )

    existing_user = None

    purchase_email = None

    if pending_purchase.customer_email:
        purchase_email = (
            pending_purchase.customer_email
            .strip()
            .lower()
        )

        existing_user = (
            db.query(User)
            .filter(
                User.email == purchase_email
            )
            .first()
        )

    plan_config = get_plan_config(
        pending_purchase.plan
    )

    if (
        pending_purchase.billing_interval
        == "annual"
    ):
        billing_interval_label = "Annual"
        billing_price_label = (
            f"${plan_config['annual_price']}/year"
        )
    else:
        billing_interval_label = "Monthly"
        billing_price_label = (
            f"${plan_config['monthly_price']}/month"
        )

    return templates.TemplateResponse(
        request=request,
        name="signup.html",
        context={
            "error": None,
            "robots_content": "noindex, nofollow",
            "purchase_token": purchase_token,
            "existing_user": existing_user,
            "claim_error": claim_error,
            "existing_subscription": existing_subscription,
            "selected_plan": (
                pending_purchase.plan
            ),
            "selected_plan_config": plan_config,
            "billing_interval": (
                pending_purchase.billing_interval
            ),
            "billing_interval_label": (
                billing_interval_label
            ),
            "billing_price_label": (
                billing_price_label
            ),
            "purchase_email": purchase_email,
        },
    )


@router.post(
    "/signup",
    response_class=HTMLResponse,
)
def signup(
    request: Request,
    purchase_token: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    organization_name: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    db: Session = Depends(get_db),
):
    name = name.strip()
    organization_name = (
        organization_name.strip()
    )

    pending_purchase = (
        db.query(PendingPurchase)
        .filter(
            PendingPurchase.token
            == purchase_token
        )
        .first()
    )

    if (
        pending_purchase is None
        or pending_purchase.status
        != "paid"
    ):
        return RedirectResponse(
            url="/pricing",
            status_code=303,
        )

    plan_config = get_plan_config(
        pending_purchase.plan
    )

    if (
        pending_purchase.billing_interval
        == "annual"
    ):
        billing_interval_label = "Annual"
        billing_price_label = (
            f"${plan_config['annual_price']}/year"
        )
    else:
        billing_interval_label = "Monthly"
        billing_price_label = (
            f"${plan_config['monthly_price']}/month"
        )

    purchase_email = (
        pending_purchase.customer_email
        or email
    )

    purchase_email = (
        purchase_email.strip().lower()
    )

    def signup_error_context(
        error_message: str,
    ) -> dict:
        return {
            "error": error_message,
            "robots_content": "noindex, nofollow",
            "purchase_token": purchase_token,
            "selected_plan": (
                pending_purchase.plan
            ),
            "selected_plan_config": (
                plan_config
            ),
            "billing_interval": (
                pending_purchase
                .billing_interval
            ),
            "billing_interval_label": (
                billing_interval_label
            ),
            "billing_price_label": (
                billing_price_label
            ),
            "purchase_email": (
                purchase_email
            ),
        }

    if (
        not name
        or not purchase_email
        or not organization_name
    ):
        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context=signup_error_context(
                "Please complete all required fields."
            ),
            status_code=400,
        )

    if password != password_confirm:
        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context=signup_error_context(
                "The passwords do not match."
            ),
            status_code=400,
        )

    if len(password) < 10:
        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context=signup_error_context(
                (
                    "Your password must be at least "
                    "10 characters long."
                )
            ),
            status_code=400,
        )

    existing_user = db.scalar(
        select(User).where(
            User.email == purchase_email
        )
    )

    if existing_user:
        return templates.TemplateResponse(
            request=request,
            name="signup.html",
            context=signup_error_context(
                (
                    "An account already exists "
                    "for this email address."
                )
            ),
            status_code=400,
        )

    organization = Organization(
        name=organization_name,
        slug=make_unique_slug(
            db,
            organization_name,
        ),
        plan=pending_purchase.plan,
        subscription_status="inactive",
        stripe_customer_id=(
            pending_purchase.stripe_customer_id
        ),
        stripe_subscription_id=(
            pending_purchase
            .stripe_subscription_id
        ),
        stripe_price_id=(
            pending_purchase.stripe_price_id
        ),
    )

    user = User(
        name=name,
        email=purchase_email,
        password_hash=hash_password(
            password
        ),
        is_active=True,
        is_verified=False,
    )

    db.add(organization)
    db.add(user)

    db.flush()

    membership = Membership(
        user_id=user.id,
        organization_id=organization.id,
        role="owner",
        is_active=True,
    )

    db.add(membership)
    db.commit()

    if organization.stripe_subscription_id:
        import stripe

        from app.config import (
            STRIPE_SECRET_KEY,
        )

        stripe.api_key = STRIPE_SECRET_KEY

        subscription = (
            stripe.Subscription.retrieve(
                organization
                .stripe_subscription_id
            )
        )

        organization = (
            sync_subscription_to_organization(
                db,
                subscription,
            )
        )

    pending_purchase.status = "claimed"

    db.commit()

    request.session.clear()

    request.session["user_id"] = user.id
    request.session["organization_id"] = (
        organization.id
    )

    return RedirectResponse(
        url="/dashboard",
        status_code=303,
    )


@router.get(
    "/login",
    response_class=HTMLResponse,
)
def login_page(
    request: Request,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": None,
            "robots_content": "noindex, nofollow",
        },
    )


@router.post(
    "/login",
    response_class=HTMLResponse,
)
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    email = email.strip().lower()

    user = db.scalar(
        select(User).where(
            User.email == email
        )
    )

    if (
        user is None
        or not user.is_active
        or not verify_password(
            password,
            user.password_hash,
        )
    ):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Invalid email or password.",
            },
            status_code=400,
        )

    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.is_active.is_(True),
        )
    )

    if membership is None:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": (
                    "No active organization membership "
                    "was found for this account."
                ),
            },
            status_code=400,
        )

    request.session.clear()

    request.session["user_id"] = user.id
    request.session["organization_id"] = (
        membership.organization_id
    )

    return RedirectResponse(
        url="/dashboard",
        status_code=303,
    )


@router.get(
    "/invite/{token}",
    response_class=HTMLResponse,
)
def invitation_page(
    token: str,
    request: Request,
    db: Session = Depends(get_db),
):
    invitation = db.scalar(
        select(TeamInvitation).where(
            TeamInvitation.token == token,
            TeamInvitation.status == "pending",
        )
    )

    if invitation is None:
        return templates.TemplateResponse(
            request=request,
            name="invite_accept.html",
            context={
                "invitation": None,
                "organization": None,
                "existing_user": None,
                "error": (
                    "This invitation is invalid "
                    "or is no longer available."
                ),
                "robots_content": "noindex, nofollow",
            },
            status_code=404,
        )

    expires_at = invitation.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(
            tzinfo=timezone.utc
        )

    if expires_at < datetime.now(timezone.utc):
        invitation.status = "expired"

        db.commit()

        return templates.TemplateResponse(
            request=request,
            name="invite_accept.html",
            context={
                "invitation": None,
                "organization": None,
                "existing_user": None,
                "error": (
                    "This invitation has expired."
                ),
            },
            status_code=400,
        )

    organization = db.get(
        Organization,
        invitation.organization_id,
    )

    existing_user = db.scalar(
        select(User).where(
            User.email == invitation.email
        )
    )

    return templates.TemplateResponse(
        request=request,
        name="invite_accept.html",
        context={
            "invitation": invitation,
            "organization": organization,
            "existing_user": existing_user,
            "error": None,
        },
    )

@router.post(
    "/invite/{token}",
    response_class=HTMLResponse,
)
def accept_invitation(
    token: str,
    request: Request,
    name: str = Form(""),
    password: str = Form(...),
    password_confirm: str = Form(""),
    db: Session = Depends(get_db),
):
    invitation = db.scalar(
        select(TeamInvitation).where(
            TeamInvitation.token == token,
            TeamInvitation.status == "pending",
        )
    )

    if invitation is None:
        return templates.TemplateResponse(
            request=request,
            name="invite_accept.html",
            context={
                "invitation": None,
                "organization": None,
                "existing_user": None,
                "error": (
                    "This invitation is invalid "
                    "or is no longer available."
                ),
            },
            status_code=404,
        )

    expires_at = invitation.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(
            tzinfo=timezone.utc
        )

    if expires_at < datetime.now(timezone.utc):
        invitation.status = "expired"

        db.commit()

        return templates.TemplateResponse(
            request=request,
            name="invite_accept.html",
            context={
                "invitation": None,
                "organization": None,
                "existing_user": None,
                "error": (
                    "This invitation has expired."
                ),
            },
            status_code=400,
        )

    organization = db.get(
        Organization,
        invitation.organization_id,
    )

    existing_user = db.scalar(
        select(User).where(
            User.email == invitation.email
        )
    )

    if existing_user is not None:

        if (
            not existing_user.is_active
            or not verify_password(
                password,
                existing_user.password_hash,
            )
        ):
            return templates.TemplateResponse(
                request=request,
                name="invite_accept.html",
                context={
                    "invitation": invitation,
                    "organization": organization,
                    "existing_user": existing_user,
                    "error": "Invalid password.",
                },
                status_code=400,
            )

        user = existing_user

    else:

        name = name.strip()

        if not name:
            return templates.TemplateResponse(
                request=request,
                name="invite_accept.html",
                context={
                    "invitation": invitation,
                    "organization": organization,
                    "existing_user": None,
                    "error": (
                        "Please enter your name."
                    ),
                },
                status_code=400,
            )

        if password != password_confirm:
            return templates.TemplateResponse(
                request=request,
                name="invite_accept.html",
                context={
                    "invitation": invitation,
                    "organization": organization,
                    "existing_user": None,
                    "error": (
                        "The passwords do not match."
                    ),
                },
                status_code=400,
            )

        if len(password) < 10:
            return templates.TemplateResponse(
                request=request,
                name="invite_accept.html",
                context={
                    "invitation": invitation,
                    "organization": organization,
                    "existing_user": None,
                    "error": (
                        "Your password must be at least "
                        "10 characters long."
                    ),
                },
                status_code=400,
            )

        user = User(
            name=name,
            email=invitation.email,
            password_hash=hash_password(
                password
            ),
            is_active=True,
            is_verified=False,
        )

        db.add(user)
        db.flush()

    existing_membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.organization_id
            == invitation.organization_id,
        )
    )

    seat_will_be_consumed = (
        existing_membership is None
        or not existing_membership.is_active
    )

    if seat_will_be_consumed:

        plan_config = get_plan_config(
            organization.plan
        )

        team_member_limit = (
            plan_config["team_member_limit"]
        )

        if team_member_limit is not None:

            active_team_member_count = (
                db.query(Membership)
                .filter(
                    Membership.organization_id
                    == organization.id,
                    Membership.is_active.is_(True),
                )
                .count()
            )

            if (
                active_team_member_count
                >= team_member_limit
            ):
                db.rollback()

                return templates.TemplateResponse(
                    request=request,
                    name="invite_accept.html",
                    context={
                        "invitation": invitation,
                        "organization": organization,
                        "existing_user": (
                            existing_user
                        ),
                        "error": (
                            f"The {plan_config['name']} "
                            f"plan supports up to "
                            f"{team_member_limit} active "
                            "team members. An organization "
                            "administrator must free a seat "
                            "before this invitation can be "
                            "accepted."
                        ),
                    },
                    status_code=400,
                )


    if existing_membership is None:

        membership = Membership(
            user_id=user.id,
            organization_id=(
                invitation.organization_id
            ),
            role=invitation.role,
            is_active=True,
        )

        db.add(membership)
        db.flush()

        event_type = "team_member_joined"

        event_description = (
            f"{user.name} joined "
            f"{organization.name} as "
            f"{invitation.role.title()}."
        )

        membership_id = membership.id


    else:

        was_active = (
            existing_membership.is_active
        )

        old_role = (
            existing_membership.role
        )

        existing_membership.role = (
            invitation.role
        )

        existing_membership.is_active = True

        membership_id = (
            existing_membership.id
        )

        if was_active:

            event_type = (
                "team_invitation_accepted"
            )

            event_description = (
                f"{user.name} accepted an invitation "
                f"to {organization.name}."
            )

        else:

            event_type = (
                "team_member_reactivated"
            )

            event_description = (
                f"{user.name} rejoined "
                f"{organization.name} as "
                f"{invitation.role.title()}."
            )


    invitation.status = "accepted"


    audit_event = AuditEvent(
        organization_id=invitation.organization_id,
        user_id=user.id,
        event_type=event_type,
        description=event_description,
        metadata_json=json.dumps(
            {
                "invitation_id": invitation.id,
                "membership_id": membership_id,
                "email": invitation.email,
                "role": invitation.role,
                "previous_role": (
                    old_role
                    if existing_membership is not None
                    else None
                ),
            }
        ),
    )

    db.add(audit_event)
    db.commit()

    request.session.clear()

    request.session["user_id"] = user.id

    request.session["organization_id"] = (
        invitation.organization_id
    )

    return RedirectResponse(
        url="/dashboard",
        status_code=303,
    )

@router.post("/logout")
def logout(
    request: Request,
):
    request.session.clear()

    return RedirectResponse(
        url="/",
        status_code=303,
    )

@router.post("/purchase/claim-existing")
def claim_existing_purchase(
    request: Request,
    purchase_token: str = Form(...),
    password: str = Form(...),
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

    if (
        pending_purchase is None
        or pending_purchase.status
        != "paid"
        or not pending_purchase.customer_email
    ):
        return RedirectResponse(
            url="/pricing",
            status_code=303,
        )

    purchase_email = (
        pending_purchase.customer_email
        .strip()
        .lower()
    )

    user = (
        db.query(User)
        .filter(
            User.email == purchase_email
        )
        .first()
    )

    if (
        user is None
        or not user.is_active
        or not verify_password(
            password,
            user.password_hash,
        )
    ):
        return RedirectResponse(
            url=(
                "/signup"
                f"?purchase_token={purchase_token}"
                "&claim_error=1"
            ),
            status_code=303,
        )

    existing_membership = (
        db.query(Membership)
        .filter(
            Membership.user_id == user.id,
            Membership.is_active.is_(True),
        )
        .first()
    )

    existing_org = None

    if existing_membership is not None:
        existing_org = (
            db.query(Organization)
            .filter(
                Organization.id
                == existing_membership.organization_id
            )
            .first()
        )

    if (
        existing_org is not None
        and existing_org.stripe_subscription_id
    ):
        return RedirectResponse(
            url=(
                "/signup"
                f"?purchase_token={purchase_token}"
                "&existing_subscription=1"
            ),
            status_code=303,
        )

    if existing_org is not None:

        organization = existing_org

        organization.plan = (
            pending_purchase.plan
        )

        organization.subscription_status = (
            "inactive"
        )

        organization.stripe_customer_id = (
            pending_purchase.stripe_customer_id
        )

        organization.stripe_subscription_id = (
            pending_purchase.stripe_subscription_id
        )

        organization.stripe_price_id = (
            pending_purchase.stripe_price_id
        )

    else:

        organization_name = (
            f"{user.name}'s Organization"
        )

        organization = Organization(
            name=organization_name,
            slug=make_unique_slug(
                db,
                organization_name,
            ),
            plan=pending_purchase.plan,
            subscription_status="inactive",
            stripe_customer_id=(
                pending_purchase.stripe_customer_id
            ),
            stripe_subscription_id=(
                pending_purchase
                .stripe_subscription_id
            ),
            stripe_price_id=(
                pending_purchase.stripe_price_id
            ),
        )

        db.add(organization)
        db.flush()

        membership = Membership(
            user_id=user.id,
            organization_id=organization.id,
            role="owner",
            is_active=True,
        )

        db.add(membership)

    db.commit()

    if organization.stripe_subscription_id:
        import stripe

        from app.config import (
            STRIPE_SECRET_KEY,
        )

        stripe.api_key = STRIPE_SECRET_KEY

        subscription = (
            stripe.Subscription.retrieve(
                organization.stripe_subscription_id
            )
        )

        organization = (
            sync_subscription_to_organization(
                db,
                subscription,
            )
        )

    pending_purchase.status = "claimed"
    db.commit()

    request.session.clear()

    request.session["user_id"] = user.id
    request.session["organization_id"] = (
        organization.id
    )

    return RedirectResponse(
        url="/dashboard",
        status_code=303,
    )