from fastapi import APIRouter, Depends, Request
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
)
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import (
    get_current_membership,
    get_current_organization,
    get_current_user,
)
from app.models import (
    Environment,
    Membership,
    Organization,
    User,
)
from app.plans import get_plan_config

from app.config import (
    STRIPE_ENTERPRISE_ANNUAL_PRICE_ID,
    STRIPE_ENTERPRISE_MONTHLY_PRICE_ID,
    STRIPE_SMALL_BUSINESS_ANNUAL_PRICE_ID,
    STRIPE_SMALL_BUSINESS_MONTHLY_PRICE_ID,
)


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)


@router.get(
    "/settings",
    response_class=HTMLResponse,
)
def settings_page(
    request: Request,
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
            url="/dashboard",
            status_code=303,
        )

    plan_config = get_plan_config(
        current_organization.plan
    )

    active_team_members = (
        db.query(Membership)
        .filter(
            Membership.organization_id
            == current_organization.id,
            Membership.is_active.is_(True),
        )
        .count()
    )

    active_environments = (
        db.query(Environment)
        .filter(
            Environment.organization_id
            == current_organization.id,
            Environment.is_active.is_(True),
        )
        .count()
    )

    subscription_status = (
        current_organization.subscription_status
        or "inactive"
    )

    subscription_status_label = (
        subscription_status
        .replace("_", " ")
        .title()
    )

    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "active_page": "settings",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "plan_config": plan_config,
            "subscription_status": (
                subscription_status
            ),
            "subscription_status_label": (
                subscription_status_label
            ),
            "active_team_members": (
                active_team_members
            ),
            "active_environments": (
                active_environments
            ),
        },
    )

@router.get(
    "/settings/subscription",
    response_class=HTMLResponse,
)
def subscription_settings_page(
    request: Request,
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
            url="/settings",
            status_code=303,
        )

    plan_config = get_plan_config(
        current_organization.plan
    )

    active_team_member_count = (
        db.query(Membership)
        .filter(
            Membership.organization_id
            == current_organization.id,
            Membership.is_active.is_(True),
        )
        .count()
    )

    active_environment_count = (
        db.query(Environment)
        .filter(
            Environment.organization_id
            == current_organization.id,
            Environment.is_active.is_(True),
        )
        .count()
    )

    team_member_limit = (
        plan_config["team_member_limit"]
    )

    environment_limit = (
        plan_config["environment_limit"]
    )

    team_over_limit = (
        team_member_limit is not None
        and active_team_member_count
        > team_member_limit
    )

    environment_over_limit = (
        environment_limit is not None
        and active_environment_count
        > environment_limit
    )

    plan_over_limit = (
        team_over_limit
        or environment_over_limit
    )

    small_business_plan = get_plan_config(
        "small_business"
    )

    enterprise_plan = get_plan_config(
        "enterprise"
    )

    subscription_status = (
        current_organization.subscription_status
        or "inactive"
    )

    subscription_status_label = (
        subscription_status
        .replace("_", " ")
        .title()
    )

    billing_interval = None
    billing_interval_label = None
    billing_price_label = None

    stripe_price_id = (
        current_organization.stripe_price_id
    )

    if stripe_price_id in {
        STRIPE_SMALL_BUSINESS_MONTHLY_PRICE_ID,
        STRIPE_ENTERPRISE_MONTHLY_PRICE_ID,
    }:
        billing_interval = "monthly"
        billing_interval_label = "Monthly"

        if current_organization.plan == "small_business":
            billing_price_label = (
                f"${small_business_plan['monthly_price']}/month"
            )
        elif current_organization.plan == "enterprise":
            billing_price_label = (
                f"${enterprise_plan['monthly_price']}/month"
            )

    elif stripe_price_id in {
        STRIPE_SMALL_BUSINESS_ANNUAL_PRICE_ID,
        STRIPE_ENTERPRISE_ANNUAL_PRICE_ID,
    }:
        billing_interval = "annual"
        billing_interval_label = "Annual"

        if current_organization.plan == "small_business":
            billing_price_label = (
                f"${small_business_plan['annual_price']}/year"
            )
        elif current_organization.plan == "enterprise":
            billing_price_label = (
                f"${enterprise_plan['annual_price']}/year"
            )

    subscription_cancel_date_label = None
    
    if (
            current_organization.subscription_cancel_at_period_end
            and current_organization.subscription_current_period_end
        ):
            cancellation_date = (
                current_organization
                .subscription_current_period_end
            )
    
            subscription_cancel_date_label = (
                f"{cancellation_date.strftime('%B')} "
                f"{cancellation_date.day}, "
                f"{cancellation_date.year}"
            )

    return templates.TemplateResponse(
        request=request,
        name="subscription_settings.html",
        context={
            "active_page": "settings",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "plan_config": plan_config,
            "small_business_plan": (
                small_business_plan
            ),
            "enterprise_plan": (
                enterprise_plan
            ),
            "subscription_status": (
                subscription_status
            ),
            "subscription_status_label": (
                subscription_status_label
            ),
            "subscription_cancel_date_label": (
                subscription_cancel_date_label
            ),
            "billing_interval": (
                billing_interval
            ),
            "billing_interval_label": (
                billing_interval_label
            ),
            "billing_price_label": (
                billing_price_label
            ),
            "active_team_member_count": (
                active_team_member_count
            ),
            "active_environment_count": (
                active_environment_count
            ),
            "team_over_limit": (
                team_over_limit
            ),
            "environment_over_limit": (
                environment_over_limit
            ),
            "plan_over_limit": (
                plan_over_limit
            ),
        },
    )