from fastapi import (
    APIRouter,
    Depends,
    Form,
    Request,
)
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
    is_platform_admin,
)
from app.models import (
    EvaluationInvitation,
    Membership,
    Organization,
    User,
)

from datetime import datetime, timedelta, timezone
import secrets

from sqlalchemy import select

import re

from app.auth import (
    hash_password,
    verify_password,
)


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)

def slugify(
    value: str,
) -> str:
    value = value.strip().lower()

    value = re.sub(
        r"[^a-z0-9]+",
        "-",
        value,
    )

    return value.strip("-")


def make_evaluation_slug(
    db: Session,
    organization_name: str,
) -> str:
    base_slug = slugify(
        organization_name
    )

    if not base_slug:
        base_slug = "organization"

    slug = base_slug
    counter = 2

    while (
        db.scalar(
            select(Organization).where(
                Organization.slug == slug
            )
        )
        is not None
    ):
        slug = (
            f"{base_slug}-{counter}"
        )
        counter += 1

    return slug


@router.get(
    "/admin/evaluations",
    response_class=HTMLResponse,
)
def evaluations_admin_page(
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
    if current_user is None:
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    if not is_platform_admin(
        current_user
    ):
        return RedirectResponse(
            url="/dashboard",
            status_code=303,
        )

    evaluations = (
        db.execute(
            select(EvaluationInvitation)
            .order_by(
                EvaluationInvitation.created_at.desc()
            )
        )
        .scalars()
        .all()
    )

    now = datetime.now(
        timezone.utc
    )

    for evaluation in evaluations:

        display_status = (
            evaluation.status
        )

        if evaluation.status == "pending":
            display_status = "Pending"

        elif evaluation.status == "revoked":
            display_status = "Revoked"

        elif evaluation.status == "converted":
            display_status = "Converted"

        elif evaluation.organization_id:

            expiration = (
                evaluation.evaluation_expires_at
            )

            if expiration is not None:

                if expiration.tzinfo is None:
                    expiration = (
                        expiration.replace(
                            tzinfo=timezone.utc
                        )
                    )

                if expiration <= now:
                    display_status = "Expired"
                else:
                    display_status = "Active"

            else:
                display_status = "Active"

        evaluation.display_status = (
            display_status
        )

    summary = {
        "pending": 0,
        "active": 0,
        "expired": 0,
        "revoked": 0,
        "converted": 0,
    }

    for evaluation in evaluations:
        status_key = (
            evaluation.display_status
            .strip()
            .lower()
        )

        if status_key in summary:
            summary[status_key] += 1

    created_evaluation = request.session.pop(
        "evaluation_created",
        None,
    )

    return templates.TemplateResponse(
        request=request,
        name="admin_evaluations.html",
        context={
            "active_page": "admin_evaluations",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "evaluations": evaluations,
            "created_evaluation": created_evaluation,
            "summary": summary,
        },
    )

@router.post(
    "/admin/evaluations",
)
def create_evaluation(
    request: Request,
    prospect_name: str = Form(...),
    company_name: str = Form(...),
    email: str = Form(...),
    access_days: int = Form(7),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(
        get_current_user
    ),
):
    if current_user is None:
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    if not is_platform_admin(
        current_user
    ):
        return RedirectResponse(
            url="/dashboard",
            status_code=303,
        )

    allowed_days = {
        3,
        7,
        14,
        30,
    }

    if access_days not in allowed_days:
        access_days = 7

    prospect_name = prospect_name.strip()
    company_name = company_name.strip()
    email = email.strip().lower()

    if (
        not prospect_name
        or not company_name
        or not email
    ):
        return RedirectResponse(
            url="/admin/evaluations",
            status_code=303,
        )

    token = secrets.token_urlsafe(32)

    invitation = EvaluationInvitation(
        created_by_user_id=current_user.id,
        prospect_name=prospect_name,
        company_name=company_name,
        email=email,
        token=token,
        status="pending",
        access_days=access_days,
        expires_at=(
            datetime.now(timezone.utc)
            + timedelta(days=7)
        ),
    )

    db.add(invitation)
    db.commit()
    db.refresh(invitation)

    request.session["evaluation_created"] = {
        "id": invitation.id,
        "token": invitation.token,
    }

    return RedirectResponse(
        url="/admin/evaluations",
        status_code=303,
    )

@router.get(
    "/evaluation/invite/{token}",
    response_class=HTMLResponse,
)
def evaluation_invitation_page(
    token: str,
    request: Request,
    db: Session = Depends(get_db),
):
    invitation = db.scalar(
        select(EvaluationInvitation).where(
            EvaluationInvitation.token == token,
            EvaluationInvitation.status == "pending",
        )
    )

    if invitation is None:
        return templates.TemplateResponse(
            request=request,
            name="evaluation_accept.html",
            context={
                "invitation": None,
                "existing_user": None,
                "error": (
                    "This evaluation invitation is invalid "
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
            name="evaluation_accept.html",
            context={
                "invitation": None,
                "existing_user": None,
                "error": (
                    "This evaluation invitation has expired."
                ),
                "robots_content": "noindex, nofollow",
            },
            status_code=400,
        )

    existing_user = db.scalar(
        select(User).where(
            User.email == invitation.email
        )
    )

    return templates.TemplateResponse(
        request=request,
        name="evaluation_accept.html",
        context={
            "invitation": invitation,
            "existing_user": existing_user,
            "error": None,
            "robots_content": "noindex, nofollow",
        },
    )

@router.post(
    "/evaluation/invite/{token}",
    response_class=HTMLResponse,
)
def accept_evaluation(
    token: str,
    request: Request,
    name: str = Form(""),
    password: str = Form(...),
    password_confirm: str = Form(""),
    db: Session = Depends(get_db),
):
    invitation = db.scalar(
        select(EvaluationInvitation).where(
            EvaluationInvitation.token == token,
            EvaluationInvitation.status == "pending",
        )
    )

    if invitation is None:
        return templates.TemplateResponse(
            request=request,
            name="evaluation_accept.html",
            context={
                "invitation": None,
                "existing_user": None,
                "error": (
                    "This evaluation invitation is invalid "
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
            name="evaluation_accept.html",
            context={
                "invitation": None,
                "existing_user": None,
                "error": (
                    "This evaluation invitation has expired."
                ),
                "robots_content": "noindex, nofollow",
            },
            status_code=400,
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
                name="evaluation_accept.html",
                context={
                    "invitation": invitation,
                    "existing_user": existing_user,
                    "error": (
                        "Invalid password."
                    ),
                    "robots_content": "noindex, nofollow",
                },
                status_code=400,
            )

        user = existing_user

    else:

        name = name.strip()

        if not name:
            return templates.TemplateResponse(
                request=request,
                name="evaluation_accept.html",
                context={
                    "invitation": invitation,
                    "existing_user": None,
                    "error": (
                        "Please enter your name."
                    ),
                    "robots_content": "noindex, nofollow",
                },
                status_code=400,
            )

        if password != password_confirm:
            return templates.TemplateResponse(
                request=request,
                name="evaluation_accept.html",
                context={
                    "invitation": invitation,
                    "existing_user": None,
                    "error": (
                        "The passwords do not match."
                    ),
                    "robots_content": "noindex, nofollow",
                },
                status_code=400,
            )

        if len(password) < 10:
            return templates.TemplateResponse(
                request=request,
                name="evaluation_accept.html",
                context={
                    "invitation": invitation,
                    "existing_user": None,
                    "error": (
                        "Your password must be at least "
                        "10 characters long."
                    ),
                    "robots_content": "noindex, nofollow",
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

    now = datetime.now(
        timezone.utc
    )

    evaluation_expires_at = (
        now
        + timedelta(
            days=invitation.access_days
        )
    )

    organization = Organization(
        name=invitation.company_name,
        slug=make_evaluation_slug(
            db,
            invitation.company_name,
        ),
        plan="small_business",
        subscription_status="evaluation",
        is_active=True,
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

    invitation.organization_id = (
        organization.id
    )
    invitation.status = "accepted"
    invitation.accepted_at = now
    invitation.evaluation_expires_at = (
        evaluation_expires_at
    )

    db.commit()

    request.session.clear()

    request.session["user_id"] = (
        user.id
    )

    request.session["organization_id"] = (
        organization.id
    )

    return RedirectResponse(
        url="/dashboard",
        status_code=303,
    )

@router.get(
    "/evaluation/expired",
    response_class=HTMLResponse,
)
def evaluation_expired_page(
    request: Request,
):
    return templates.TemplateResponse(
        request=request,
        name="evaluation_expired.html",
        context={
            "robots_content": (
                "noindex, nofollow"
            ),
        },
    )

@router.post(
    "/admin/evaluations/{evaluation_id}/extend",
)
def extend_evaluation(
    evaluation_id: int,
    request: Request,
    days: int = Form(7),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(
        get_current_user
    ),
):
    if current_user is None:
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    if not is_platform_admin(
        current_user
    ):
        return RedirectResponse(
            url="/dashboard",
            status_code=303,
        )

    evaluation = db.get(
        EvaluationInvitation,
        evaluation_id,
    )

    if evaluation is None:
        return RedirectResponse(
            url="/admin/evaluations",
            status_code=303,
        )

    allowed_days = {
        3,
        7,
        14,
        30,
    }

    if days not in allowed_days:
        days = 7

    now = datetime.now(
        timezone.utc
    )

    current_expiration = (
        evaluation.evaluation_expires_at
    )

    if current_expiration is not None:

        if current_expiration.tzinfo is None:
            current_expiration = (
                current_expiration.replace(
                    tzinfo=timezone.utc
                )
            )

    if (
        current_expiration is None
        or current_expiration < now
    ):
        starting_point = now
    else:
        starting_point = (
            current_expiration
        )

    evaluation.evaluation_expires_at = (
        starting_point
        + timedelta(days=days)
    )

    if evaluation.organization_id:
        evaluation.status = "accepted"
        evaluation.revoked_at = None

    db.commit()

    return RedirectResponse(
        url="/admin/evaluations",
        status_code=303,
    )

@router.post(
    "/admin/evaluations/{evaluation_id}/revoke",
)
def revoke_evaluation(
    evaluation_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(
        get_current_user
    ),
):
    if current_user is None:
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    if not is_platform_admin(
        current_user
    ):
        return RedirectResponse(
            url="/dashboard",
            status_code=303,
        )

    evaluation = db.get(
        EvaluationInvitation,
        evaluation_id,
    )

    if evaluation is None:
        return RedirectResponse(
            url="/admin/evaluations",
            status_code=303,
        )

    evaluation.status = "revoked"
    evaluation.revoked_at = (
        datetime.now(timezone.utc)
    )

    db.commit()

    return RedirectResponse(
        url="/admin/evaluations",
        status_code=303,
    )

@router.get(
    "/admin/evaluations/{evaluation_id}",
    response_class=HTMLResponse,
)
def evaluation_details_page(
    evaluation_id: int,
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
    if current_user is None:
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    if not is_platform_admin(
        current_user
    ):
        return RedirectResponse(
            url="/dashboard",
            status_code=303,
        )

    evaluation = db.get(
        EvaluationInvitation,
        evaluation_id,
    )

    if evaluation is None:
        return RedirectResponse(
            url="/admin/evaluations",
            status_code=303,
        )

    organization = None

    if evaluation.organization_id:
        organization = db.get(
            Organization,
            evaluation.organization_id,
        )

    now = datetime.now(
        timezone.utc
    )

    display_status = evaluation.status

    if evaluation.status == "pending":
        display_status = "Pending"

    elif evaluation.status == "revoked":
        display_status = "Revoked"

    elif evaluation.status == "converted":
        display_status = "Converted"

    elif evaluation.organization_id:

        expiration = (
            evaluation.evaluation_expires_at
        )

        if expiration is not None:

            if expiration.tzinfo is None:
                expiration = (
                    expiration.replace(
                        tzinfo=timezone.utc
                    )
                )

            if expiration <= now:
                display_status = "Expired"
            else:
                display_status = "Active"

        else:
            display_status = "Active"

    return templates.TemplateResponse(
        request=request,
        name="admin_evaluation_details.html",
        context={
            "active_page": "admin_evaluations",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "evaluation": evaluation,
            "organization": organization,
            "display_status": display_status,
        },
    )