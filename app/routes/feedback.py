"""
Feedback: signed-in users tell PreClear about their experience, ideas for
improvements, or bugs. Platform admins review it at /admin/feedback.
"""
import json
import logging
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
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
    AuditEvent,
    Feedback,
    Membership,
    Organization,
    User,
)
from app.services.email_service import send_feedback_email


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)

logger = logging.getLogger("uvicorn.error")

CATEGORIES = {
    "experience": "My experience",
    "improvement": "An improvement idea",
    "bug": "Something isn't working",
    "other": "Something else",
}

STATUSES = {
    "new": "New",
    "reviewed": "Reviewed",
    "planned": "Planned",
    "resolved": "Resolved",
}

MIN_MESSAGE = 10
MAX_MESSAGE = 5000

# Enough for genuine use, low enough to stop a runaway script.
MAX_PER_DAY = 10

# Across everyone in one organization, so a single compromised account,
# or several, can't flood the support inbox.
MAX_PER_ORGANIZATION_PER_DAY = 30


def _safe_page(value: str | None) -> str | None:
    """Keeps only a path within PreClear, such as /ledger or /analysis/12."""
    value = (value or "").strip()

    if not value.startswith("/") or value.startswith("//"):
        return None

    value = value.split("?", 1)[0].split("#", 1)[0]

    if not re.fullmatch(r"/[A-Za-z0-9/_\-.]*", value):
        return None

    return value[:300]


def _signed_in(user, organization, membership) -> bool:
    return (
        user is not None
        and organization is not None
        and membership is not None
    )


@router.get(
    "/feedback",
    response_class=HTMLResponse,
)
def feedback_page(
    request: Request,
    current_user: User | None = Depends(get_current_user),
    current_organization: Organization | None = Depends(get_current_organization),
    current_membership: Membership | None = Depends(get_current_membership),
):
    if not _signed_in(current_user, current_organization, current_membership):
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="feedback.html",
        context={
            "active_page": "feedback",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "categories": CATEGORIES,
            "from_page": _safe_page(request.query_params.get("from")),
            "chosen_category": (
                request.query_params.get("type")
                if request.query_params.get("type") in CATEGORIES
                else "experience"
            ),
            "sent": request.query_params.get("sent") == "1",
            "is_admin": is_platform_admin(current_user),
            "error": request.session.pop("feedback_error", None),
            "max_message": MAX_MESSAGE,
        },
    )


@router.post("/feedback")
def submit_feedback(
    request: Request,
    category: str = Form(...),
    message: str = Form(""),
    rating: str = Form(""),
    page: str = Form(""),
    may_contact: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
    current_organization: Organization | None = Depends(get_current_organization),
    current_membership: Membership | None = Depends(get_current_membership),
):
    if not _signed_in(current_user, current_organization, current_membership):
        return RedirectResponse(url="/login", status_code=303)

    def fail(text: str):
        request.session["feedback_error"] = text
        return RedirectResponse(url="/feedback", status_code=303)

    if category not in CATEGORIES:
        return fail("Choose what your feedback is about.")

    message = message.strip()

    if len(message) < MIN_MESSAGE:
        return fail("Tell us a little more, at least a sentence.")

    if len(message) > MAX_MESSAGE:
        return fail(f"Feedback can be up to {MAX_MESSAGE:,} characters.")

    try:
        score = int(rating) if rating else None
    except ValueError:
        score = None

    if score is not None and not 1 <= score <= 5:
        score = None

    since = datetime.now(timezone.utc) - timedelta(days=1)
    recent = (
        db.query(Feedback)
        .filter(
            Feedback.user_id == current_user.id,
            Feedback.created_at >= since,
        )
        .count()
    )

    if recent >= MAX_PER_DAY:
        return fail(
            "You've sent a lot of feedback today. Thank you! Please try "
            "again tomorrow, or use the Support page for anything urgent."
        )

    organization_recent = (
        db.query(Feedback)
        .filter(
            Feedback.organization_id == current_organization.id,
            Feedback.created_at >= since,
        )
        .count()
    )

    if organization_recent >= MAX_PER_ORGANIZATION_PER_DAY:
        logger.warning(
            "Feedback limit reached for organization %s (%s today).",
            current_organization.id,
            organization_recent,
        )
        return fail(
            "Your organization has sent a lot of feedback today. Thank "
            "you! Please try again tomorrow, or use the Support page for "
            "anything urgent."
        )

    entry = Feedback(
        organization_id=current_organization.id,
        user_id=current_user.id,
        category=category,
        rating=score,
        message=message,
        page=_safe_page(page),
        browser=(request.headers.get("user-agent") or "")[:300] or None,
        may_contact=bool(may_contact),
    )

    db.add(entry)
    db.flush()

    db.add(
        AuditEvent(
            organization_id=current_organization.id,
            user_id=current_user.id,
            event_type="feedback_submitted",
            description=(
                f"{current_user.name} sent feedback "
                f"({CATEGORIES[category].lower()})."
            ),
            metadata_json=json.dumps(
                {"feedback_id": entry.id, "category": category}
            ),
        )
    )

    db.commit()

    # Notifying the team is best effort; the feedback is already saved.
    try:
        send_feedback_email(
            organization_name=current_organization.name,
            user_name=current_user.name,
            user_email=current_user.email,
            category_label=CATEGORIES[category],
            rating=score,
            message=message,
            page=entry.page,
            may_contact=entry.may_contact,
        )
    except Exception as error:  # email service down or not configured
        logger.warning("Feedback %s saved, but the email failed: %s", entry.id, error)

    return RedirectResponse(url="/feedback?sent=1", status_code=303)


@router.get(
    "/admin/feedback",
    response_class=HTMLResponse,
)
def feedback_admin_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
    current_organization: Organization | None = Depends(get_current_organization),
    current_membership: Membership | None = Depends(get_current_membership),
):
    if not is_platform_admin(current_user):
        return RedirectResponse(url="/dashboard", status_code=303)

    category = request.query_params.get("type", "")
    status = request.query_params.get("status", "")

    query = db.query(Feedback)

    if category in CATEGORIES:
        query = query.filter(Feedback.category == category)

    if status in STATUSES:
        query = query.filter(Feedback.status == status)

    entries = query.order_by(Feedback.created_at.desc()).limit(300).all()

    users = {
        user.id: user
        for user in db.query(User).filter(
            User.id.in_({e.user_id for e in entries if e.user_id})
        )
    }
    organizations = {
        org.id: org
        for org in db.query(Organization).filter(
            Organization.id.in_({e.organization_id for e in entries if e.organization_id})
        )
    }

    ratings = [e.rating for e in entries if e.rating]

    return templates.TemplateResponse(
        request=request,
        name="admin_feedback.html",
        context={
            "active_page": "feedback",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "entries": entries,
            "users": users,
            "organizations": organizations,
            "categories": CATEGORIES,
            "statuses": STATUSES,
            "chosen_type": category,
            "chosen_status": status,
            "average_rating": (
                round(sum(ratings) / len(ratings), 1) if ratings else None
            ),
        },
    )


@router.post("/admin/feedback/{feedback_id}/status")
def update_feedback_status(
    feedback_id: int,
    status: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
):
    if not is_platform_admin(current_user):
        return RedirectResponse(url="/dashboard", status_code=303)

    entry = db.get(Feedback, feedback_id)

    if entry is not None and status in STATUSES:
        entry.status = status
        db.commit()

    return RedirectResponse(url="/admin/feedback", status_code=303)
