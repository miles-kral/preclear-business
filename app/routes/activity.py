from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import (
    can_view_organization,
    get_current_membership,
    get_current_organization,
    get_current_user,
)
from app.models import (
    AuditEvent,
    Membership,
    Organization,
    User,
)

from datetime import datetime, timedelta, timezone
from sqlalchemy import or_
from io import BytesIO

from app.services.pdf_service import (
    build_activity_log_pdf,
)

router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)

def build_activity_query(
    *,
    db: Session,
    organization_id: int,
    activity_type: str = "",
    user_id: str = "",
    date_range: str = "",
):
    query = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.organization_id
            == organization_id
        )
    )

    if activity_type:
        if activity_type == "security":
            query = query.filter(
                or_(
                    AuditEvent.event_type.like(
                        "%analysis%"
                    ),
                    AuditEvent.event_type.like(
                        "%evidence%"
                    ),
                )
            )

        elif activity_type == "team":
            query = query.filter(
                AuditEvent.event_type.like(
                    "team_%"
                )
            )

        elif activity_type == "environment":
            query = query.filter(
                AuditEvent.event_type.like(
                    "environment_%"
                )
            )

    if user_id:
        try:
            selected_user_id = int(
                user_id
            )

            query = query.filter(
                AuditEvent.user_id
                == selected_user_id
            )

        except ValueError:
            pass

    if date_range in {
        "7",
        "30",
        "90",
    }:
        cutoff = (
            datetime.now(
                timezone.utc
            )
            - timedelta(
                days=int(
                    date_range
                )
            )
        )

        query = query.filter(
            AuditEvent.created_at
            >= cutoff
        )

    return query


@router.get(
    "/activity",
    response_class=HTMLResponse,
)
def activity_page(
    request: Request,
    activity_type: str = "",
    user_id: str = "",
    date_range: str = "",
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

    if not can_view_organization(
        current_membership
    ):
        return RedirectResponse(
            url="/dashboard",
            status_code=303,
        )

    events = (
        build_activity_query(
            db=db,
            organization_id=(
                current_organization.id
            ),
            activity_type=activity_type,
            user_id=user_id,
            date_range=date_range,
        )
        .order_by(
            AuditEvent.created_at.desc()
        )
        .limit(250)
        .all()
    )


    if activity_type:

        if activity_type == "security":

            events_query = events_query.filter(
                or_(
                    AuditEvent.event_type.like(
                        "%analysis%"
                    ),
                    AuditEvent.event_type.like(
                        "%evidence%"
                    ),
                )
            )

        elif activity_type == "team":

            events_query = events_query.filter(
                AuditEvent.event_type.like(
                    "team_%"
                )
            )

        elif activity_type == "environment":

            events_query = events_query.filter(
                AuditEvent.event_type.like(
                    "environment_%"
                )
            )


    if user_id:

        try:
            selected_user_id = int(user_id)

            events_query = events_query.filter(
                AuditEvent.user_id
                == selected_user_id
            )

        except ValueError:
            pass


    if date_range in {
        "7",
        "30",
        "90",
    }:

        cutoff = (
            datetime.now(timezone.utc)
            - timedelta(
                days=int(date_range)
            )
        )

        events_query = events_query.filter(
            AuditEvent.created_at >= cutoff
        )

    organization_users = (
        db.query(User)
        .join(
            Membership,
            Membership.user_id == User.id,
        )
        .filter(
            Membership.organization_id
            == current_organization.id
        )
        .order_by(
            User.name.asc()
        )
        .all()
    )

    return templates.TemplateResponse(
        request=request,
        name="activity.html",
        context={
            "active_page": "activity",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "events": events,
            "organization_users": organization_users,
            "selected_activity_type": activity_type,
            "selected_user_id": user_id,
            "selected_date_range": date_range,    
        },
    )

@router.get(
    "/activity/export/pdf"
)
def download_activity_log_pdf(
    request: Request,
    activity_type: str = "",
    user_id: str = "",
    date_range: str = "",
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

    if not can_view_organization(
        current_membership
    ):
        return RedirectResponse(
            url="/dashboard",
            status_code=303,
        )

    events = (
        build_activity_query(
            db=db,
            organization_id=(
                current_organization.id
            ),
            activity_type=activity_type,
            user_id=user_id,
            date_range=date_range,
        )
        .order_by(
            AuditEvent.created_at.desc()
        )
        .limit(250)
        .all()
    )

    selected_user_name = ""

    if user_id:

        try:
            selected_user = db.get(
                User,
                int(user_id),
            )

            if selected_user:
                selected_user_name = (
                    selected_user.name
                )

        except ValueError:
            pass

    pdf_bytes = build_activity_log_pdf(
        events=events,
        organization=current_organization,
        activity_type=activity_type,
        user_name=selected_user_name,
        date_range=date_range,
    )

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                'attachment; '
                'filename="PreClear-Activity-Log.pdf"'
            )
        },
    )