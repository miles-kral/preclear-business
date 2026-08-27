from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import (
    can_review_evidence,
    get_current_membership,
    get_current_organization,
    get_current_user,
)
from app.models import (
    Analysis,
    AuditEvent,
    Membership,
    Organization,
    User,
    GovernancePolicy,
)

from app.plans import (
    get_evidence_retention_cutoff,
)

import json

from datetime import datetime, timezone
from io import BytesIO

from app.services.pdf_service import (
    build_decision_ledger_pdf,
    build_evidence_record_pdf,
)


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)

def format_ledger_time(
    value: datetime,
) -> str:
    now = datetime.now(
        timezone.utc
    )

    if value.tzinfo is None:
        value = value.replace(
            tzinfo=timezone.utc
        )

    value_local = value.astimezone()
    now_local = now.astimezone()

    value_date = value_local.date()
    today = now_local.date()

    date_text = (
        f"{value_local.strftime('%b')} "
        f"{value_local.day}"
    )

    time_text = value_local.strftime(
        "%I:%M %p"
    ).lstrip("0")

    if value_date == today:
        return (
            f"Today · {date_text} · "
            f"{time_text}"
        )

    yesterday = today.fromordinal(
        today.toordinal() - 1
    )

    if value_date == yesterday:
        return (
            f"Yesterday · {date_text} · "
            f"{time_text}"
        )

    return (
        f"{date_text} · "
        f"{time_text}"
    )

def format_evidence_time(
    value: datetime | None,
) -> str | None:
    if value is None:
        return None

    if value.tzinfo is None:
        value = value.replace(
            tzinfo=timezone.utc
        )

    value_local = value.astimezone()

    return (
        f"{value_local.strftime('%b')} "
        f"{value_local.day}, "
        f"{value_local.year} · "
        f"{value_local.strftime('%I:%M %p').lstrip('0')}"
    )


@router.get(
    "/ledger",
    response_class=HTMLResponse,
)
def decision_ledger(
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

    retention_cutoff = (
        get_evidence_retention_cutoff(
            current_organization.plan
        )
    )

    governance_policy = (
        db.query(GovernancePolicy)
        .filter(
            GovernancePolicy.organization_id
            == current_organization.id
        )
        .first()
    )

    review_deadline_days = (
        governance_policy.review_deadline_days
        if governance_policy is not None
        else 7
    )

    analyses_query = (
        db.query(Analysis)
        .filter(
            Analysis.organization_id
            == current_organization.id
        )
    )

    if retention_cutoff is not None:
        analyses_query = (
            analyses_query.filter(
                Analysis.created_at
                >= retention_cutoff
            )
        )

    analyses = (
        analyses_query
        .order_by(
            Analysis.created_at.desc()
        )
        .all()
    )

    ledger_records = [
        {
            "analysis": analysis,
            "display_time": format_ledger_time(
                analysis.created_at
            ),
        }
        for analysis in analyses
    ]

    return templates.TemplateResponse(
        request=request,
        name="ledger.html",
        context={
            "active_page": "ledger",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "analyses": analyses,
            "ledger_records": ledger_records,
            "review_deadline_days": review_deadline_days,
        },
    )

@router.get(
    "/ledger/export/pdf"
)
def download_decision_ledger_pdf(
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

    retention_cutoff = (
        get_evidence_retention_cutoff(
            current_organization.plan
        )
    )

    analyses_query = (
        db.query(Analysis)
        .filter(
            Analysis.organization_id
            == current_organization.id
        )
    )

    if retention_cutoff is not None:
        analyses_query = (
            analyses_query.filter(
                Analysis.created_at
                >= retention_cutoff
            )
        )

    analyses = (
        analyses_query
        .order_by(
            Analysis.created_at.desc()
        )
        .all()
    )

    pdf_bytes = build_decision_ledger_pdf(
        analyses=analyses,
        organization=current_organization,
    )

    filename = (
        "PreClear-Decision-Ledger.pdf"
    )

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            )
        },
    )

@router.get(
    "/ledger/{analysis_id}",
    response_class=HTMLResponse,
)
def evidence_record(
    analysis_id: int,
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

    retention_cutoff = (
        get_evidence_retention_cutoff(
            current_organization.plan
        )
    )

    analysis_query = (
        db.query(Analysis)
        .filter(
            Analysis.id == analysis_id,
            Analysis.organization_id
            == current_organization.id,
        )
    )

    if retention_cutoff is not None:
        analysis_query = (
            analysis_query.filter(
                Analysis.created_at
                >= retention_cutoff
            )
        )

    analysis = (
        analysis_query.first()
    )

    if analysis is None:
        return RedirectResponse(
            url="/ledger",
            status_code=303,
        )

    reviewed_by_user = None

    if analysis.reviewed_by_user_id:
        reviewed_by_user = db.get(
            User,
            analysis.reviewed_by_user_id,
        )

    reviewed_display_time = (
        format_evidence_time(
            analysis.reviewed_at
        )
    )

    try:
        reasons = json.loads(
            analysis.reasons
        )
    except (
        TypeError,
        json.JSONDecodeError,
    ):
        reasons = [
            analysis.reasons
        ]

    return templates.TemplateResponse(
        request=request,
        name="evidence_record.html",
        context={
            "active_page": "ledger",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "analysis": analysis,
            "reasons": reasons,
            "reviewed_by_user": reviewed_by_user,
            "reviewed_display_time": reviewed_display_time,
        },
    )

@router.get(
    "/ledger/{analysis_id}/pdf"
)
def download_evidence_record_pdf(
    analysis_id: int,
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

    retention_cutoff = (
        get_evidence_retention_cutoff(
            current_organization.plan
        )
    )

    analysis_query = (
        db.query(Analysis)
        .filter(
            Analysis.id == analysis_id,
            Analysis.organization_id
            == current_organization.id,
        )
    )

    if retention_cutoff is not None:
        analysis_query = (
            analysis_query.filter(
                Analysis.created_at
                >= retention_cutoff
            )
        )

    analysis = (
        analysis_query.first()
    )

    if analysis is None:
        return RedirectResponse(
            url="/ledger",
            status_code=303,
        )

    reviewed_by_user = None

    if analysis.reviewed_by_user_id:
        reviewed_by_user = db.get(
            User,
            analysis.reviewed_by_user_id,
        )

    pdf_bytes = build_evidence_record_pdf(
        analysis=analysis,
        organization=current_organization,
        reviewed_by_user=reviewed_by_user,
    )

    filename = (
        f"PreClear-Evidence-Record-"
        f"PC-{analysis.id}.pdf"
    )

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            )
        },
    )

@router.post(
    "/ledger/{analysis_id}/review"
)
def review_evidence_record(
    analysis_id: int,
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

    if not can_review_evidence(
        current_membership
    ):
        return RedirectResponse(
            url=f"/ledger/{analysis_id}",
            status_code=303,
        )

    retention_cutoff = (
        get_evidence_retention_cutoff(
            current_organization.plan
        )
    )

    analysis_query = (
        db.query(Analysis)
        .filter(
            Analysis.id == analysis_id,
            Analysis.organization_id
            == current_organization.id,
        )
    )

    if retention_cutoff is not None:
        analysis_query = (
            analysis_query.filter(
                Analysis.created_at
                >= retention_cutoff
            )
        )

    analysis = (
        analysis_query.first()
    )

    if analysis is None:
        return RedirectResponse(
            url="/ledger",
            status_code=303,
        )

    if analysis is None:
        return RedirectResponse(
            url="/ledger",
            status_code=303,
        )

    analysis.review_status = "reviewed"
    analysis.reviewed_at = datetime.now(
        timezone.utc
    )
    analysis.reviewed_by_user_id = (
        current_user.id
    )

    audit_event = AuditEvent(
        organization_id=current_organization.id,
        user_id=current_user.id,
        event_type="evidence_reviewed",
        description=(
            f"{current_user.name} reviewed "
            f"Evidence Record PC-{analysis.id}."
        ),
        metadata_json=json.dumps(
            {
                "analysis_id": analysis.id,
                "review_status": "reviewed",
            }
        ),
    )

    db.add(audit_event)
    db.commit()

    return RedirectResponse(
        url=f"/ledger/{analysis.id}",
        status_code=303,
    )

@router.post(
    "/ledger/{analysis_id}/resolve"
)
def resolve_evidence_record(
    analysis_id: int,
    request: Request,
    resolution_note: str = Form(""),
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

    if not can_review_evidence(
        current_membership
    ):
        return RedirectResponse(
            url=f"/ledger/{analysis_id}",
            status_code=303,
        )

    retention_cutoff = (
        get_evidence_retention_cutoff(
            current_organization.plan
        )
    )

    analysis_query = (
        db.query(Analysis)
        .filter(
            Analysis.id == analysis_id,
            Analysis.organization_id
            == current_organization.id,
        )
    )

    if retention_cutoff is not None:
        analysis_query = (
            analysis_query.filter(
                Analysis.created_at
                >= retention_cutoff
            )
        )

    analysis = (
        analysis_query.first()
    )

    if analysis is None:
        return RedirectResponse(
            url="/ledger",
            status_code=303,
        )

    if analysis is None:
        return RedirectResponse(
            url="/ledger",
            status_code=303,
        )

    analysis.review_status = "resolved"
    analysis.reviewed_at = datetime.now(
        timezone.utc
    )
    analysis.reviewed_by_user_id = (
        current_user.id
    )

    cleaned_note = (
        resolution_note.strip()
    )

    analysis.resolution_note = (
        cleaned_note or None
    )

    audit_event = AuditEvent(
        organization_id=current_organization.id,
        user_id=current_user.id,
        event_type="evidence_resolved",
        description=(
            f"{current_user.name} resolved "
            f"Evidence Record PC-{analysis.id}."
        ),
        metadata_json=json.dumps(
            {
                "analysis_id": analysis.id,
                "review_status": "resolved",
                "resolution_note": (
                    analysis.resolution_note
                ),
            }
        ),
    )

    db.add(audit_event)
    db.commit()

    return RedirectResponse(
        url=f"/ledger/{analysis.id}",
        status_code=303,
    )

