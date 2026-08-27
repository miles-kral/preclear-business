from datetime import datetime, timedelta, timezone
from io import BytesIO
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import (
    get_current_membership,
    get_current_organization,
    get_current_user,
)
from app.models import (
    Analysis,
    AuditEvent,
    Environment,
    Membership,
    Organization,
    User,
)
from app.plans import (
    get_evidence_retention_cutoff,
    get_plan_config,
)
from app.services.pdf_service import (
    build_security_summary_pdf,
)


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)


@router.get(
    "/reports",
    response_class=HTMLResponse,
)
def reports_page(
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

    plan_config = get_plan_config(
        current_organization.plan
    )

    advanced_reporting = (
        plan_config["advanced_reporting"]
    )

    now = datetime.now(
        timezone.utc
    )

    thirty_days_ago = (
        now - timedelta(days=30)
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

    recent_analyses = [
        analysis
        for analysis in analyses
        if (
            analysis.created_at.replace(
                tzinfo=timezone.utc
            )
            if analysis.created_at.tzinfo is None
            else analysis.created_at
        ) >= thirty_days_ago
    ]

    total_analyses = len(
        recent_analyses
    )

    looks_safe_count = sum(
        1
        for analysis in recent_analyses
        if analysis.decision == "LOOKS_SAFE"
    )

    caution_count = sum(
        1
        for analysis in recent_analyses
        if analysis.decision == "USE_CAUTION"
    )

    danger_count = sum(
        1
        for analysis in recent_analyses
        if analysis.decision == "DO_NOT_OPEN"
    )

    open_evidence_count = sum(
        1
        for analysis in recent_analyses
        if analysis.review_status == "open"
    )

    reviewed_evidence_count = sum(
        1
        for analysis in recent_analyses
        if analysis.review_status == "reviewed"
    )

    resolved_evidence_count = sum(
        1
        for analysis in recent_analyses
        if analysis.review_status == "resolved"
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

    recent_activity_count = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.organization_id
            == current_organization.id,
            AuditEvent.created_at
            >= thirty_days_ago,
        )
        .count()
    )

    environment_activity = []

    environments = (
        db.query(Environment)
        .filter(
            Environment.organization_id
            == current_organization.id
        )
        .order_by(
            Environment.name.asc()
        )
        .all()
    )

    for environment in environments:

        environment_analysis_count = sum(
            1
            for analysis in recent_analyses
            if analysis.environment_id
            == environment.id
        )

        environment_attention_count = sum(
            1
            for analysis in recent_analyses
            if (
                analysis.environment_id
                == environment.id
                and analysis.decision
                in {
                    "USE_CAUTION",
                    "DO_NOT_OPEN",
                }
            )
        )

        environment_activity.append(
            {
                "environment": environment,
                "analysis_count": (
                    environment_analysis_count
                ),
                "attention_count": (
                    environment_attention_count
                ),
            }
        )

    environment_activity.sort(
        key=lambda item:
            item["analysis_count"],
        reverse=True,
    )

    if total_analyses > 0:

        safe_pct = round(
            looks_safe_count
            / total_analyses
            * 100
        )

        caution_pct = round(
            caution_count
            / total_analyses
            * 100
        )

        danger_pct = (
            100
            - safe_pct
            - caution_pct
        )

    else:

        safe_pct = 0
        caution_pct = 0
        danger_pct = 0

    return templates.TemplateResponse(
        request=request,
        name="reports.html",
        context={
            "active_page": "reports",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "plan_config": plan_config,
            "advanced_reporting": advanced_reporting,
            "total_analyses": total_analyses,
            "looks_safe_count": looks_safe_count,
            "caution_count": caution_count,
            "danger_count": danger_count,
            "safe_pct": safe_pct,
            "caution_pct": caution_pct,
            "danger_pct": danger_pct,
            "open_evidence_count": open_evidence_count,
            "reviewed_evidence_count": reviewed_evidence_count,
            "resolved_evidence_count": resolved_evidence_count,
            "active_environment_count": active_environment_count,
            "recent_activity_count": recent_activity_count,
            "environment_activity": environment_activity,
        },
    )

@router.get(
    "/reports/security-summary/pdf"
)
def download_security_summary_pdf(
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

    now = datetime.now(
        timezone.utc
    )

    thirty_days_ago = (
        now - timedelta(days=30)
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
            == current_organization.id,
            Analysis.created_at
            >= thirty_days_ago,
        )
    )

    if retention_cutoff is not None:
        analyses_query = (
            analyses_query.filter(
                Analysis.created_at
                >= retention_cutoff
            )
        )

    recent_analyses = (
        analyses_query
        .order_by(
            Analysis.created_at.desc()
        )
        .all()
    )

    total_analyses = len(
        recent_analyses
    )

    looks_safe_count = sum(
        1
        for analysis in recent_analyses
        if analysis.decision == "LOOKS_SAFE"
    )

    caution_count = sum(
        1
        for analysis in recent_analyses
        if analysis.decision == "USE_CAUTION"
    )

    danger_count = sum(
        1
        for analysis in recent_analyses
        if analysis.decision == "DO_NOT_OPEN"
    )

    open_evidence_count = sum(
        1
        for analysis in recent_analyses
        if analysis.review_status == "open"
    )

    reviewed_evidence_count = sum(
        1
        for analysis in recent_analyses
        if analysis.review_status == "reviewed"
    )

    resolved_evidence_count = sum(
        1
        for analysis in recent_analyses
        if analysis.review_status == "resolved"
    )

    if total_analyses > 0:

        safe_pct = round(
            looks_safe_count
            / total_analyses
            * 100
        )

        caution_pct = round(
            caution_count
            / total_analyses
            * 100
        )

        danger_pct = (
            100
            - safe_pct
            - caution_pct
        )

    else:

        safe_pct = 0
        caution_pct = 0
        danger_pct = 0

    recent_activity_count = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.organization_id
            == current_organization.id,
            AuditEvent.created_at
            >= thirty_days_ago,
        )
        .count()
    )

    environments = (
        db.query(Environment)
        .filter(
            Environment.organization_id
            == current_organization.id
        )
        .order_by(
            Environment.name.asc()
        )
        .all()
    )

    environment_activity = []

    for environment in environments:

        analysis_count = sum(
            1
            for analysis in recent_analyses
            if analysis.environment_id
            == environment.id
        )

        attention_count = sum(
            1
            for analysis in recent_analyses
            if (
                analysis.environment_id
                == environment.id
                and analysis.decision
                in {
                    "USE_CAUTION",
                    "DO_NOT_OPEN",
                }
            )
        )

        environment_activity.append(
            {
                "environment": environment,
                "analysis_count": analysis_count,
                "attention_count": attention_count,
            }
        )

    environment_activity.sort(
        key=lambda item:
            item["analysis_count"],
        reverse=True,
    )

    pdf_bytes = (
        build_security_summary_pdf(
            organization=current_organization,
            total_analyses=total_analyses,
            looks_safe_count=looks_safe_count,
            caution_count=caution_count,
            danger_count=danger_count,
            safe_pct=safe_pct,
            caution_pct=caution_pct,
            danger_pct=danger_pct,
            open_evidence_count=(
                open_evidence_count
            ),
            reviewed_evidence_count=(
                reviewed_evidence_count
            ),
            resolved_evidence_count=(
                resolved_evidence_count
            ),
            recent_activity_count=(
                recent_activity_count
            ),
            environment_activity=(
                environment_activity
            ),
        )
    )

    filename = (
        "PreClear-30-Day-Security-Summary.pdf"
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