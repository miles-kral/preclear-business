from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from sqlalchemy import or_

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
    GovernancePolicy,
    Membership,
    Organization,
    User,
)
from app.plans import (
    get_evidence_retention_cutoff,
    get_plan_config,
)


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)

def format_governance_time(
    value: datetime,
) -> str:
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
    "/governance",
    response_class=HTMLResponse,
)
def governance_page(
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

    governance_policy = (
        db.query(GovernancePolicy)
        .filter(
            GovernancePolicy.organization_id
            == current_organization.id
        )
        .first()
    )

    if governance_policy is None:

        governance_policy = GovernancePolicy(
            organization_id=(
                current_organization.id
            ),
            high_risk_review_required=True,
            caution_review_required=True,
            review_deadline_days=7,
            resolution_note_required=True,
        )

        db.add(governance_policy)
        db.commit()
        db.refresh(governance_policy)

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

    open_evidence_count = sum(
        1
        for analysis in analyses
        if analysis.review_status == "open"
    )

    reviewed_evidence_count = sum(
        1
        for analysis in analyses
        if analysis.review_status == "reviewed"
    )

    resolved_evidence_count = sum(
        1
        for analysis in analyses
        if analysis.review_status == "resolved"
    )

    high_risk_open_count = sum(
        1
        for analysis in analyses
        if (
            analysis.decision == "DO_NOT_OPEN"
            and analysis.review_status
            != "resolved"
        )
    )

    caution_open_count = sum(
        1
        for analysis in analyses
        if (
            analysis.decision == "USE_CAUTION"
            and analysis.review_status
            != "resolved"
        )
    )

    unresolved_analyses = [
        analysis
        for analysis in analyses
        if analysis.review_status
        != "resolved"
    ]

    review_deadline = (
        datetime.now(timezone.utc)
        - timedelta(
            days=governance_policy.review_deadline_days
        )
    )

    overdue_review_analyses = []

    for analysis in unresolved_analyses:

        created_at = analysis.created_at

        if created_at.tzinfo is None:
            created_at = created_at.replace(
                tzinfo=timezone.utc
            )

        if created_at < review_deadline:
            overdue_review_analyses.append(
                analysis
            )

    overdue_review_count = len(
        overdue_review_analyses
    )

    if high_risk_open_count > 0:

        governance_posture = {
            "key": "elevated",
            "label": "Elevated Risk",
            "description": (
                f"{high_risk_open_count} high-risk "
                "decision"
                + (
                    " requires"
                    if high_risk_open_count == 1
                    else "s require"
                )
                + " governance review."
            ),
        }

    elif caution_open_count > 0:

        governance_posture = {
            "key": "attention",
            "label": "Needs Attention",
            "description": (
                f"{caution_open_count} caution "
                "decision"
                + (
                    " requires"
                    if caution_open_count == 1
                    else "s require"
                )
                + " governance review."
            ),
        }

    else:

        governance_posture = {
            "key": "healthy",
            "label": "Healthy",
            "description": (
                "No unresolved elevated-risk "
                "evidence requires attention."
            ),
        }

    if unresolved_analyses:

        oldest_unresolved = min(
            unresolved_analyses,
            key=lambda analysis:
                analysis.created_at,
        )

        oldest_created_at = (
            oldest_unresolved.created_at
        )

        if oldest_created_at.tzinfo is None:
            oldest_created_at = (
                oldest_created_at.replace(
                    tzinfo=timezone.utc
                )
            )

        oldest_unresolved_days = max(
            0,
            (
                datetime.now(timezone.utc)
                - oldest_created_at
            ).days,
        )

    else:

        oldest_unresolved = None
        oldest_unresolved_days = None

    active_environment_count = (
        db.query(Environment)
        .filter(
            Environment.organization_id
            == current_organization.id,
            Environment.is_active.is_(True),
        )
        .count()
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

    recent_governance_events = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.organization_id
            == current_organization.id,
            or_(
                AuditEvent.event_type.like(
                    "evidence_%"
                ),
                AuditEvent.event_type.like(
                    "team_%"
                ),
                AuditEvent.event_type.like(
                    "environment_%"
                ),
            ),
        )
        .order_by(
            AuditEvent.created_at.desc()
        )
        .limit(8)
        .all()
    )

    recent_governance_activity = [
        {
            "event": event,
            "display_time": format_governance_time(
                event.created_at
            ),
        }
        for event in recent_governance_events
    ]

    retention_months = (
        plan_config[
            "evidence_retention_months"
        ]
    )

    advanced_governance = (
        plan_config[
            "advanced_governance"
        ]
    )

    return templates.TemplateResponse(
        request=request,
        name="governance.html",
        context={
            "active_page": "governance",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "plan_config": plan_config,
            "retention_months": retention_months,
            "advanced_governance": advanced_governance,
            "open_evidence_count": open_evidence_count,
            "reviewed_evidence_count": reviewed_evidence_count,
            "resolved_evidence_count": resolved_evidence_count,
            "high_risk_open_count": high_risk_open_count,
            "caution_open_count": caution_open_count,
            "active_environment_count": active_environment_count,
            "active_team_member_count": active_team_member_count,
            "recent_governance_events": recent_governance_events,
            "recent_governance_activity": recent_governance_activity,
            "governance_posture": governance_posture,
            "unresolved_evidence_count": len(
                unresolved_analyses
            ),
            "oldest_unresolved": oldest_unresolved,
            "oldest_unresolved_days": oldest_unresolved_days,
            "governance_policy": governance_policy,
            "overdue_review_count": overdue_review_count,
        },
    )