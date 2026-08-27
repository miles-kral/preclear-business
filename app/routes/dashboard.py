from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone

from app.database import get_db
from app.dependencies import (
    get_current_membership,
    get_current_organization,
    get_current_user,
)
from app.models import Analysis, AuditEvent, Environment, Membership, Organization, User
from app.plans import get_plan_config


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)


def format_dashboard_time(
    value: datetime,
) -> str:
    now = datetime.now(timezone.utc)

    if value.tzinfo is None:
        value = value.replace(
            tzinfo=timezone.utc
        )

    value_local = value.astimezone()

    now_local = now.astimezone()

    value_date = value_local.date()
    today = now_local.date()

    time_text = value_local.strftime(
        "%I:%M %p"
    ).lstrip("0")

    if value_date == today:
        return f"Today · {time_text}"

    if (
        value_date
        == today.fromordinal(
            today.toordinal() - 1
        )
    ):
        return f"Yesterday · {time_text}"

    return (
        f"{value_local.strftime('%b')} "
        f"{value_local.day} · "
        f"{time_text}"
    )

def calculate_risk_index(
    analyses: list[Analysis],
) -> int:
    if not analyses:
        return 0

    weights = {
        "LOOKS_SAFE": 0,
        "USE_CAUTION": 50,
        "DO_NOT_OPEN": 100,
    }

    total_risk = sum(
        weights.get(
            analysis.decision,
            0,
        )
        for analysis in analyses
    )

    return round(
        total_risk /
        len(analyses)
    )

@router.get(
    "/dashboard",
    response_class=HTMLResponse,
)
def dashboard_page(
    request: Request,
    current_user: User | None = Depends(
        get_current_user
    ),
    current_organization: Organization | None = Depends(
        get_current_organization
    ),
    current_membership: Membership | None = Depends(
        get_current_membership
    ),
    db: Session = Depends(get_db),
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

    analyses = (
        db.query(Analysis)
        .filter(
            Analysis.organization_id
            == current_organization.id
        )
        .order_by(
            Analysis.created_at.desc()
        )
        .all()
    )


    total_decisions = len(
    analyses
    )


    looks_safe_count = sum(
        1
        for analysis in analyses
        if analysis.decision == "LOOKS_SAFE"
    )


    use_caution_count = sum(
        1
        for analysis in analyses
        if analysis.decision == "USE_CAUTION"
    )


    do_not_open_count = sum(
        1
        for analysis in analyses
        if analysis.decision == "DO_NOT_OPEN"
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

    audit_event_count = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.organization_id
            == current_organization.id
        )
        .count()
    )

    recent_activity_events = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.organization_id
            == current_organization.id
        )
        .order_by(
            AuditEvent.created_at.desc()
        )
        .limit(3)
        .all()
    )

    recent_analyses = analyses[:5]

    recent_decisions = [
        {
            "analysis": analysis,
            "display_time": format_dashboard_time(
                analysis.created_at
            ),
        }
        for analysis in recent_analyses
    ]

    recent_team_activity = []

    for event in recent_activity_events:

        if event.user:
            user_name = event.user.name or event.user.email
        else:
            user_name = "System"

        initials = "".join(
            part[0].upper()
            for part in user_name.split()
            if part
        )[:2]

        if not initials:
            initials = "PC"

        recent_team_activity.append(
            {
                "user_name": user_name,
                "initials": initials,
                "description": event.description,
                "display_time": format_dashboard_time(
                    event.created_at
                ),
            }
        )

    now = datetime.now(
        timezone.utc
    )

    thirty_days_ago = (
        now - timedelta(days=30)
    )

    sixty_days_ago = (
        now - timedelta(days=60)
    )


    def normalized_created_at(
        analysis: Analysis,
    ) -> datetime:
        value = analysis.created_at

        if value.tzinfo is None:
            return value.replace(
                tzinfo=timezone.utc
            )

        return value


    current_period_analyses = [
        analysis
        for analysis in analyses
        if normalized_created_at(
            analysis
        ) >= thirty_days_ago
    ]

    current_period_total = len(
        current_period_analyses
    )

    current_period_safe_count = sum(
        1
        for analysis in current_period_analyses
        if analysis.decision == "LOOKS_SAFE"
    )

    current_period_caution_count = sum(
        1
        for analysis in current_period_analyses
        if analysis.decision == "USE_CAUTION"
    )

    current_period_danger_count = sum(
        1
        for analysis in current_period_analyses
        if analysis.decision == "DO_NOT_OPEN"
    )


    if current_period_total > 0:

        current_period_safe_pct = round(
            current_period_safe_count
            / current_period_total
            * 100
        )

        current_period_caution_pct = round(
            current_period_caution_count
            / current_period_total
            * 100
        )

        current_period_danger_pct = (
            100
            - current_period_safe_pct
            - current_period_caution_pct
        )

    else:

        current_period_safe_pct = 0
        current_period_caution_pct = 0
        current_period_danger_pct = 0


    current_period_attention_count = (
        current_period_caution_count
        + current_period_danger_count
    )


    previous_period_analyses = [
        analysis
        for analysis in analyses
        if (
            sixty_days_ago
            <= normalized_created_at(
                analysis
            )
            < thirty_days_ago
        )
    ]


    current_risk_index = (
        calculate_risk_index(
            current_period_analyses
        )
    )

    previous_risk_index = (
        calculate_risk_index(
            previous_period_analyses
        )
    )

    risk_change = (
        current_risk_index
        - previous_risk_index
    )

    risk_trend = []

    for bucket_index in range(6):

        bucket_start = (
            thirty_days_ago
            + timedelta(
                days=bucket_index * 5
            )
        )

        bucket_end = (
            bucket_start
            + timedelta(days=5)
        )

        bucket_analyses = [
            analysis
            for analysis in analyses
            if (
                bucket_start
                <= normalized_created_at(
                    analysis
                )
                < bucket_end
            )
        ]

        score = calculate_risk_index(
            bucket_analyses
        )

        local_end = (
            bucket_end.astimezone()
        )

        risk_trend.append(
            {
                "label": (
                    f"{local_end.strftime('%b')} "
                    f"{local_end.day}"
                ),
                "score": score,
            }
        )

    chart_width = 700
    chart_height = 220

    point_count = len(
        risk_trend
    )

    x_spacing = (
        chart_width /
        (point_count - 1)
        if point_count > 1
        else 0
    )

    chart_points = []

    for index, item in enumerate(
        risk_trend
    ):
        x = round(
            index * x_spacing,
            2,
        )

        y = round(
            chart_height
            - (
                item["score"] /
                100
            )
            * chart_height,
            2,
        )

        chart_points.append(
            {
                "x": x,
                "y": y,
                "label": item["label"],
                "score": item["score"],
            }
        )


    risk_trend_points = " ".join(
        f"{point['x']},{point['y']}"
        for point in chart_points
    )


    if chart_points:
        area_path = (
            f"M {chart_points[0]['x']} "
            f"{chart_points[0]['y']} "
        )

        area_path += " ".join(
            (
                f"L {point['x']} "
                f"{point['y']}"
            )
            for point in chart_points[1:]
        )

        area_path += (
            f" L {chart_width} "
            f"{chart_height}"
            f" L 0 {chart_height} Z"
        )

    else:
        area_path = ""

    recent_high_risk = [
        analysis
        for analysis in current_period_analyses
        if (
            analysis.decision == "DO_NOT_OPEN"
            and analysis.review_status
            != "resolved"
        )
    ]


    recent_caution = [
        analysis
        for analysis in current_period_analyses
        if (
            analysis.decision == "USE_CAUTION"
            and analysis.review_status
            != "resolved"
        )
    ]


    if recent_high_risk:

        protection_status = {
            "key": "elevated",
            "label": "Elevated Risk",
            "description": (
                f"{len(recent_high_risk)} high-risk "
                "decision"
                + (
                    " requires"
                    if len(recent_high_risk) == 1
                    else "s require"
                )
                + " review."
            ),
        }

    elif recent_caution:

        protection_status = {
            "key": "attention",
            "label": "Attention Needed",
            "description": (
                f"{len(recent_caution)} caution "
                "decision"
                + (
                    " requires"
                    if len(recent_caution) == 1
                    else "s require"
                )
                + " review."
            ),
        }

    else:

        protection_status = {
            "key": "protected",
            "label": "Protected",
            "description": (
                "No unresolved caution or high-risk "
                "decisions in the last 30 days."
            ),
        }

    plan_labels = {
        "small_business": "Small Business",
        "business": "Business",
        "enterprise": "Enterprise",
    }

    subscription_plan_label = plan_labels.get(
        current_organization.plan,
        current_organization.plan
        .replace("_", " ")
        .title(),
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

    plan_config = get_plan_config(
        current_organization.plan
    )

    subscription_plan_label = (
        plan_config["name"]
    )

    analysis_limit = (
        plan_config["analysis_limit"]
    )

    team_member_limit = (
        plan_config["team_member_limit"]
    )

    environment_limit = (
        plan_config["environment_limit"]
    )

    analysis_usage = len(
        current_period_analyses
    )

    if analysis_limit is not None:

        analysis_remaining = max(
            analysis_limit - analysis_usage,
         0,
        )

        analysis_usage_pct = min(
            round(
                analysis_usage
                / analysis_limit
                * 100
            ),
            100,
        )

    else:

        analysis_remaining = None
        analysis_usage_pct = 0

    team_member_usage = (
        active_team_member_count
    )

    environment_usage = (
        active_environment_count
    )


    if team_member_limit is not None:

        team_member_remaining = max(
            team_member_limit
            - team_member_usage,
            0,
        )

        team_member_usage_pct = min(
            round(
                team_member_usage
                / team_member_limit
                * 100
            ),
            100,
        )

    else:

        team_member_remaining = None
        team_member_usage_pct = 0


    if environment_limit is not None:

        environment_remaining = max(
            environment_limit
            - environment_usage,
            0,
        )

        environment_usage_pct = min(
            round(
                environment_usage
                / environment_limit
                * 100
            ),
            100,
        )

    else:

        environment_remaining = None
        environment_usage_pct = 0

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "active_page": "dashboard",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "total_decisions": total_decisions,
            "looks_safe_count": looks_safe_count,
            "use_caution_count": use_caution_count,
            "do_not_open_count": do_not_open_count,
            "current_period_safe_pct": current_period_safe_pct,
            "current_period_caution_pct": current_period_caution_pct,
            "current_period_danger_pct": current_period_danger_pct,
            "current_period_attention_count": current_period_attention_count,
            "open_evidence_count": open_evidence_count,
            "reviewed_evidence_count": reviewed_evidence_count,
            "resolved_evidence_count": resolved_evidence_count,
            "active_environment_count": active_environment_count,
            "active_team_member_count": active_team_member_count,
            "audit_event_count": audit_event_count,
            "recent_decisions": recent_decisions,
            "current_risk_index": current_risk_index,
            "previous_risk_index": previous_risk_index,
            "risk_change": risk_change,
            "risk_trend": risk_trend,
            "chart_points": chart_points,
            "risk_trend_points": risk_trend_points,
            "risk_trend_area_path": area_path,
            "protection_status": protection_status,
            "recent_team_activity": recent_team_activity,
            "subscription_plan_label": subscription_plan_label,
            "subscription_status": subscription_status,
            "subscription_status_label": subscription_status_label,
            "subscription_plan_label": subscription_plan_label,
            "analysis_limit": analysis_limit,
            "analysis_usage": analysis_usage,
            "analysis_remaining": analysis_remaining,
            "analysis_usage_pct": analysis_usage_pct,
            "team_member_limit": team_member_limit,
            "environment_limit": environment_limit,
            "team_member_usage": team_member_usage,
            "team_member_remaining": team_member_remaining,
            "team_member_usage_pct": team_member_usage_pct,
            "environment_usage": environment_usage,
            "environment_remaining": environment_remaining,
            "environment_usage_pct": environment_usage_pct,
        },
    )