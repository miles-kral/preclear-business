import json
from datetime import datetime, timedelta, timezone

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Request,
    UploadFile,
)
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import (
    can_analyze,
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
from app.services.analysis_service import (
    MAX_UPLOAD_BYTES,
    analyze_file,
)
from app.services.link_analysis import (
    MAX_LINK_LENGTH,
    InvalidLinkError,
    analyze_link,
)
from app.plans import get_plan_config, has_subscription_access


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)


# Must match the <option> values in analyze.html.
ALLOWED_SOURCES = {
    "email",
    "vendor",
    "customer",
    "website",
    "shared",
    "other",
}

ALLOWED_LINK_SOURCES = {
    "email",
    "text_message",
    "chat",
    "website",
    "document",
    "other",
}

UPLOAD_READ_CHUNK_BYTES = 1024 * 1024

MAX_UPLOAD_MB = MAX_UPLOAD_BYTES // (1024 * 1024)

# Only these fixed messages can be shown, so nothing from the URL is
# ever displayed back to the user.
UPLOAD_ERROR_MESSAGES = {
    "file_too_large": (
        f"That file is larger than {MAX_UPLOAD_MB} MB, the most "
        "PreClear can analyze. Verify it with the sender before "
        "opening it."
    ),
    "empty_file": (
        "That file is empty, so there was nothing to analyze."
    ),
    "invalid_request": (
        "The analysis request was incomplete. Choose an "
        "environment and source, then try again."
    ),
}

LINK_ERROR_MESSAGES = {
    "invalid_link": (
        "That doesn't look like a link PreClear can check. Paste the "
        "full address, for example https://example.com/page."
    ),
    "link_too_long": (
        "That link is too long for PreClear to check. Verify it with "
        "the sender before visiting it."
    ),
    "invalid_link_request": (
        "The link check was incomplete. Choose an environment and "
        "link source, then try again."
    ),
}


async def read_upload_limited(
    file: UploadFile,
    max_bytes: int,
) -> bytes | None:
    """
    Reads an upload in chunks. Returns None as soon as the file passes
    max_bytes, so an oversized file is never held in memory in full.
    """
    chunks: list[bytes] = []
    total = 0

    while True:
        chunk = await file.read(
            UPLOAD_READ_CHUNK_BYTES
        )

        if not chunk:
            break

        total += len(chunk)

        if total > max_bytes:
            return None

        chunks.append(chunk)

    return b"".join(chunks)

def get_analysis_usage_status(
    db: Session,
    organization: Organization,
) -> dict:

    plan_config = get_plan_config(
        organization.plan
    )

    analysis_limit = (
        plan_config["analysis_limit"]
    )

    thirty_days_ago = (
        datetime.now(timezone.utc)
        - timedelta(days=30)
    )

    analysis_usage = (
        db.query(Analysis)
        .filter(
            Analysis.organization_id
            == organization.id,
            Analysis.created_at
            >= thirty_days_ago,
        )
        .count()
    )

    if analysis_limit is None:

        return {
            "status": "unlimited",
            "usage": analysis_usage,
            "limit": None,
            "remaining": None,
            "usage_pct": 0,
        }

    remaining = max(
        analysis_limit - analysis_usage,
        0,
    )

    usage_pct = min(
        round(
            analysis_usage
            / analysis_limit
            * 100
        ),
        100,
    )

    if analysis_usage >= analysis_limit:

        status = "over_limit"

    elif usage_pct >= 80:

        status = "approaching_limit"

    else:

        status = "normal"

    return {
        "status": status,
        "usage": analysis_usage,
        "limit": analysis_limit,
        "remaining": remaining,
        "usage_pct": usage_pct,
    }


@router.get(
    "/analyze",
    response_class=HTMLResponse,
)
def analyze_page(
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

    if not can_analyze(
        current_membership
    ):
        return RedirectResponse(
            url="/dashboard",
            status_code=303,
        )

    if not has_subscription_access(
        current_organization.subscription_status
    ):
        return RedirectResponse(
            url="/settings/subscription",
            status_code=303,
        )

    analysis_usage_status = (
        get_analysis_usage_status(
            db,
            current_organization,
        )
    )
    
    environments = (
        db.query(Environment)
        .filter(
            Environment.organization_id
            == current_organization.id,
            Environment.is_active.is_(True),
        )
        .order_by(
            Environment.name.asc()
        )
        .all()
    )

    return templates.TemplateResponse(
        request=request,
        name="analyze.html",
        context={
            "active_page": "analyze",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "environments": environments,
            "analysis_usage_status": analysis_usage_status,
            "upload_error": UPLOAD_ERROR_MESSAGES.get(
                request.query_params.get("error", "")
            ),
            "link_error": LINK_ERROR_MESSAGES.get(
                request.query_params.get("error", "")
            ),
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "max_upload_mb": MAX_UPLOAD_MB,
        },
    )


def _access_redirect(
    current_user: User | None,
    current_organization: Organization | None,
    current_membership: Membership | None,
) -> RedirectResponse | None:
    """Returns a redirect if the user may not run analyses, else None."""
    if (
        current_user is None
        or current_organization is None
        or current_membership is None
    ):
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    if not can_analyze(
        current_membership
    ):
        return RedirectResponse(
            url="/dashboard",
            status_code=303,
        )

    if not has_subscription_access(
        current_organization.subscription_status
    ):
        return RedirectResponse(
            url="/settings/subscription",
            status_code=303,
        )

    return None


def _get_environment(
    db: Session,
    organization: Organization,
    environment_id: int,
) -> Environment | None:
    return db.scalar(
        select(Environment).where(
            Environment.id == environment_id,
            Environment.organization_id
            == organization.id,
            Environment.is_active.is_(True),
        )
    )


def _record_analysis(
    db: Session,
    *,
    organization: Organization,
    user: User,
    environment: Environment,
    source: str,
    result: dict,
    analysis_type: str,
    usage_status: dict,
    event_type: str,
    description: str,
) -> Analysis:
    """Saves an analysis and its audit event."""
    vt_result = result.get(
        "virustotal",
        {},
    )

    analysis = Analysis(
        organization_id=organization.id,
        user_id=user.id,
        environment_id=environment.id,
        analysis_type=analysis_type,
        source=source,
        filename=result["filename"],
        extension=result["extension"],
        mime_type=result["mime_type"],
        file_size=result["file_size"],
        sha256=result["sha256"],
        target=result.get("target"),
        details_json=result.get("details_json"),
        virustotal_found=(
            vt_result.get("found")
            if vt_result.get("available")
            else None
        ),
        virustotal_malicious=(
            vt_result.get("malicious")
        ),
        virustotal_suspicious=(
            vt_result.get("suspicious")
        ),
        virustotal_undetected=(
            vt_result.get("undetected")
        ),
        virustotal_harmless=(
            vt_result.get("harmless")
        ),
        virustotal_error=(
            vt_result.get("error")
        ),
        risk_level=result["risk_level"],
        decision=result["decision"],
        explanation=result["explanation"],
        reasons=json.dumps(
            result["reasons"]
        ),
    )

    db.add(analysis)
    db.flush()

    audit_event = AuditEvent(
        organization_id=organization.id,
        user_id=user.id,
        event_type=event_type,
        description=description,
        metadata_json=json.dumps(
            {
                "analysis_id": analysis.id,
                "analysis_type": analysis_type,
                "decision": result["decision"],
                "risk_level": result["risk_level"],
                "environment": environment.name,
                "source": source,
                "usage_status": (
                    usage_status["status"]
                ),
                "usage_before_analysis": (
                    usage_status["usage"]
                ),
                "analysis_limit": (
                    usage_status["limit"]
                ),
            }
        ),
    )

    db.add(audit_event)
    db.commit()

    return analysis


@router.post("/analyze")
async def analyze_file_route(
    request: Request,
    file: UploadFile = File(...),
    environment: int = Form(...),
    source: str = Form(...),
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
    redirect = _access_redirect(
        current_user,
        current_organization,
        current_membership,
    )

    if redirect is not None:
        return redirect

    # Validate the request before spending any work or API calls on it.
    if source not in ALLOWED_SOURCES:
        return RedirectResponse(
            url="/analyze?error=invalid_request",
            status_code=303,
        )

    environment_record = _get_environment(
        db,
        current_organization,
        environment,
    )

    if environment_record is None:
        return RedirectResponse(
            url="/analyze?error=invalid_request",
            status_code=303,
        )

    # The allowance is a soft limit: it is recorded and shown as a
    # warning, but never blocks a scan.
    analysis_usage_status = (
        get_analysis_usage_status(
            db,
            current_organization,
        )
    )

    content = await read_upload_limited(
        file,
        MAX_UPLOAD_BYTES,
    )

    if content is None:
        return RedirectResponse(
            url="/analyze?error=file_too_large",
            status_code=303,
        )

    if not content:
        return RedirectResponse(
            url="/analyze?error=empty_file",
            status_code=303,
        )

    # analyze_file hashes the file and calls VirusTotal, both of which
    # block. Running it in a worker thread keeps the server responsive
    # for everyone else while it works.
    result = await run_in_threadpool(
        analyze_file,
        filename=file.filename or "unknown",
        content=content,
        content_type=file.content_type,
    )

    analysis = _record_analysis(
        db,
        organization=current_organization,
        user=current_user,
        environment=environment_record,
        source=source,
        result=result,
        analysis_type="file",
        usage_status=analysis_usage_status,
        event_type="file_analysis",
        description=(
            f"{current_user.name} analyzed "
            f"{result['filename']}."
        ),
    )

    return RedirectResponse(
        url=f"/analysis/{analysis.id}",
        status_code=303,
    )


@router.post("/analyze/link")
async def analyze_link_route(
    request: Request,
    url: str = Form(...),
    environment: int = Form(...),
    source: str = Form(...),
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
    redirect = _access_redirect(
        current_user,
        current_organization,
        current_membership,
    )

    if redirect is not None:
        return redirect

    if source not in ALLOWED_LINK_SOURCES:
        return RedirectResponse(
            url="/analyze?error=invalid_link_request#check-link",
            status_code=303,
        )

    if len(url) > MAX_LINK_LENGTH:
        return RedirectResponse(
            url="/analyze?error=link_too_long#check-link",
            status_code=303,
        )

    environment_record = _get_environment(
        db,
        current_organization,
        environment,
    )

    if environment_record is None:
        return RedirectResponse(
            url="/analyze?error=invalid_link_request#check-link",
            status_code=303,
        )

    analysis_usage_status = (
        get_analysis_usage_status(
            db,
            current_organization,
        )
    )

    # PreClear never visits the link. analyze_link only inspects the
    # address and may look up the host's reputation on VirusTotal.
    try:
        result = await run_in_threadpool(
            analyze_link,
            url,
        )

    except InvalidLinkError:
        return RedirectResponse(
            url="/analyze?error=invalid_link#check-link",
            status_code=303,
        )

    analysis = _record_analysis(
        db,
        organization=current_organization,
        user=current_user,
        environment=environment_record,
        source=source,
        result=result,
        analysis_type="link",
        usage_status=analysis_usage_status,
        event_type="link_analysis",
        description=(
            f"{current_user.name} checked a link to "
            f"{(result['details'].get('inner') or result['details']).get('host') or result['filename']}."
        ),
    )

    return RedirectResponse(
        url=f"/analysis/{analysis.id}",
        status_code=303,
    )


@router.get(
    "/analysis/{analysis_id}",
    response_class=HTMLResponse,
)
def analysis_result_page(
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

    analysis = db.scalar(
        select(Analysis).where(
            Analysis.id == analysis_id,
            Analysis.organization_id
            == current_organization.id,
        )
    )

    if analysis is None:
        return RedirectResponse(
            url="/analyze",
            status_code=303,
        )

    reasons = json.loads(
        analysis.reasons
    )

    try:
        details = json.loads(
            analysis.details_json or "{}"
        )
    except ValueError:
        details = {}

    return templates.TemplateResponse(
        request=request,
        name="analysis_result.html",
        context={
            "active_page": "analyze",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "analysis": analysis,
            "reasons": reasons,
            "details": details,
        },
    )