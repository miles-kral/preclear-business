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
from app.services.email_analysis import (
    InvalidEmailError,
    analyze_email,
    email_from_saved_page,
    looks_like_email,
    starts_with_headers,
)
from app.services.text_analysis import (
    MAX_TEXT_CHARS,
    InvalidTextError,
    analyze_text,
)
from app.services.trusted_domains import load_trusted_context
from app.services.qr_analysis import (
    analyze_qr_in_file,
    combine_with_file_result,
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


# Must match the <option> values in analyze.html (the file form and the
# QR scan form).
ALLOWED_SOURCES = {
    "email",
    "vendor",
    "customer",
    "website",
    "shared",
    "printed",
    "text_message",
    "document",
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

# Pasted email source. Starlette limits each form field to 1 MB by
# default, far too small for an email with attachments, so this route
# reads its form with a higher per-field limit. The request-size
# middleware (just over 50 MB) stays the outer cap, and form encoding
# adds some size, which the text limit leaves room for.
MAX_PASTED_EMAIL_CHARS = 15 * 1024 * 1024
MAX_PASTED_EMAIL_FIELD_BYTES = 50 * 1024 * 1024

# After an error, the pasted text is shown again so it can be fixed, up
# to this size.
MAX_PASTED_EMAIL_REDISPLAY = 200_000

EMAIL_PASTE_ERRORS = {
    "empty": (
        "Paste the email's original first. In Outlook, open the email, "
        "choose More actions (...), then View, then View message source, "
        "and copy everything it shows."
    ),
    "not_original": (
        "That looks like the email's message, not its original. The "
        "original starts with lines such as Received:, From: and "
        "Subject:. In Outlook, open the email, choose More actions (...), "
        "then View, then View message source, and copy everything."
    ),
    "too_large": (
        "That's too much text for PreClear to check. Make sure you copied "
        "a single email."
    ),
    "unreadable": (
        "PreClear couldn't read that as an email. Copy the original "
        "again, from its first line to its last, and paste it here."
    ),
    "invalid_request": (
        "The check was incomplete. Choose an environment and source, "
        "then try again."
    ),
}

ALLOWED_TEXT_SOURCES = {
    "text_message",
    "chat",
    "email",
    "other",
}

TEXT_ERRORS = {
    "empty": "Paste the text message first.",
    "too_long": (
        f"That's longer than PreClear checks ({MAX_TEXT_CHARS:,} "
        "characters). Paste a single message."
    ),
    "invalid_request": (
        "The check was incomplete. Choose an environment and source, "
        "then try again."
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

    return _render_analyze_page(
        request,
        db,
        current_user,
        current_organization,
        current_membership,
        analysis_usage_status,
    )


def _render_analyze_page(
    request: Request,
    db: Session,
    current_user: User,
    current_organization: Organization,
    current_membership: Membership,
    analysis_usage_status: dict | None = None,
    extra: dict | None = None,
    status_code: int = 200,
):
    if analysis_usage_status is None:
        analysis_usage_status = get_analysis_usage_status(
            db,
            current_organization,
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

    context = {
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
        "email_paste_error": None,
        "email_paste_text": "",
        "text_error": None,
        "text_message": "",
        "max_text_chars": MAX_TEXT_CHARS,
        "max_upload_bytes": MAX_UPLOAD_BYTES,
        "max_upload_mb": MAX_UPLOAD_MB,
    }

    context.update(extra or {})

    return templates.TemplateResponse(
        request=request,
        name="analyze.html",
        context=context,
        status_code=status_code,
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

    # Store "What was checked" with the evidence, for every type.
    try:
        details = json.loads(result.get("details_json") or "{}")
    except ValueError:
        details = {}

    if result.get("checks") and "checks" not in details:
        details["checks"] = result["checks"]

    details_json = json.dumps(details) if details else None

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
        details_json=details_json,
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

    filename = file.filename or "unknown"

    result = None

    # A saved email (.eml) gets the email analyzer: sender, verification,
    # requests, links and attachments. If it can't be read as an email,
    # it falls back to the regular file checks.
    # The organization's own domains and vendors, for lookalike checks.
    trusted = load_trusted_context(
        db,
        current_organization.id,
    )

    email_content = None

    if looks_like_email(filename, content):
        email_content = content
    else:
        # A browser-saved "Show original" page holds the email inside it.
        email_content = email_from_saved_page(content)

    if email_content is not None:
        try:
            result = await run_in_threadpool(
                analyze_email,
                filename=filename,
                content=email_content,
                trusted=trusted,
            )
        except InvalidEmailError:
            result = None

    if result is not None:
        sender = (
            result["details"].get("from_address")
            or "an unknown sender"
        )

        analysis = _record_analysis(
            db,
            organization=current_organization,
            user=current_user,
            environment=environment_record,
            source=source,
            result=result,
            analysis_type="email",
            usage_status=analysis_usage_status,
            event_type="email_analysis",
            description=(
                f"{current_user.name} checked an email "
                f"from {sender}."
            ),
        )

        return RedirectResponse(
            url=f"/analysis/{analysis.id}",
            status_code=303,
        )

    # analyze_file hashes the file and calls VirusTotal, both of which
    # block. Running it in a worker thread keeps the server responsive
    # for everyone else while it works.
    result = await run_in_threadpool(
        analyze_file,
        filename=filename,
        content=content,
        content_type=file.content_type,
    )

    analysis_type = "file"

    # Images and PDFs are also checked for QR codes, whose contents are
    # explained and whose links are checked without being visited.
    qr = await run_in_threadpool(
        analyze_qr_in_file,
        content,
        result,
        trusted=trusted,
    )

    if qr is not None:
        result, analysis_type = combine_with_file_result(
            result,
            qr,
        )

    if analysis_type == "qr":
        description = (
            f"{current_user.name} checked a QR code in "
            f"{result['details']['source_file']}."
        )
    else:
        description = (
            f"{current_user.name} analyzed "
            f"{result['filename']}."
        )

    analysis = _record_analysis(
        db,
        organization=current_organization,
        user=current_user,
        environment=environment_record,
        source=source,
        result=result,
        analysis_type=analysis_type,
        usage_status=analysis_usage_status,
        event_type=(
            "qr_analysis"
            if analysis_type == "qr"
            else "file_analysis"
        ),
        description=description,
    )

    return RedirectResponse(
        url=f"/analysis/{analysis.id}",
        status_code=303,
    )


@router.post("/analyze/email")
async def analyze_pasted_email_route(
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
    """
    Checks an email's original pasted as text, for email services that
    can't save an email as a file. The text is read but never stored.
    """
    redirect = _access_redirect(
        current_user,
        current_organization,
        current_membership,
    )

    if redirect is not None:
        return redirect

    form = await request.form(
        max_fields=10,
        max_part_size=MAX_PASTED_EMAIL_FIELD_BYTES,
    )

    text = str(form.get("email_source") or "")
    source = str(form.get("source") or "")

    try:
        environment = int(form.get("environment") or 0)
    except ValueError:
        environment = 0

    def fail(code: str):
        keep = (
            text
            if code not in {"too_large"}
            and len(text) <= MAX_PASTED_EMAIL_REDISPLAY
            else ""
        )
        return _render_analyze_page(
            request,
            db,
            current_user,
            current_organization,
            current_membership,
            extra={
                "email_paste_error": EMAIL_PASTE_ERRORS[code],
                "email_paste_text": keep,
            },
            status_code=400,
        )

    if source not in ALLOWED_SOURCES:
        return fail("invalid_request")

    environment_record = _get_environment(
        db,
        current_organization,
        environment,
    )

    if environment_record is None:
        return fail("invalid_request")

    if not text.strip():
        return fail("empty")

    if len(text) > MAX_PASTED_EMAIL_CHARS:
        return fail("too_large")

    data = text.lstrip("\ufeff \t\r\n").encode("utf-8", "replace")

    if not starts_with_headers(data):
        unwrapped = email_from_saved_page(data)
        if unwrapped is None:
            return fail("not_original")
        data = unwrapped

    analysis_usage_status = get_analysis_usage_status(
        db,
        current_organization,
    )

    trusted = load_trusted_context(
        db,
        current_organization.id,
    )

    # Parsing and checking an email blocks, so it runs in a worker
    # thread to keep the server responsive for everyone else.
    try:
        result = await run_in_threadpool(
            analyze_email,
            filename="pasted-email.eml",
            content=data,
            trusted=trusted,
        )
    except InvalidEmailError:
        return fail("unreadable")

    result["details"]["input"] = "pasted"
    result["details_json"] = json.dumps(result["details"])

    sender = (
        result["details"].get("from_address")
        or "an unknown sender"
    )

    analysis = _record_analysis(
        db,
        organization=current_organization,
        user=current_user,
        environment=environment_record,
        source=source,
        result=result,
        analysis_type="email",
        usage_status=analysis_usage_status,
        event_type="email_analysis",
        description=(
            f"{current_user.name} checked a pasted email "
            f"from {sender}."
        ),
    )

    return RedirectResponse(
        url=f"/analysis/{analysis.id}",
        status_code=303,
    )


@router.post("/analyze/text")
async def analyze_text_route(
    request: Request,
    message: str = Form(""),
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
    """
    Checks a pasted text or chat message. The message is read but never
    stored; the record keeps a short description, links and warning signs.
    """
    redirect = _access_redirect(
        current_user,
        current_organization,
        current_membership,
    )

    if redirect is not None:
        return redirect

    def fail(code: str):
        return _render_analyze_page(
            request,
            db,
            current_user,
            current_organization,
            current_membership,
            extra={
                "text_error": TEXT_ERRORS[code],
                "text_message": (
                    message if len(message) <= MAX_TEXT_CHARS else ""
                ),
            },
            status_code=400,
        )

    if source not in ALLOWED_TEXT_SOURCES:
        return fail("invalid_request")

    environment_record = _get_environment(
        db,
        current_organization,
        environment,
    )

    if environment_record is None:
        return fail("invalid_request")

    analysis_usage_status = get_analysis_usage_status(
        db,
        current_organization,
    )

    trusted = load_trusted_context(
        db,
        current_organization.id,
    )

    try:
        result = await run_in_threadpool(
            analyze_text,
            message,
            trusted,
        )
    except InvalidTextError as error:
        return fail(str(error))

    analysis = _record_analysis(
        db,
        organization=current_organization,
        user=current_user,
        environment=environment_record,
        source=source,
        result=result,
        analysis_type="text",
        usage_status=analysis_usage_status,
        event_type="text_analysis",
        description=(
            f"{current_user.name} checked a text message "
            f"({result['filename'][len('Text message '):]})."
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
            trusted=load_trusted_context(
                db,
                current_organization.id,
            ),
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