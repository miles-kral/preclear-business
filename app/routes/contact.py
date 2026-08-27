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
)
from app.models import (
    BillingRequest,
    Membership,
    Organization,
    SupportRequest,
    User,
)
from app.services.email_service import (
    send_sales_inquiry_email,
    send_support_request_email,
)
from app.config import APP_BASE_URL

router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)


@router.get(
    "/contact",
    response_class=HTMLResponse,
)
def contact_page(
    request: Request,
):
    return templates.TemplateResponse(
        request=request,
        name="contact.html",
        context={
            "sales_success": (
                request.query_params.get("sent")
                == "1"
            ),
            "page_title": (
                "Contact PreClear | PreClear Business"
            ),
            "meta_description": (
                "Contact PreClear for product, security, "
                "sales, or enterprise questions."
            ),
            "canonical_url": (
                f"{APP_BASE_URL}/contact"
            ),
        },
    )

@router.get(
    "/support",
    response_class=HTMLResponse,
)
def support_page(
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

    return templates.TemplateResponse(
        request=request,
        name="support.html",
        context={
            "active_page": "support",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "support_success": (
                request.query_params.get(
                    "support_sent"
                )
                == "1"
            ),
            "support_error": (
                request.query_params.get(
                    "support_error"
                )
                == "1"
            ),
            "robots_content": (
                "noindex, nofollow"
            ),
        },
    )


@router.post("/contact")
def submit_contact_request(
    request: Request,
    company_name: str = Form(...),
    contact_name: str = Form(...),
    contact_email: str = Form(...),
    estimated_users: str = Form(""),
    estimated_monthly_analyses: str = Form(""),
    purchase_order: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
    current_organization: Organization | None = Depends(
        get_current_organization
    ),
):
    company_name = company_name.strip()
    contact_name = contact_name.strip()
    contact_email = contact_email.strip()
    purchase_order = purchase_order.strip()
    notes = notes.strip()

    try:
        users_value = (
            int(estimated_users)
            if estimated_users.strip()
            else None
        )
    except ValueError:
        users_value = None

    try:
        analyses_value = (
            int(estimated_monthly_analyses)
            if estimated_monthly_analyses.strip()
            else None
        )
    except ValueError:
        analyses_value = None

    billing_request = BillingRequest(
        organization_id=(
            current_organization.id
            if current_organization
            else None
        ),
        company_name=company_name,
        contact_name=contact_name,
        contact_email=contact_email,
        estimated_users=users_value,
        estimated_monthly_files=analyses_value,
        purchase_order=(
            purchase_order
            if purchase_order
            else None
        ),
        notes=(
            notes
            if notes
            else None
        ),
        status="pending",
    )

    db.add(
        billing_request
    )

    db.commit()

    try:
        send_sales_inquiry_email(
            company_name=company_name,
            contact_name=contact_name,
            contact_email=contact_email,
            estimated_users=users_value,
            estimated_monthly_files=analyses_value,
            purchase_order=(
                purchase_order
                if purchase_order
                else None
            ),
            notes=(
                notes
                if notes
                else None
            ),
        )

    except Exception:
        # The request remains safely stored even if
        # email delivery is temporarily unavailable.
        pass

    return RedirectResponse(
        url="/contact?sent=1",
        status_code=303,
    )

@router.post("/contact/support")
def submit_support_request(
    request: Request,
    request_type: str = Form(...),
    subject: str = Form(...),
    message: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(
        get_current_user
    ),
    current_organization: Organization | None = Depends(
        get_current_organization
    ),
):
    if (
        current_user is None
        or current_organization is None
    ):
        return RedirectResponse(
            url="/login",
            status_code=303,
        )

    request_type = request_type.strip()
    subject = subject.strip()
    message = message.strip()

    allowed_request_types = {
        "general",
        "technical",
        "billing",
        "account",
        "feature_integration",
    }

    if request_type not in allowed_request_types:
        request_type = "general"

    if not subject or not message:
        return RedirectResponse(
            url="/support?support_error=1",
            status_code=303,
        )

    support_request = SupportRequest(
        organization_id=current_organization.id,
        user_id=current_user.id,
        request_type=request_type,
        subject=subject,
        message=message,
        status="open",
    )

    db.add(
        support_request
    )

    db.commit()

    try:
        send_support_request_email(
            company_name=current_organization.name,
            contact_name=current_user.name,
            contact_email=current_user.email,
            request_type=request_type,
            subject=subject,
            message=message,
        )

    except Exception:
        # Preserve the support request even if
        # email delivery is temporarily unavailable.
        pass

    return RedirectResponse(
        url="/support?support_sent=1",
        status_code=303,
    )