"""
Trusted domains settings: an organization lists its own domains and its
key vendors, and PreClear uses them to catch lookalikes.
"""
import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import (
    can_manage_organization,
    get_current_membership,
    get_current_organization,
    get_current_user,
)
from app.models import (
    AuditEvent,
    Membership,
    Organization,
    TrustedDomain,
    User,
)
from app.plans import has_subscription_access
from app.services.trusted_domains import (
    MAX_TRUSTED_DOMAINS,
    normalize_domain,
)


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)

PAGE_URL = "/settings/trusted-domains"

KINDS = {"vendor", "own"}

MAX_LABEL_LENGTH = 120

# Shared email and hosting providers can't be "trusted" as a whole:
# anyone can get an address or a page on them.
SHARED_PROVIDER_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "yahoo.com", "aol.com", "icloud.com",
    "me.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
    "zoho.com", "yandex.com", "comcast.net", "att.net", "verizon.net",
    "google.com", "microsoft.com", "amazonaws.com", "github.io",
    "web.app", "firebaseapp.com", "netlify.app", "vercel.app",
    "herokuapp.com", "onrender.com", "blogspot.com", "wixsite.com",
    "weebly.com", "bit.ly", "tinyurl.com",
}


def set_message(
    request: Request,
    text: str,
    message_type: str = "success",
) -> None:
    request.session["trusted_domain_message"] = {
        "text": text,
        "type": message_type,
    }


def _record_event(
    db: Session,
    organization: Organization,
    user: User,
    event_type: str,
    description: str,
    entry: TrustedDomain,
) -> None:
    db.add(
        AuditEvent(
            organization_id=organization.id,
            user_id=user.id,
            event_type=event_type,
            description=description,
            metadata_json=json.dumps(
                {
                    "domain": entry.domain,
                    "label": entry.label,
                    "kind": entry.kind,
                }
            ),
        )
    )


@router.get(
    PAGE_URL,
    response_class=HTMLResponse,
)
def trusted_domains_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
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
        return RedirectResponse(url="/login", status_code=303)

    entries = (
        db.query(TrustedDomain)
        .filter(TrustedDomain.organization_id == current_organization.id)
        .order_by(TrustedDomain.kind.asc(), TrustedDomain.label.asc())
        .all()
    )

    return templates.TemplateResponse(
        request=request,
        name="trusted_domains.html",
        context={
            "active_page": "settings",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "own_domains": [e for e in entries if e.kind == "own"],
            "vendor_domains": [e for e in entries if e.kind != "own"],
            "entry_count": len(entries),
            "max_entries": MAX_TRUSTED_DOMAINS,
            "can_manage": can_manage_organization(current_membership),
            "message": request.session.pop("trusted_domain_message", None),
        },
    )


@router.post(PAGE_URL)
def add_trusted_domain(
    request: Request,
    domain: str = Form(...),
    label: str = Form(""),
    kind: str = Form("vendor"),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
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
        return RedirectResponse(url="/login", status_code=303)

    if not can_manage_organization(current_membership):
        return RedirectResponse(url=PAGE_URL, status_code=303)

    if not has_subscription_access(current_organization.subscription_status):
        set_message(
            request,
            "An active subscription is required to add trusted domains.",
            "error",
        )
        return RedirectResponse(url=PAGE_URL, status_code=303)

    registered = normalize_domain(domain)

    if registered is None:
        set_message(
            request,
            "That doesn't look like a domain. Enter something like "
            "acme-supply.com, or paste a web or email address.",
            "error",
        )
        return RedirectResponse(url=PAGE_URL, status_code=303)

    if registered in SHARED_PROVIDER_DOMAINS:
        set_message(
            request,
            f"{registered} is a shared email or hosting service that anyone "
            "can use, so it can't be added as a trusted domain.",
            "error",
        )
        return RedirectResponse(url=PAGE_URL, status_code=303)

    kind = kind if kind in KINDS else "vendor"
    label = " ".join(label.split())[:MAX_LABEL_LENGTH] or registered

    count = (
        db.query(TrustedDomain)
        .filter(TrustedDomain.organization_id == current_organization.id)
        .count()
    )

    if count >= MAX_TRUSTED_DOMAINS:
        set_message(
            request,
            f"You can list up to {MAX_TRUSTED_DOMAINS} trusted domains. "
            "Remove one to add another.",
            "error",
        )
        return RedirectResponse(url=PAGE_URL, status_code=303)

    entry = TrustedDomain(
        organization_id=current_organization.id,
        domain=registered,
        label=label,
        kind=kind,
        created_by_user_id=current_user.id,
    )

    db.add(entry)

    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        set_message(
            request,
            f"{registered} is already on your trusted list.",
            "error",
        )
        return RedirectResponse(url=PAGE_URL, status_code=303)

    _record_event(
        db,
        current_organization,
        current_user,
        "trusted_domain_added",
        f"{current_user.name} added {registered} ({label}) as a trusted "
        f"{'organization domain' if kind == 'own' else 'vendor domain'}.",
        entry,
    )

    db.commit()

    note = ""
    if registered != domain.strip().lower():
        note = f" PreClear saved it as {registered}, which also covers its subdomains."

    set_message(request, f"Added {label} ({registered}).{note}")

    return RedirectResponse(url=PAGE_URL, status_code=303)


@router.post(PAGE_URL + "/{entry_id}/delete")
def remove_trusted_domain(
    request: Request,
    entry_id: int,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
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
        return RedirectResponse(url="/login", status_code=303)

    if not can_manage_organization(current_membership):
        return RedirectResponse(url=PAGE_URL, status_code=303)

    entry = (
        db.query(TrustedDomain)
        .filter(
            TrustedDomain.id == entry_id,
            TrustedDomain.organization_id == current_organization.id,
        )
        .first()
    )

    if entry is None:
        return RedirectResponse(url=PAGE_URL, status_code=303)

    _record_event(
        db,
        current_organization,
        current_user,
        "trusted_domain_removed",
        f"{current_user.name} removed {entry.domain} ({entry.label}) "
        "from the trusted list.",
        entry,
    )

    db.delete(entry)
    db.commit()

    set_message(request, f"Removed {entry.label} ({entry.domain}).")

    return RedirectResponse(url=PAGE_URL, status_code=303)
