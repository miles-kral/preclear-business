import json

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
    AuditEvent,
    Membership,
    Organization,
    User,
)
from app.auth import (
    hash_password,
    verify_password,
)


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)


def set_account_message(
    request: Request,
    message: str,
    message_type: str = "success",
) -> None:
    request.session["account_message"] = {
        "message": message,
        "type": message_type,
    }


def get_account_message(
    request: Request,
) -> dict | None:
    return request.session.pop(
        "account_message",
        None,
    )


@router.get(
    "/account",
    response_class=HTMLResponse,
)
def account_page(
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

    account_message = get_account_message(
        request
    )

    return templates.TemplateResponse(
        request=request,
        name="account.html",
        context={
            "active_page": "account",
            "current_user": current_user,
            "current_organization": (
                current_organization
            ),
            "current_membership": (
                current_membership
            ),
            "account_message": account_message,
        },
    )


@router.post("/account/profile")
def update_account_profile(
    request: Request,
    name: str = Form(...),
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

    name = name.strip()

    if not name:
        set_account_message(
            request,
            "Your name is required.",
            "error",
        )

        return RedirectResponse(
            url="/account",
            status_code=303,
        )

    old_name = current_user.name

    if name == old_name:
        set_account_message(
            request,
            "No profile changes were made.",
        )

        return RedirectResponse(
            url="/account",
            status_code=303,
        )

    current_user.name = name

    audit_event = AuditEvent(
        organization_id=current_organization.id,
        user_id=current_user.id,
        event_type="account_profile_updated",
        description=(
            f"{name} updated their account profile."
        ),
        metadata_json=json.dumps(
            {
                "old_name": old_name,
                "new_name": name,
            }
        ),
    )

    db.add(audit_event)
    db.commit()

    set_account_message(
        request,
        "Your profile has been updated.",
    )

    return RedirectResponse(
        url="/account",
        status_code=303,
    )


@router.post("/account/password")
def update_account_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
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

    if not verify_password(
        current_password,
        current_user.password_hash,
    ):
        set_account_message(
            request,
            "Your current password is incorrect.",
            "error",
        )

        return RedirectResponse(
            url="/account",
            status_code=303,
        )

    if new_password != confirm_password:
        set_account_message(
            request,
            "The new passwords do not match.",
            "error",
        )

        return RedirectResponse(
            url="/account",
            status_code=303,
        )

    if len(new_password) < 10:
        set_account_message(
            request,
            (
                "Your new password must be at least "
                "10 characters."
            ),
            "error",
        )

        return RedirectResponse(
            url="/account",
            status_code=303,
        )

    if verify_password(
        new_password,
        current_user.password_hash,
    ):
        set_account_message(
            request,
            (
                "Your new password must be different "
                "from your current password."
            ),
            "error",
        )

        return RedirectResponse(
            url="/account",
            status_code=303,
        )

    current_user.password_hash = hash_password(
        new_password
    )

    audit_event = AuditEvent(
        organization_id=current_organization.id,
        user_id=current_user.id,
        event_type="account_password_changed",
        description=(
            f"{current_user.name} changed "
            "their account password."
        ),
        metadata_json=json.dumps(
            {
                "user_id": current_user.id,
                "email": current_user.email,
            }
        ),
    )

    db.add(audit_event)
    db.commit()

    set_account_message(
        request,
        "Your password has been changed.",
    )

    return RedirectResponse(
        url="/account",
        status_code=303,
    )