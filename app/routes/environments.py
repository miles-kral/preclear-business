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
    can_manage_organization,
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

from app.plans import get_plan_config, has_subscription_access

import json

router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)


def set_environment_message(
    request: Request,
    message: str,
    message_type: str = "success",
) -> None:
    request.session["environment_message"] = {
        "text": message,
        "type": message_type,
    }


@router.get(
    "/environments",
    response_class=HTMLResponse,
)
def environments_page(
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

    environments = (
        db.query(Environment)
        .filter(
            Environment.organization_id
            == current_organization.id
        )
        .order_by(
            Environment.is_active.desc(),
            Environment.name.asc(),
        )
        .all()
    )

    environment_stats = {}

    for environment in environments:

        environment_analyses = (
            db.query(Analysis)
            .filter(
                Analysis.organization_id
                == current_organization.id,
                Analysis.environment_id
             == environment.id,
            )
            .all()
        )

        environment_stats[
            environment.id
        ] = {
            "total": len(
                environment_analyses
            ),
            "safe": sum(
                1
                for analysis in environment_analyses
                if analysis.decision == "LOOKS_SAFE"
            ),
            "caution": sum(
                1
                for analysis in environment_analyses
                if analysis.decision == "USE_CAUTION"
            ),
            "danger": sum(
                1
                for analysis in environment_analyses
                if analysis.decision == "DO_NOT_OPEN"
            ),
        }

    environment_message = request.session.pop(
        "environment_message",
        None,
    )

    return templates.TemplateResponse(
        request=request,
        name="environments.html",
        context={
            "active_page": "environments",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "environments": environments,
            "environment_message": environment_message,
            "environment_stats": environment_stats,
        },
    )

@router.post("/environments")
def create_environment(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
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

    if not can_manage_organization(
        current_membership
    ):
        return RedirectResponse(
            url="/environments",
            status_code=303,
        )

    if not has_subscription_access(
        current_organization.subscription_status
    ):
        set_environment_message(
            request,
            (
                "An active subscription is required "
                "to create environments."
            ),
            "error",
        )

        return RedirectResponse(
            url="/environments",
            status_code=303,
        )

    name = name.strip()
    description = description.strip()

    if not name:
        set_environment_message(
            request,
            "Environment name is required.",
            "error",
        )

        return RedirectResponse(
            url="/environments",
            status_code=303,
        )

    existing_environment = (
        db.query(Environment)
        .filter(
            Environment.organization_id
            == current_organization.id,
            Environment.name == name,
        )
        .first()
    )

    if existing_environment is not None:
        set_environment_message(
            request,
            (
                "An environment with that name "
                "already exists."
            ),
            "error",
        )

        return RedirectResponse(
            url="/environments",
            status_code=303,
        )

    plan_config = get_plan_config(
        current_organization.plan
    )

    environment_limit = (
        plan_config["environment_limit"]
    )

    if environment_limit is not None:

        active_environment_count = (
            db.query(Environment)
            .filter(
                Environment.organization_id
                == current_organization.id,
                Environment.is_active.is_(True),
            )
            .count()
        )

        if (
            active_environment_count
            >= environment_limit
        ):
            set_environment_message(
                request,
                (
                    f"Your {plan_config['name']} plan "
                    f"supports up to "
                    f"{environment_limit} active environments."
                ),
                "error",
            )

            return RedirectResponse(
                url="/environments",
                status_code=303,
            )

    environment = Environment(
        organization_id=current_organization.id,
        name=name,
        description=(
            description
            if description
            else None
        ),
        is_active=True,
    )

    db.add(environment)
    db.flush()

    audit_event = AuditEvent(
        organization_id=current_organization.id,
        user_id=current_user.id,
        event_type="environment_created",
        description=(
            f"{current_user.name} created "
            f"the {environment.name} environment."
        ),
        metadata_json=json.dumps(
            {
                "environment_id": environment.id,
                "environment_name": environment.name,
            }
        ),
    )

    db.add(audit_event)
    db.commit()

    set_environment_message(
        request,
        f"{name} environment created.",
    )

    return RedirectResponse(
        url="/environments",
        status_code=303,
    )

@router.post(
    "/environments/{environment_id}/edit"
)
def edit_environment(
    environment_id: int,
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
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

    if not can_manage_organization(
        current_membership
    ):
        return RedirectResponse(
            url="/environments",
            status_code=303,
        )

    environment = (
        db.query(Environment)
        .filter(
            Environment.id == environment_id,
            Environment.organization_id
            == current_organization.id,
        )
        .first()
    )

    if environment is None:
        return RedirectResponse(
            url="/environments",
            status_code=303,
        )

    name = name.strip()
    description = description.strip()

    if not name:
        set_environment_message(
            request,
            "Environment name is required.",
            "error",
        )

        return RedirectResponse(
            url="/environments",
            status_code=303,
        )

    duplicate = (
        db.query(Environment)
        .filter(
            Environment.organization_id
            == current_organization.id,
            Environment.name == name,
            Environment.id != environment.id,
        )
        .first()
    )

    if duplicate is not None:
        set_environment_message(
            request,
            (
                "Another environment already "
                "uses that name."
            ),
            "error",
        )

        return RedirectResponse(
            url="/environments",
            status_code=303,
        )

    old_name = environment.name
    old_description = environment.description

    environment.name = name

    environment.description = (
        description
        if description
        else None
    )

    audit_event = AuditEvent(
        organization_id=current_organization.id,
        user_id=current_user.id,
        event_type="environment_updated",
        description=(
            f"{current_user.name} updated "
            f"the {environment.name} environment."
        ),
        metadata_json=json.dumps(
            {
                "environment_id": environment.id,
                "old_name": old_name,
                "new_name": environment.name,
                "old_description": old_description,
                "new_description": environment.description,
            }
        ),
    )

    db.add(audit_event)
    db.commit()

    set_environment_message(
        request,
        f"{environment.name} updated.",
    )

    return RedirectResponse(
        url="/environments",
        status_code=303,
    )

@router.post(
    "/environments/{environment_id}/status"
)
def update_environment_status(
    environment_id: int,
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

    if not can_manage_organization(
        current_membership
    ):
        return RedirectResponse(
            url="/environments",
            status_code=303,
        )

    environment = (
        db.query(Environment)
        .filter(
            Environment.id == environment_id,
            Environment.organization_id
            == current_organization.id,
        )
        .first()
    )

    if environment is None:
        return RedirectResponse(
            url="/environments",
            status_code=303,
        )

    if not environment.is_active:

        if not has_subscription_access(
            current_organization.subscription_status
        ):
            set_environment_message(
                request,
                (
                    "An active subscription is required "
                    "to reactivate environments."
                ),
                "error",
            )

            return RedirectResponse(
                url="/environments",
                status_code=303,
            )

        plan_config = get_plan_config(
            current_organization.plan
        )

        environment_limit = (
            plan_config["environment_limit"]
        )

        if environment_limit is not None:

            active_environment_count = (
                db.query(Environment)
                .filter(
                    Environment.organization_id
                    == current_organization.id,
                    Environment.is_active.is_(True),
                )
                .count()
            )

            if (
                active_environment_count
                >= environment_limit
            ):
                set_environment_message(
                    request,
                    (
                        f"Your {plan_config['name']} plan "
                        f"supports up to "
                        f"{environment_limit} active environments."
                    ),
                    "error",
                )

                return RedirectResponse(
                    url="/environments",
                    status_code=303,
                )

    environment.is_active = (
        not environment.is_active
    )

    if environment.is_active:
        event_type = "environment_activated"
        action = "activated"
    else:
        event_type = "environment_deactivated"
        action = "deactivated"

    audit_event = AuditEvent(
        organization_id=current_organization.id,
        user_id=current_user.id,
        event_type=event_type,
        description=(
            f"{current_user.name} {action} "
            f"the {environment.name} environment."
        ),
        metadata_json=json.dumps(
            {
                "environment_id": environment.id,
                "environment_name": environment.name,
                "is_active": environment.is_active,
            }
        ),
    )

    db.add(audit_event)

    db.commit()

    if environment.is_active:
        message = (
            f"{environment.name} activated."
        )
    else:
        message = (
            f"{environment.name} deactivated."
        )

    set_environment_message(
        request,
        message,
    )

    return RedirectResponse(
        url="/environments",
        status_code=303,
    )