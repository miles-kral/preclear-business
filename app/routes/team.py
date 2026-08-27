from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import secrets
import json

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
    TeamInvitation,
    User,
)

from app.config import APP_BASE_URL
from app.services.email_service import (
    send_team_invitation_email,
)
from app.plans import get_plan_config, has_subscription_access


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)

def set_team_message(
    request: Request,
    message: str,
    message_type: str = "success",
) -> None:
    request.session["team_message"] = {
        "text": message,
        "type": message_type,
    }


@router.get(
    "/team",
    response_class=HTMLResponse,
)
def team_page(
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

    memberships = (
        db.query(Membership)
        .filter(
            Membership.organization_id
            == current_organization.id,
            Membership.is_active.is_(True),
        )
        .all()
    )

    pending_invitations = (
        db.query(TeamInvitation)
        .filter(
            TeamInvitation.organization_id
            == current_organization.id,
            TeamInvitation.status == "pending",
        )
        .order_by(
            TeamInvitation.created_at.desc()
        )
        .all()
    )

    team_message = request.session.pop(
        "team_message",
        None,
    )

    return templates.TemplateResponse(
        request=request,
        name="team.html",
        context={
            "active_page": "team",
            "current_user": current_user,
            "current_organization": current_organization,
            "current_membership": current_membership,
            "memberships": memberships,
            "pending_invitations": pending_invitations,
            "team_message": team_message,
        },
    )

@router.post("/team/invite")
def invite_team_member(
    request: Request,
    email: str = Form(...),
    role: str = Form(...),
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

    if current_membership.role not in {
        "owner",
        "admin",
    }:
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    if not has_subscription_access(
        current_organization.subscription_status
    ):
        set_team_message(
            request,
            (
                "An active subscription is required "
                "to invite team members."
            ),
            "error",
        )

        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    email = email.strip().lower()

    allowed_roles = {
        "admin",
        "analyst",
        "viewer",
    }

    if role not in allowed_roles:
        role = "viewer"

    existing_user = (
        db.query(User)
        .filter(
            User.email == email
        )
        .first()
    )

    if existing_user is not None:
        existing_membership = (
            db.query(Membership)
            .filter(
                Membership.user_id
                == existing_user.id,
                Membership.organization_id
                == current_organization.id,
            )
            .first()
        )

        if (
            existing_membership is not None
            and existing_membership.is_active
        ):
            set_team_message(
                request,
                (
                    "That person is already an active "
                    "member of your organization."
                ),
                "error",
            )

            return RedirectResponse(
                url="/team",
                status_code=303,
            )

    existing_invitation = (
        db.query(TeamInvitation)
        .filter(
            TeamInvitation.organization_id
            == current_organization.id,
            TeamInvitation.email == email,
            TeamInvitation.status == "pending",
        )
        .first()
    )

    if existing_invitation is not None:
        set_team_message(
            request,
            (
                "A pending invitation already exists "
                "for that email address."
            ),
            "error",
        )

        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    plan_config = get_plan_config(
        current_organization.plan
    )

    team_member_limit = (
        plan_config["team_member_limit"]
    )

    active_member_count = (
        db.query(Membership)
        .filter(
            Membership.organization_id
            == current_organization.id,
            Membership.is_active.is_(True),
        )
        .count()
    )

    pending_invitation_count = (
        db.query(TeamInvitation)
        .filter(
            TeamInvitation.organization_id
            == current_organization.id,
            TeamInvitation.status == "pending",
        )
        .count()
    )

    reserved_team_seats = (
        active_member_count
        + pending_invitation_count
    )

    if (
        team_member_limit is not None
        and reserved_team_seats
        >= team_member_limit
    ):
        set_team_message(
            request,
            (
                f"Your {plan_config['name']} plan "
                f"supports up to "
                f"{team_member_limit} team members. "
                "Cancel a pending invitation, "
                "deactivate a team member, or "
                "upgrade your plan to add another "
                "person."
            ),
            "error",
        )

        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    invitation = TeamInvitation(
        organization_id=current_organization.id,
        invited_by_user_id=current_user.id,
        email=email,
        role=role,
        token=secrets.token_urlsafe(32),
        status="pending",
        expires_at=(
            datetime.now(timezone.utc)
            + timedelta(days=7)
        ),
    )

    db.add(invitation)
    db.commit()

    invite_url = (
        f"{APP_BASE_URL}/invite/"
        f"{invitation.token}"
    )

    try:
        send_team_invitation_email(
            email=invitation.email,
            invite_url=invite_url,
            inviter_name=current_user.name,
            organization_name=current_organization.name,
            role=invitation.role,
        )

        invitation.delivery_status = "sent"
        invitation.last_delivery_error = None

        set_team_message(
            request,
            f"Invitation sent to {invitation.email}.",
        )

    except Exception as exc:
        invitation.delivery_status = "failed"
        invitation.last_delivery_error = str(exc)

        set_team_message(
            request,
            (
                "The invitation was created, "
                "but the email could not be delivered. "
                "You can resend it from the pending "
                "invitations list."
            ),
            "error",
        )

    audit_event = AuditEvent(
        organization_id=current_organization.id,
        user_id=current_user.id,
        event_type="team_invitation_created",
        description=(
            f"{current_user.name} invited "
            f"{invitation.email} as "
            f"{invitation.role.title()}."
        ),
        metadata_json=json.dumps(
            {
                "invitation_id": invitation.id,
                "email": invitation.email,
                "role": invitation.role,
                "delivery_status": (
                    invitation.delivery_status
                ),
            }
        ),
    )

    db.add(audit_event)
    db.commit()

    return RedirectResponse(
        url="/team",
        status_code=303,
    )

@router.post(
    "/team/invitations/{invitation_id}/resend"
)
def resend_team_invitation(
    invitation_id: int,
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

    if current_membership.role not in {
        "owner",
        "admin",
    }:
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    invitation = (
        db.query(TeamInvitation)
        .filter(
            TeamInvitation.id == invitation_id,
            TeamInvitation.organization_id
            == current_organization.id,
            TeamInvitation.status == "pending",
        )
        .first()
    )

    if invitation is None:
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    invite_url = (
        f"{APP_BASE_URL}/invite/"
        f"{invitation.token}"
    )

    try:
        send_team_invitation_email(
            email=invitation.email,
            invite_url=invite_url,
            inviter_name=current_user.name,
            organization_name=current_organization.name,
            role=invitation.role,
        )

        invitation.delivery_status = "sent"
        invitation.last_delivery_error = None

        set_team_message(
            request,
            f"Invitation resent to {invitation.email}.",
        )

    except Exception as exc:
        invitation.delivery_status = "failed"
        invitation.last_delivery_error = str(exc)

        set_team_message(
            request,
            (
                "The invitation could not be resent. "
                "Please try again."
            ),
            "error",
        )

    audit_event = AuditEvent(
        organization_id=current_organization.id,
        user_id=current_user.id,
        event_type="team_invitation_resent",
        description=(
            f"{current_user.name} resent the invitation "
            f"to {invitation.email}."
        ),
        metadata_json=json.dumps(
            {
                "invitation_id": invitation.id,
                "email": invitation.email,
                "role": invitation.role,
                "delivery_status": invitation.delivery_status,
            }
        ),
    )

    db.add(audit_event)

    db.commit()

    return RedirectResponse(
        url="/team",
        status_code=303,
    )

@router.post(
    "/team/invitations/{invitation_id}/cancel"
)
def cancel_team_invitation(
    invitation_id: int,
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

    if current_membership.role not in {
        "owner",
        "admin",
    }:
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    invitation = (
        db.query(TeamInvitation)
        .filter(
            TeamInvitation.id == invitation_id,
            TeamInvitation.organization_id
            == current_organization.id,
            TeamInvitation.status == "pending",
        )
        .first()
    )

    if invitation is None:
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    invitation.status = "cancelled"

    audit_event = AuditEvent(
        organization_id=current_organization.id,
        user_id=current_user.id,
        event_type="team_invitation_cancelled",
        description=(
            f"{current_user.name} cancelled the invitation "
            f"to {invitation.email}."
        ),
        metadata_json=json.dumps(
            {
                "invitation_id": invitation.id,
                "email": invitation.email,
                "role": invitation.role,
            }
        ),
    )

    db.add(audit_event)
    db.commit()

    set_team_message(
        request,
        f"Invitation to {invitation.email} cancelled.",
    )

    return RedirectResponse(
        url="/team",
        status_code=303,
    )

@router.post(
    "/team/{membership_id}/role"
)
def update_team_role(
    membership_id: int,
    request: Request,
    role: str = Form(...),
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

    if current_membership.role not in {
        "owner",
        "admin",
    }:
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    membership = (
        db.query(Membership)
        .filter(
            Membership.id == membership_id,
            Membership.organization_id
            == current_organization.id,
        )
        .first()
    )

    if membership is None:
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    # Nobody can change the Owner through this control.
    if membership.role == "owner":
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    # Admins cannot manage other admins.
    if (
        current_membership.role == "admin"
        and membership.role == "admin"
    ):
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    allowed_roles = {
        "admin",
        "analyst",
        "viewer",
    }

    if role not in allowed_roles:
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    # Only the Owner can promote someone to Admin.
    if (
        role == "admin"
        and current_membership.role != "owner"
    ):
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    old_role = membership.role

    membership.role = role

    audit_event = AuditEvent(
        organization_id=current_organization.id,
        user_id=current_user.id,
        event_type="team_role_changed",
        description=(
            f"{current_user.name} changed "
            f"{membership.user.name}'s role from "
            f"{old_role.title()} to {role.title()}."
        ),
        metadata_json=json.dumps(
            {
                "membership_id": membership.id,
                "user_id": membership.user_id,
                "old_role": old_role,
                "new_role": role,
            }
        ),
    )

    db.add(audit_event)
    db.commit()

    set_team_message(
        request,
        "Team member role updated.",
    )

    return RedirectResponse(
        url="/team",
        status_code=303,
    )

@router.post(
    "/team/{membership_id}/remove"
)
def remove_team_member(
    membership_id: int,
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

    if current_membership.role not in {
        "owner",
        "admin",
    }:
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    membership = (
        db.query(Membership)
        .filter(
            Membership.id == membership_id,
            Membership.organization_id
            == current_organization.id,
        )
        .first()
    )

    if membership is None:
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    # Never remove the Owner here.
    if membership.role == "owner":
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    # Prevent removing your own membership.
    if membership.user_id == current_user.id:
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    # Admins cannot remove other admins.
    if (
        current_membership.role == "admin"
        and membership.role == "admin"
    ):
        return RedirectResponse(
            url="/team",
            status_code=303,
        )

    membership.is_active = False

    audit_event = AuditEvent(
        organization_id=current_organization.id,
        user_id=current_user.id,
        event_type="team_access_removed",
        description=(
            f"{current_user.name} removed "
            f"{membership.user.name}'s access."
        ),
        metadata_json=json.dumps(
            {
                "membership_id": membership.id,
                "user_id": membership.user_id,
                "email": membership.user.email,
                "role": membership.role,
            }
        ),
    )

    db.add(audit_event)
    db.commit()

    set_team_message(
        request,
        "Team member access removed.",
    )

    return RedirectResponse(
        url="/team",
        status_code=303,
    )