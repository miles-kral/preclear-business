from __future__ import annotations

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session
from fastapi.responses import RedirectResponse

from app.database import get_db
from app.models import Membership, Organization, User


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User | None:
    user_id = request.session.get("user_id")

    if not user_id:
        return None

    return db.get(
        User,
        user_id,
    )


def get_current_organization(
    request: Request,
    db: Session = Depends(get_db),
) -> Organization | None:
    organization_id = request.session.get(
        "organization_id"
    )

    if not organization_id:
        return None

    return db.get(
        Organization,
        organization_id,
    )


def get_current_membership(
    request: Request,
    db: Session = Depends(get_db),
) -> Membership | None:
    user_id = request.session.get("user_id")
    organization_id = request.session.get(
        "organization_id"
    )

    if not user_id or not organization_id:
        return None

    return db.scalar(
        select(Membership).where(
            Membership.user_id == user_id,
            Membership.organization_id
            == organization_id,
            Membership.is_active.is_(True),
        )
    )

def has_role(
    membership: Membership | None,
    allowed_roles: set[str],
) -> bool:
    return (
        membership is not None
        and membership.is_active
        and membership.role in allowed_roles
    )


def can_manage_organization(
    membership: Membership | None,
) -> bool:
    return has_role(
        membership,
        {
            "owner",
            "admin",
        },
    )


def can_analyze(
    membership: Membership | None,
) -> bool:
    return has_role(
        membership,
        {
            "owner",
            "admin",
            "analyst",
        },
    )


def can_review_evidence(
    membership: Membership | None,
) -> bool:
    return has_role(
        membership,
        {
            "owner",
            "admin",
            "analyst",
        },
    )


def can_view_organization(
    membership: Membership | None,
) -> bool:
    return has_role(
        membership,
        {
            "owner",
            "admin",
            "analyst",
            "viewer",
        },
    )