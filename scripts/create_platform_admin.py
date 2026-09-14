from getpass import getpass

from sqlalchemy import select

from app.auth import hash_password
from app.database import SessionLocal
from app.models import Membership, Organization, User


INTERNAL_ORG_NAME = "PreClear Internal"
INTERNAL_ORG_SLUG = "preclear-internal"


def main() -> None:
    db = SessionLocal()

    try:
        name = input(
            "Admin name: "
        ).strip()

        email = input(
            "Admin email: "
        ).strip().lower()

        password = getpass(
            "Admin password: "
        )

        password_confirm = getpass(
            "Confirm password: "
        )

        if not name:
            raise ValueError(
                "Name is required."
            )

        if not email:
            raise ValueError(
                "Email is required."
            )

        if password != password_confirm:
            raise ValueError(
                "Passwords do not match."
            )

        if len(password) < 10:
            raise ValueError(
                "Password must be at least "
                "10 characters."
            )


        organization = db.scalar(
            select(Organization).where(
                Organization.slug
                == INTERNAL_ORG_SLUG
            )
        )

        if organization is None:
            organization = Organization(
                name=INTERNAL_ORG_NAME,
                slug=INTERNAL_ORG_SLUG,
                plan="small_business",
                subscription_status="internal",
                is_active=True,
            )

            db.add(
                organization
            )

            db.flush()

            print(
                "Created PreClear Internal "
                "organization."
            )

        else:
            organization.subscription_status = (
                "internal"
            )

            organization.is_active = True


        user = db.scalar(
            select(User).where(
                User.email == email
            )
        )

        if user is None:
            user = User(
                name=name,
                email=email,
                password_hash=hash_password(
                    password
                ),
                is_active=True,
                is_verified=True,
            )

            db.add(
                user
            )

            db.flush()

            print(
                "Created platform admin user."
            )

        else:
            user.name = name
            user.password_hash = (
                hash_password(
                    password
                )
            )
            user.is_active = True

            print(
                "Updated existing user."
            )


        membership = db.scalar(
            select(Membership).where(
                Membership.user_id
                == user.id,
                Membership.organization_id
                == organization.id,
            )
        )

        if membership is None:
            membership = Membership(
                user_id=user.id,
                organization_id=organization.id,
                role="owner",
                is_active=True,
            )

            db.add(
                membership
            )

            print(
                "Created owner membership."
            )

        else:
            membership.role = "owner"
            membership.is_active = True


        db.commit()

        print()
        print(
            "Platform admin provisioning complete."
        )
        print(
            f"Email: {email}"
        )
        print(
            f"Organization: {organization.name}"
        )

    finally:
        db.close()


if __name__ == "__main__":
    main()