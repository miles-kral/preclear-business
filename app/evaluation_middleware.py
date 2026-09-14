from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse

from app.database import SessionLocal
from app.dependencies import is_platform_admin
from app.models import (
    EvaluationInvitation,
    Organization,
    User,
)


class EvaluationAccessMiddleware(
    BaseHTTPMiddleware
):
    async def dispatch(
        self,
        request,
        call_next,
    ):
        path = request.url.path

        allowed_paths = (
            "/static",
            "/login",
            "/logout",
            "/pricing",
            "/contact",
            "/evaluation/",
            "/billing/",
        )

        if path.startswith(
            allowed_paths
        ):
            return await call_next(
                request
            )

        user_id = request.session.get(
            "user_id"
        )

        organization_id = (
            request.session.get(
                "organization_id"
            )
        )

        if (
            not user_id
            or not organization_id
        ):
            return await call_next(
                request
            )

        db = SessionLocal()

        try:
            user = db.get(
                User,
                user_id,
            )

            organization = db.get(
                Organization,
                organization_id,
            )

            if (
                user is None
                or organization is None
            ):
                return await call_next(
                    request
                )

            if is_platform_admin(user):
                return await call_next(
                    request
                )

            if (
                organization
                .subscription_status
                != "evaluation"
            ):
                return await call_next(
                    request
                )

            evaluation = (
                db.query(
                    EvaluationInvitation
                )
                .filter(
                    EvaluationInvitation
                    .organization_id
                    == organization.id
                )
                .order_by(
                    EvaluationInvitation
                    .id.desc()
                )
                .first()
            )

            if (
                evaluation is None
                or evaluation
                .evaluation_expires_at
                is None
            ):
                return RedirectResponse(
                    url="/evaluation/expired",
                    status_code=303,
                )

            if evaluation.status == "revoked":
                return RedirectResponse(
                    url="/evaluation/expired",
                    status_code=303,
                )

            expires_at = (
                evaluation
                .evaluation_expires_at
            )

            if expires_at.tzinfo is None:
                expires_at = (
                    expires_at.replace(
                        tzinfo=timezone.utc
                    )
                )

            if (
                expires_at
                <= datetime.now(
                    timezone.utc
                )
            ):
                if (
                    evaluation.status
                    != "expired"
                ):
                    evaluation.status = (
                        "expired"
                    )
                    db.commit()

                return RedirectResponse(
                    url="/evaluation/expired",
                    status_code=303,
                )

        finally:
            db.close()

        return await call_next(
            request
        )