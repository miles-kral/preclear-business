from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app import config


class SecurityHeadersMiddleware(
    BaseHTTPMiddleware
):
    async def dispatch(
        self,
        request: Request,
        call_next,
    ):
        response = await call_next(
            request
        )

        response.headers[
            "X-Content-Type-Options"
        ] = "nosniff"

        response.headers[
            "Referrer-Policy"
        ] = (
            "strict-origin-when-cross-origin"
        )

        response.headers[
            "X-Frame-Options"
        ] = "DENY"

        response.headers[
            "Permissions-Policy"
        ] = (
            "camera=(), "
            "microphone=(), "
            "geolocation=()"
        )

        if config.IS_PRODUCTION:
            response.headers[
                "Strict-Transport-Security"
            ] = (
                "max-age=31536000; "
                "includeSubDomains"
            )

        return response