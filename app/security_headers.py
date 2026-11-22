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
            "Content-Security-Policy"
        ] = (
            "default-src 'self'; "
            "script-src 'self' "
            "https://challenges.cloudflare.com "
            "https://plausible.io; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self' "
            "https://challenges.cloudflare.com "
            "https://plausible.io; "
            "frame-src "
            "https://challenges.cloudflare.com; "
            "object-src 'none'; "
            "base-uri 'self'; "
            # Checkout and billing buttons post to PreClear, which then
            # redirects to Stripe. Browsers apply form-action to that
            # redirect too, so Stripe's checkout and billing portal
            # must be listed or the buttons silently do nothing.
            "form-action 'self' "
            "https://checkout.stripe.com "
            "https://billing.stripe.com; "
            "frame-ancestors 'none'"
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