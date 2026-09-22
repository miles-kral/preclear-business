from urllib.parse import urlsplit
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from app import config


logger = logging.getLogger(
    "uvicorn.error"
)


SAFE_METHODS = {
    "GET",
    "HEAD",
    "OPTIONS",
    "TRACE",
}


CSRF_EXEMPT_PATHS = {
    "/billing/webhook",
}


def _url_origin(
    value: str,
) -> str:
    parsed = urlsplit(
        value
    )

    if (
        not parsed.scheme
        or not parsed.netloc
    ):
        return ""

    return (
        f"{parsed.scheme.lower()}://"
        f"{parsed.netloc.lower()}"
    )


def _expected_origin(
    request: Request,
) -> str:
    host = (
        request.headers.get(
            "host",
            "",
        )
        .strip()
        .lower()
    )

    if not host:
        return ""

    scheme = (
        "https"
        if config.IS_PRODUCTION
        else request.url.scheme
    )

    return (
        f"{scheme}://{host}"
    )


class CSRFMiddleware(
    BaseHTTPMiddleware
):
    async def dispatch(
        self,
        request: Request,
        call_next,
    ):
        method = (
            request.method.upper()
        )

        if (
            method in SAFE_METHODS
            or request.url.path
            in CSRF_EXEMPT_PATHS
        ):
            return await call_next(
                request
            )

        expected_origin = (
            _expected_origin(
                request
            )
        )

        origin = (
            request.headers.get(
                "origin",
                "",
            )
            .strip()
        )

        if origin:
            supplied_origin = (
                _url_origin(
                    origin
                )
            )

        else:
            referer = (
                request.headers.get(
                    "referer",
                    "",
                )
                .strip()
            )

            supplied_origin = (
                _url_origin(
                    referer
                )
                if referer
                else ""
            )

        if (
            not expected_origin
            or not supplied_origin
            or supplied_origin
            != expected_origin
        ):
            logger.warning(
                "CSRF blocked method=%s "
                "path=%s origin=%r "
                "expected_origin=%r",
                method,
                request.url.path,
                supplied_origin,
                expected_origin,
            )

            return PlainTextResponse(
                "Request could not be verified.",
                status_code=403,
            )

        return await call_next(
            request
        )