from collections import defaultdict, deque
from threading import Lock
from time import monotonic

from fastapi import Request
import requests
import logging
from app import config


CONTACT_RATE_LIMIT = 3
CONTACT_RATE_WINDOW_SECONDS = 600

PASSWORD_RESET_RATE_LIMIT = 3
PASSWORD_RESET_RATE_WINDOW_SECONDS = 900

LOGIN_RATE_LIMIT = 10
LOGIN_RATE_WINDOW_SECONDS = 900

_password_reset_times: dict[
    str,
    deque[float],
] = defaultdict(deque)

_password_reset_lock = Lock()

_login_attempt_times: dict[
    str,
    deque[float],
] = defaultdict(deque)

_login_attempt_lock = Lock()

_submission_times: dict[
    str,
    deque[float],
] = defaultdict(deque)

_submission_lock = Lock()

logger = logging.getLogger(
    "uvicorn.error"
)


def get_request_ip(
    request: Request,
) -> str:
    if config.IS_PRODUCTION:
        cf_connecting_ip = (
            request.headers.get(
                "cf-connecting-ip",
                "",
            )
            .strip()
        )

        if cf_connecting_ip:
            return cf_connecting_ip

    if request.client:
        return request.client.host

    return "unknown"


def contact_rate_limit_exceeded(
    request: Request,
) -> bool:
    client_ip = get_request_ip(
        request
    )

    now = monotonic()

    cutoff = (
        now
        - CONTACT_RATE_WINDOW_SECONDS
    )

    with _submission_lock:
        timestamps = (
            _submission_times[
                client_ip
            ]
        )

        while (
            timestamps
            and timestamps[0] < cutoff
        ):
            timestamps.popleft()

        if (
            len(timestamps)
            >= CONTACT_RATE_LIMIT
        ):
            return True

        timestamps.append(now)

    return False

def password_reset_rate_limit_exceeded(
    request: Request,
) -> bool:
    client_ip = get_request_ip(
        request
    )

    now = monotonic()
    cutoff = (
        now
        - PASSWORD_RESET_RATE_WINDOW_SECONDS
    )

    with _password_reset_lock:
        timestamps = _password_reset_times[
            client_ip
        ]

        while (
            timestamps
            and timestamps[0] < cutoff
        ):
            timestamps.popleft()

        if (
            len(timestamps)
            >= PASSWORD_RESET_RATE_LIMIT
        ):
            return True

        timestamps.append(now)

    return False

def login_rate_limit_exceeded(
    request: Request,
) -> bool:
    client_ip = get_request_ip(
        request
    )

    now = monotonic()
    cutoff = (
        now
        - LOGIN_RATE_WINDOW_SECONDS
    )

    with _login_attempt_lock:
        timestamps = _login_attempt_times[
            client_ip
        ]

        while (
            timestamps
            and timestamps[0] < cutoff
        ):
            timestamps.popleft()

        return (
            len(timestamps)
            >= LOGIN_RATE_LIMIT
        )


def record_failed_login_attempt(
    request: Request,
) -> None:
    client_ip = get_request_ip(
        request
    )

    now = monotonic()
    cutoff = (
        now
        - LOGIN_RATE_WINDOW_SECONDS
    )

    with _login_attempt_lock:
        timestamps = _login_attempt_times[
            client_ip
        ]

        while (
            timestamps
            and timestamps[0] < cutoff
        ):
            timestamps.popleft()

        timestamps.append(now)


def clear_failed_login_attempts(
    request: Request,
) -> None:
    client_ip = get_request_ip(
        request
    )

    with _login_attempt_lock:
        _login_attempt_times.pop(
            client_ip,
            None,
        )

def verify_turnstile(
    token: str,
    secret_key: str,
    remote_ip: str | None = None,
    expected_action: str | None = None,
    allowed_hostnames: set[str] | None = None,
) -> bool:
    if not secret_key:
        return True

    if not token:
        return False

    payload = {
        "secret": secret_key,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=payload,
            timeout=5,
        )

        response.raise_for_status()

        result = response.json()

        if not result.get("success"):
            return False

        action = (
            str(result.get("action") or "")
            .strip()
        )

        hostname = (
            str(result.get("hostname") or "")
            .strip()
            .lower()
        )

        using_test_key = (
            secret_key.startswith("1x")
            or secret_key.startswith("2x")
            or secret_key.startswith("3x")
        )

        if (
            expected_action
            and not using_test_key
            and action != expected_action
        ):
            return False

        if (
            allowed_hostnames
            and not using_test_key
            and hostname not in allowed_hostnames
        ):
            return False

        return True

    except (
        requests.RequestException,
        ValueError,
    ):
        return False

def log_contact_security_event(
    request: Request,
    event: str,
    *,
    blocked: bool = True,
) -> None:
    client_ip = get_request_ip(
        request
    )

    user_agent = (
        request.headers.get(
            "user-agent",
            "unknown",
        )
        .strip()
    )

    if len(user_agent) > 180:
        user_agent = (
            user_agent[:180]
            + "..."
        )

    log_method = (
        logger.warning
        if blocked
        else logger.info
    )

    log_method(
        "CONTACT_SECURITY event=%s ip=%s user_agent=%r",
        event,
        client_ip,
        user_agent,
    )