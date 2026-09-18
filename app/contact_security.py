from collections import defaultdict, deque
from threading import Lock
from time import monotonic

from fastapi import Request
import requests


CONTACT_RATE_LIMIT = 3
CONTACT_RATE_WINDOW_SECONDS = 600


_submission_times: dict[
    str,
    deque[float],
] = defaultdict(deque)

_submission_lock = Lock()


def get_request_ip(
    request: Request,
) -> str:
    forwarded_for = request.headers.get(
        "x-forwarded-for",
        "",
    )

    if forwarded_for:
        return (
            forwarded_for
            .split(",")[0]
            .strip()
        )

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

def verify_turnstile(
    token: str,
    secret_key: str,
    remote_ip: str | None = None,
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

        return bool(
            result.get("success")
        )

    except (
        requests.RequestException,
        ValueError,
    ):
        return False