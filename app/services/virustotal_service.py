from __future__ import annotations

import requests

from app.config import VIRUSTOTAL_API_KEY


VIRUSTOTAL_API_URL = (
    "https://www.virustotal.com/api/v3/files"
)


def lookup_file_hash(
    sha256: str,
) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {
            "available": False,
            "found": False,
            "error": "not_configured",
        }

    try:
        response = requests.get(
            f"{VIRUSTOTAL_API_URL}/{sha256}",
            headers={
                "x-apikey": VIRUSTOTAL_API_KEY,
            },
            timeout=10,
        )

    except requests.RequestException:
        return {
            "available": False,
            "found": False,
            "error": "request_failed",
        }

    if response.status_code == 404:
        return {
            "available": True,
            "found": False,
            "error": None,
        }

    if response.status_code != 200:
        return {
            "available": False,
            "found": False,
            "error": (
                f"http_{response.status_code}"
            ),
        }

    try:
        payload = response.json()

        attributes = (
            payload
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {},
        )

        return {
            "available": True,
            "found": True,
            "error": None,
            "malicious": int(
                stats.get("malicious", 0)
            ),
            "suspicious": int(
                stats.get("suspicious", 0)
            ),
            "undetected": int(
                stats.get("undetected", 0)
            ),
            "harmless": int(
                stats.get("harmless", 0)
            ),
            "timeout": int(
                stats.get("timeout", 0)
            ),
        }

    except (
        ValueError,
        TypeError,
        AttributeError,
    ):
        return {
            "available": False,
            "found": False,
            "error": "invalid_response",
        }