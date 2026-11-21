from __future__ import annotations

import ipaddress
import re

import requests

from app.config import VIRUSTOTAL_API_KEY


VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"

VIRUSTOTAL_API_URL = f"{VIRUSTOTAL_API_BASE}/files"

# Hostnames are checked against this before being placed in a request
# path, so nothing unexpected can be sent to VirusTotal.
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def _get_report(url: str) -> dict:
    """
    Fetches an existing VirusTotal report. This only reads VirusTotal's
    stored results; it never asks VirusTotal to visit or scan anything.
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            "available": False,
            "found": False,
            "error": "not_configured",
        }

    try:
        response = requests.get(
            url,
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
            "error": f"http_{response.status_code}",
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
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "timeout": int(stats.get("timeout", 0)),
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


def lookup_file_hash(
    sha256: str,
) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", sha256 or ""):
        return {
            "available": False,
            "found": False,
            "error": "invalid_hash",
        }

    return _get_report(f"{VIRUSTOTAL_API_URL}/{sha256}")


def lookup_host(
    host: str,
) -> dict:
    """
    Looks up the reputation of a domain or IP address. Only the host name
    is sent, never the full link, so tokens or personal details in a URL
    stay private.
    """
    host = (host or "").strip().lower().rstrip(".")

    try:
        ip = ipaddress.ip_address(host)

    except ValueError:
        ip = None

    if ip is not None:
        return _get_report(f"{VIRUSTOTAL_API_BASE}/ip_addresses/{ip}")

    if not HOSTNAME_PATTERN.match(host):
        return {
            "available": False,
            "found": False,
            "error": "invalid_host",
        }

    return _get_report(f"{VIRUSTOTAL_API_BASE}/domains/{host}")