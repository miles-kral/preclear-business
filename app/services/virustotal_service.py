from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta, timezone

import requests
from sqlalchemy.exc import SQLAlchemyError

from app.config import VIRUSTOTAL_API_KEY


logger = logging.getLogger("uvicorn.error")

# How long a VirusTotal answer is reused before asking again. Results for
# known items change slowly; "not found yet" is rechecked sooner because
# new threats get added. Errors are never cached.
CACHE_TTL_FOUND = timedelta(hours=24)
CACHE_TTL_NOT_FOUND = timedelta(hours=6)

# Cached rows older than this are deleted.
CACHE_MAX_AGE = timedelta(days=7)


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


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _cached_report(
    kind: str,
    key: str,
    url: str,
) -> dict:
    """
    Returns a recent cached result for this file or host if there is one,
    otherwise asks VirusTotal and caches the answer. The cache is only an
    optimization: if it can't be read or written, the lookup still works.
    """
    # Imported here so this module has no import-time database dependency.
    from app.database import SessionLocal
    from app.models import ReputationCache

    now = datetime.now(timezone.utc)

    try:
        with SessionLocal() as db:
            row = (
                db.query(ReputationCache)
                .filter(
                    ReputationCache.kind == kind,
                    ReputationCache.lookup_key == key,
                )
                .first()
            )

            if row is not None:
                cached = json.loads(row.result_json)
                ttl = (
                    CACHE_TTL_FOUND
                    if cached.get("found")
                    else CACHE_TTL_NOT_FOUND
                )
                if now - _as_utc(row.fetched_at) < ttl:
                    cached["cached"] = True
                    return cached

    except (SQLAlchemyError, ValueError) as error:
        logger.warning("Reputation cache read failed: %s", error)

    result = _get_report(url)

    # Only real answers are cached; outages and rate limits are not.
    if not result.get("available"):
        return result

    try:
        with SessionLocal() as db:
            row = (
                db.query(ReputationCache)
                .filter(
                    ReputationCache.kind == kind,
                    ReputationCache.lookup_key == key,
                )
                .first()
            )

            if row is None:
                row = ReputationCache(kind=kind, lookup_key=key)
                db.add(row)

            row.result_json = json.dumps(result)
            row.fetched_at = now

            db.query(ReputationCache).filter(
                ReputationCache.fetched_at < now - CACHE_MAX_AGE
            ).delete(synchronize_session=False)

            db.commit()

    except SQLAlchemyError as error:
        # Another request may have cached the same item at the same
        # moment; either way the lookup result is still returned.
        logger.warning("Reputation cache write failed: %s", error)

    return result


def lookup_file_hash(
    sha256: str,
) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", sha256 or ""):
        return {
            "available": False,
            "found": False,
            "error": "invalid_hash",
        }

    if not VIRUSTOTAL_API_KEY:
        return {
            "available": False,
            "found": False,
            "error": "not_configured",
        }

    return _cached_report(
        "file",
        sha256,
        f"{VIRUSTOTAL_API_URL}/{sha256}",
    )


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

    if not VIRUSTOTAL_API_KEY:
        return {
            "available": False,
            "found": False,
            "error": "not_configured",
        }

    if ip is not None:
        return _cached_report(
            "host",
            str(ip),
            f"{VIRUSTOTAL_API_BASE}/ip_addresses/{ip}",
        )

    if not HOSTNAME_PATTERN.match(host):
        return {
            "available": False,
            "found": False,
            "error": "invalid_host",
        }

    return _cached_report(
        "host",
        host,
        f"{VIRUSTOTAL_API_BASE}/domains/{host}",
    )
