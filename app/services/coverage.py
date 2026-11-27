"""
"What was checked": each result lists its checks and how far each one got,
so a partial result (no reputation lookup, a long PDF, a missing header)
is visible instead of looking like a clean bill of health.
"""
from __future__ import annotations

DONE = "done"
NOT_NEEDED = "not_needed"
LIMITED = "limited"
UNAVAILABLE = "unavailable"

STATUS_LABELS = {
    DONE: "Done",
    NOT_NEEDED: "Not needed",
    LIMITED: "Limited",
    UNAVAILABLE: "Unavailable",
}


def check(name: str, status: str, note: str) -> dict:
    return {"name": name, "status": status, "note": note}


def reputation_available() -> bool:
    from app.services import virustotal_service

    return bool(virustotal_service.VIRUSTOTAL_API_KEY)


def reputation_check(vt_result: dict | None, subject: str) -> dict:
    """Describes a single VirusTotal lookup for a file or a link's domain."""
    vt_result = vt_result or {}
    error = vt_result.get("error")

    if vt_result.get("available") and vt_result.get("found"):
        return check(
            "Threat intelligence",
            DONE,
            f"VirusTotal has a record of this {subject}.",
        )

    if vt_result.get("available"):
        return check(
            "Threat intelligence",
            DONE,
            f"VirusTotal has no record of this {subject} yet.",
        )

    if error == "not_configured":
        return check(
            "Threat intelligence",
            UNAVAILABLE,
            "Reputation lookups aren't set up for this platform.",
        )

    if error == "skipped":
        return check(
            "Threat intelligence",
            LIMITED,
            "Skipped to stay within the lookup limit.",
        )

    return check(
        "Threat intelligence",
        UNAVAILABLE,
        "VirusTotal couldn't be reached, so the reputation check was "
        "skipped. All other checks ran.",
    )


def budget_reputation_check(items: int, budget: int) -> dict:
    """Describes reputation lookups shared across an email's or a text's
    links and attachments, which are capped per item."""
    if not reputation_available():
        return check(
            "Threat intelligence",
            UNAVAILABLE,
            "Reputation lookups aren't set up for this platform.",
        )

    if items == 0:
        return check(
            "Threat intelligence",
            NOT_NEEDED,
            "Nothing to look up.",
        )

    if items > budget:
        return check(
            "Threat intelligence",
            LIMITED,
            f"Looked up the {budget} most suspicious of {items} items, to "
            "stay within the lookup limit.",
        )

    return check(
        "Threat intelligence",
        DONE,
        f"Looked up {items} item{'' if items == 1 else 's'}.",
    )


def summarize(checks: list[dict]) -> str:
    incomplete = [
        item for item in checks
        if item["status"] in {LIMITED, UNAVAILABLE}
    ]

    if not incomplete:
        return "All checks completed."

    completed = len(checks) - len(incomplete)
    return (
        f"Partial check: {completed} of {len(checks)} checks completed "
        "fully. The decision is based on what could be checked."
    )
