"""
Text message checks.

People paste a text message (SMS, Teams or Slack chat). PreClear checks
its wording for scam stories and every link in it, without visiting any
link. The message itself is read but never stored: the record keeps only
a short description, the links found and the warning signs.
"""
from __future__ import annotations

import hashlib
import json
import re

from app.services.link_analysis import (
    BRAND_DOMAINS,
    InvalidLinkError,
    analyze_link,
)
from app.services.coverage import (
    DONE,
    NOT_NEEDED,
    budget_reputation_check,
    check,
)
from app.services.message_wording import find_signals, is_urgent


MAX_TEXT_CHARS = 5000

MAX_LINKS = 10

# VirusTotal's free tier allows only a few lookups a minute.
MAX_REPUTATION_LOOKUPS = 3

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

DECISION_FOR_RISK = {
    "LOW": "LOOKS_SAFE",
    "MEDIUM": "USE_CAUTION",
    "HIGH": "DO_NOT_OPEN",
}

# Full addresses, "www." addresses, and bare domains with a path, which
# texts often use (ez-tollpay.com/pay).
LINK_PATTERN = re.compile(
    r"(?:https?://[^\s<>\"']+)"
    r"|(?:www\.[^\s<>\"']+)"
    r"|(?:\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,24}"
    r"(?:/[^\s<>\"']*)?)",
    re.IGNORECASE,
)

# Bare words that look like domains but are usually just text.
NOT_LINKS = re.compile(r"^(?:e\.g|i\.e|etc|a\.m|p\.m|u\.s|mr|mrs|dr)\b", re.I)


class InvalidTextError(ValueError):
    """The message was empty or too long."""


class _Assessment:
    def __init__(self) -> None:
        self.risk_level = "LOW"
        self.reasons: list[str] = []

    def flag(self, risk_level: str, reason: str) -> None:
        if RISK_ORDER[risk_level] > RISK_ORDER[self.risk_level]:
            self.risk_level = risk_level
        self.reasons.append(reason)

    def note(self, reason: str) -> None:
        self.reasons.append(reason)

    def raise_to(self, risk_level: str) -> None:
        if RISK_ORDER[risk_level] > RISK_ORDER[self.risk_level]:
            self.risk_level = risk_level

    @property
    def decision(self) -> str:
        return DECISION_FOR_RISK[self.risk_level]


def find_links(text: str) -> list[str]:
    links = []

    for match in LINK_PATTERN.finditer(text):
        candidate = match.group(0).rstrip(".,;:!?)]}'\"")

        if NOT_LINKS.match(candidate):
            continue

        # A bare word with a dot but no path, such as "file.pdf" or a
        # version number, is only treated as a link if it has letters on
        # both sides of the last dot and isn't a common file name.
        if not re.match(r"^(?:https?://|www\.)", candidate, re.I):
            host = candidate.split("/")[0]
            if re.search(r"\.(?:pdf|docx?|xlsx?|jpe?g|png|txt|csv|zip)$", host, re.I):
                continue

        if candidate.lower() not in (link.lower() for link in links):
            links.append(candidate)

    return links[:MAX_LINKS]


def _recognized(details: dict) -> str | None:
    """
    Returns a reason if a link goes somewhere PreClear recognizes as a
    company's own site: the organization's trusted domains or a known
    brand's official domain.
    """
    target = details.get("inner") or details

    if target.get("trusted"):
        return "trusted"

    registered = target.get("registered_domain") or ""
    for domains in BRAND_DOMAINS.values():
        if registered in domains:
            return "brand"

    return None


def _describe(links: list[dict]) -> str:
    hosts = [item["host"] for item in links if item.get("host")]

    if not hosts:
        return "Text message with no links"

    if len(hosts) == 1:
        return f"Text message with a link to {hosts[0]}"

    return f"Text message with links to {hosts[0]} and {len(hosts) - 1} more"


def analyze_text(message: str, trusted=None) -> dict:
    """
    Checks a pasted text message. Blocking (link reputation lookups), so
    call it from a worker thread. The message isn't included in the
    result.
    """
    text = (message or "").strip()

    if not text:
        raise InvalidTextError("empty")

    if len(text) > MAX_TEXT_CHARS:
        raise InvalidTextError("too_long")

    assessment = _Assessment()
    details: dict = {}

    signals = find_signals(text)
    details["signals"] = [signal.key for signal in signals]

    # Links, each checked without being visited.
    link_items = []
    lookups = MAX_REPUTATION_LOOKUPS

    for link in find_links(text):
        try:
            result = analyze_link(
                link,
                check_reputation=lookups > 0,
                trusted=trusted,
            )
        except InvalidLinkError:
            continue

        lookups -= 1

        link_details = result["details"]
        host = (link_details.get("inner") or link_details).get("host", "")

        link_items.append({
            "url": result["target"][:2048],
            "host": host,
            "risk_level": result["risk_level"],
            "decision": result["decision"],
            "recognized": _recognized(link_details),
            "reasons": result["reasons"],
        })

    # Wording first: what the message asks for.
    for signal in signals:
        assessment.flag("HIGH" if signal.serious else "MEDIUM", signal.reason)

    keys = set(details["signals"])
    story_keys = keys - {"boss_favor"}

    if "gift_cards" in keys and "boss_favor" in keys:
        assessment.flag(
            "HIGH",
            "A private, urgent favor involving gift cards is one of the most "
            "common scams aimed at employees. Confirm with the person "
            "directly, by phone or in person.",
        )

    unrecognized = [item for item in link_items if not item["recognized"]]

    # A scam story plus a link to a site PreClear doesn't recognize as the
    # company's own is the classic text scam: real carriers, toll agencies
    # and banks rarely text such links.
    if story_keys and unrecognized:
        hosts = ", ".join(item["host"] for item in unrecognized[:2])
        assessment.flag(
            "HIGH",
            f"The message tells a story meant to make you act, and links to "
            f"{hosts}, which PreClear doesn't recognize as the company's own "
            "website. This combination is how most text scams work.",
        )

    # A trusted company named in the text, linking somewhere else.
    if trusted and unrecognized:
        lowered = text.lower()
        for entry in trusted.entries:
            label = entry.label.lower()
            if len(label) >= 4 and re.search(
                rf"(?<![a-z0-9]){re.escape(label)}(?![a-z0-9])", lowered
            ):
                assessment.flag(
                    "HIGH",
                    f"The message mentions {entry.label}, but its link goes "
                    f"to {unrecognized[0]['host']}, not {entry.domain}.",
                )
                break

    # Each link's own findings.
    for item in link_items:
        if item["risk_level"] != "LOW":
            assessment.raise_to(item["risk_level"])
            for reason in [
                r for r in item["reasons"]
                if not r.startswith("The link does not use an encrypted")
            ][:2]:
                assessment.reasons.append(f"Link to {item['host']}: {reason}")
        elif item["recognized"] == "trusted":
            assessment.note(
                f"The link to {item['host']} goes to a domain your "
                "organization trusts."
            )

    if signals and is_urgent(text):
        assessment.note(
            "The message also pushes you to act quickly. Pressure plus a "
            "request is the pattern behind most scams."
        )

    details["checks"] = [
        check(
            "Wording",
            DONE,
            "Checked what the message asks for against common scams.",
        ),
        (
            check(
                "Links",
                DONE,
                f"Checked {len(link_items)} link"
                f"{'' if len(link_items) == 1 else 's'} without visiting "
                f"{'it' if len(link_items) == 1 else 'them'}.",
            )
            if link_items
            else check("Links", NOT_NEEDED, "The message has no links.")
        ),
        (
            check(
                "Your trusted domains",
                DONE,
                "Compared the links and names with your trusted domains.",
            )
            if trusted
            else check(
                "Your trusted domains",
                NOT_NEEDED,
                "Your organization hasn't listed trusted domains yet.",
            )
        ),
        budget_reputation_check(
            len({item["host"] for item in link_items if item.get("host")}),
            MAX_REPUTATION_LOOKUPS,
        ),
    ]

    if link_items:
        details["links"] = [
            {key: item[key] for key in ("url", "host", "risk_level", "decision")}
            for item in link_items
        ]

    if not assessment.reasons:
        if link_items:
            assessment.note(
                f"PreClear checked {len(link_items)} link"
                f"{'' if len(link_items) == 1 else 's'} without visiting "
                f"{'it' if len(link_items) == 1 else 'them'} and found no "
                "warning signs, and the wording doesn't match common scams."
            )
        else:
            assessment.note(
                "The wording doesn't match common scams, and the message "
                "has no links."
            )

    decision = assessment.decision

    if decision == "LOOKS_SAFE":
        explanation = (
            "PreClear did not find warning signs in this message. If you "
            "weren't expecting it, or it asks you to act, check with the "
            "sender another way first."
        )
    elif decision == "USE_CAUTION":
        explanation = (
            "This message has characteristics that deserve verification "
            "before you act on it. Contact the sender using a phone number "
            "or address you already have, not one in the message."
        )
    else:
        explanation = (
            "This message shows strong signs of a scam. Don't tap its "
            "links, reply, or do what it asks. If it claims to be from "
            "someone you know, contact them another way."
        )

    label = _describe(link_items)

    return {
        "filename": label,
        "extension": None,
        "mime_type": None,
        "file_size": len(text.encode("utf-8")),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "target": label,
        "details": details,
        "details_json": json.dumps(details),
        "risk_level": assessment.risk_level,
        "virustotal": {"available": False, "found": False, "error": "not_applicable"},
        "decision": decision,
        "explanation": explanation,
        "reasons": assessment.reasons,
    }
