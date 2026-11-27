"""
Email analysis for messages saved as .eml files.

PreClear reads the saved message and never connects to a mailbox. It
checks who the email is really from, what the receiving mail server
recorded about the sender, what the message asks the reader to do, every
link (without visiting any of them) and every attachment (with the file
scanner). The email's body text is read for the analysis but not stored.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser

from app.services.analysis_service import analyze_file
from app.services.coverage import (
    DONE,
    LIMITED,
    NOT_NEEDED,
    budget_reputation_check,
    check,
)
from app.services.message_wording import find_signals, is_urgent
from app.services.qr_analysis import analyze_qr_in_file
from app.services.link_analysis import (
    ACCOUNT_WORDS,
    BRAND_DISPLAY_NAMES,
    BRAND_DOMAINS,
    BRAND_KEYWORDS,
    InvalidLinkError,
    _EXTRACT,
    _decode_host,
    _edit_distance,
    _scripts_in,
    _skeleton,
    analyze_link,
    brand_mentioned,
)


# Limits that keep a hostile or enormous message from tying up the server.
MAX_MIME_PARTS = 200
MAX_BODY_CHARS = 2_000_000
MAX_LINKS_ANALYZED = 40
MAX_ATTACHMENTS_ANALYZED = 20

# VirusTotal's free tier allows only a few lookups a minute, so one email
# gets a small shared budget, spent on the most suspicious items first.
REPUTATION_LOOKUP_BUDGET = 4
MAX_ATTACHMENT_LOOKUPS = 2

MAX_LABEL_LENGTH = 255

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

DECISION_FOR_RISK = {
    "LOW": "LOOKS_SAFE",
    "MEDIUM": "USE_CAUTION",
    "HIGH": "DO_NOT_OPEN",
}

HEADER_NAMES = re.compile(
    rb"^(from|to|subject|date|received|message-id|mime-version|"
    rb"return-path|reply-to|content-type|delivered-to|"
    rb"authentication-results|x-[a-z0-9-]+):",
    re.IGNORECASE | re.MULTILINE,
)

FREE_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "yahoo.com", "ymail.com", "aol.com",
    "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com",
    "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com",
    "comcast.net", "att.net", "verizon.net",
}

URL_IN_TEXT = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'()\[\]{}]+",
    re.IGNORECASE,
)

LOOKS_LIKE_ADDRESS = re.compile(
    r"^(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[/?#]\S*)?$",
    re.IGNORECASE,
)

class InvalidEmailError(ValueError):
    """The upload could not be read as an email message."""


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


# ------------------------------------------------------------- detection

# Header names that show a block of text is an email's original source.
KNOWN_HEADERS = {
    "received", "from", "to", "cc", "subject", "date", "message-id",
    "mime-version", "return-path", "reply-to", "content-type",
    "delivered-to", "authentication-results", "dkim-signature",
    "arc-seal", "arc-message-signature", "arc-authentication-results",
    "received-spf", "sender", "x-received", "x-originating-ip",
    "x-ms-exchange-organization-authas", "thread-topic", "thread-index",
    "content-transfer-encoding", "x-mailer", "list-unsubscribe",
}

HEADER_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9-]*):")

# Largest saved web page searched for an email inside it.
MAX_SAVED_PAGE_BYTES = 30 * 1024 * 1024


def starts_with_headers(data: bytes) -> bool:
    """
    True when the text begins with mail headers: the first line is a
    header, and at least 3 known header names appear before the first
    blank line. An email is recognized by its headers, never by what its
    body looks like (most bodies are HTML).
    """
    text = data[:65536].decode("utf-8", "replace").lstrip("\ufeff \t\r\n")
    lines = text.splitlines()

    if not lines or not HEADER_LINE.match(lines[0]):
        return False

    found = set()

    for line in lines:
        if not line.strip():
            break
        if line[0] in " \t":
            continue  # a header continued on the next line
        match = HEADER_LINE.match(line)
        if not match:
            return False
        name = match.group(1).lower()
        if name in KNOWN_HEADERS or name.startswith("x-"):
            found.add(name)

    return len(found) >= 3


def email_from_saved_page(content: bytes) -> bytes | None:
    """
    When a browser saves an email's "Show original" page as a web page,
    the email sits escaped inside a <pre> block. Returns the email if the
    page holds one, otherwise None. Ordinary pages are left alone.
    """
    if len(content) > MAX_SAVED_PAGE_BYTES:
        return None

    head = content[:4096].lower()
    if b"<html" not in head and b"<!doctype" not in head and b"<pre" not in head:
        return None

    page = content.decode("utf-8", "replace")

    for match in re.finditer(r"<pre[^>]*>(.*?)</pre>", page, re.S | re.I):
        inner = html.unescape(re.sub(r"<[^>]+>", "", match.group(1)))
        candidate = inner.lstrip("\ufeff \t\r\n").encode("utf-8")
        if starts_with_headers(candidate):
            return candidate

    return None



def looks_like_email(filename: str, content: bytes) -> bool:
    """True for .eml uploads, or text files that are clearly raw email."""
    name = (filename or "").lower()

    if name.endswith(".eml"):
        return True

    if not (name.endswith(".txt") or "." not in name.rsplit("/", 1)[-1]):
        return False

    head = content[:8192]
    found = {
        match.group(1).lower()
        for match in HEADER_NAMES.finditer(head)
    }

    return (
        len(found) >= 4
        and bool(HEADER_NAMES.match(head.lstrip()))
        and (b"from" in found and (b"received" in found or b"message-id" in found))
    )


# --------------------------------------------------------------- parsing


class _LinkCollector(HTMLParser):
    """Collects links, forms and remote images from HTML without rendering it."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.form_actions: list[str] = []
        self.remote_images = 0
        self.has_script = False
        self.text_parts: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag in {"a", "area"} and attrs.get("href"):
            if tag == "area":
                self.links.append((attrs["href"].strip(), ""))
            else:
                self._href = attrs["href"].strip()
                self._text = []

        elif tag == "form":
            self.form_actions.append((attrs.get("action") or "").strip())

        elif tag == "img":
            src = (attrs.get("src") or "").strip().lower()
            if src.startswith(("http://", "https://", "//")):
                self.remote_images += 1

        elif tag == "script":
            self.has_script = True

        if tag in {"script", "style"}:
            self._skip_depth += 1

    def handle_data(self, data):
        if self._skip_depth:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self._skip_depth:
            self._skip_depth -= 1

        if tag == "a" and self._href is not None:
            text = " ".join("".join(self._text).split())
            self.links.append((self._href, text))
            self._href = None


def _part_text(part: EmailMessage) -> str:
    try:
        text = part.get_content()
        if isinstance(text, bytes):
            text = text.decode("utf-8", "replace")
    except (LookupError, ValueError, AssertionError):
        payload = part.get_payload(decode=True) or b""
        text = payload.decode("utf-8", "replace")

    return text[:MAX_BODY_CHARS]


def _address(header_value) -> tuple[str, str, str]:
    """Returns (display name, address, domain) for a header like From."""
    if not header_value:
        return "", "", ""

    pairs = getaddresses([str(header_value)])

    if not pairs:
        return "", "", ""

    name, address = pairs[0]
    address = address.strip().lower()
    domain = address.rsplit("@", 1)[-1] if "@" in address else ""

    return name.strip(), address, domain.rstrip(".>")


def _registered(domain: str) -> str:
    if not domain:
        return ""

    extracted = _EXTRACT(domain)

    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return domain


def _parse_authentication_results(message: EmailMessage) -> dict:
    """
    Reads the verdicts recorded by the receiving mail server. Only the
    topmost Authentication-Results header is used: it was added by the
    server that delivered the message, while lower ones could have been
    written by the sender.
    """
    headers = message.get_all("Authentication-Results") or []

    if not headers:
        return {}

    text = str(headers[0])
    results = {}

    for method in ("spf", "dkim", "dmarc", "compauth"):
        match = re.search(rf"\b{method}=([a-z]+)", text, re.IGNORECASE)
        if match:
            results[method] = match.group(1).lower()

    match = re.search(r"header\.from=([^\s;]+)", text, re.IGNORECASE)
    if match:
        results["header_from"] = match.group(1).lower()

    return results


# ------------------------------------------------------------------ checks


def _brand_imitation(domain: str) -> str | None:
    """Returns a brand name if the sending domain imitates it."""
    registered = _registered(domain)
    extracted = _EXTRACT(domain)
    name = _decode_host(extracted.domain or "")

    for brand, domains in BRAND_DOMAINS.items():
        if registered in domains or extracted.domain == brand:
            return None

    tokens = [token for token in re.split(r"[.\-_]", domain) if token]

    for keyword, brand in BRAND_KEYWORDS.items():
        if brand_mentioned(keyword, tokens):
            return BRAND_DISPLAY_NAMES[brand]

    skeleton = _skeleton(name)

    for brand in BRAND_DOMAINS:
        if len(brand) < 4:
            continue
        brand_skeleton = _skeleton(brand)
        if skeleton == brand_skeleton or (
            len(brand) >= 6
            and _edit_distance(skeleton, brand_skeleton) == 1
        ):
            return BRAND_DISPLAY_NAMES[brand]

    return None


def _check_sender(
    assessment: _Assessment,
    message: EmailMessage,
    details: dict,
) -> None:
    from_name, from_address, from_domain = _address(message.get("From"))
    _, reply_address, reply_domain = _address(message.get("Reply-To"))
    _, return_address, return_domain = _address(message.get("Return-Path"))

    details["from_name"] = from_name
    details["from_address"] = from_address
    details["reply_to"] = reply_address
    details["return_path"] = return_address

    if not from_address:
        assessment.flag(
            "MEDIUM",
            "The email has no readable sender address.",
        )
        return

    from_registered = _registered(from_domain)
    details["from_domain"] = from_registered

    if reply_address and _registered(reply_domain) != from_registered:
        assessment.flag(
            "MEDIUM",
            f"Replies would go to {reply_address}, not to the sender "
            f"({from_address}). Scammers use this so your answer reaches "
            "them instead of the person you think you're writing to.",
        )

    # A display name that contains a different email address, e.g.
    # "billing@vendor.com" <random@elsewhere.net>.
    shown = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", from_name)
    if shown and _registered(shown.group(1).lower()) != from_registered:
        assessment.flag(
            "HIGH",
            f"The sender's name shows the address {shown.group(0)}, but "
            f"the email was really sent from {from_address}.",
        )

    brand = _brand_imitation(from_domain)
    if brand:
        assessment.flag(
            "HIGH",
            f"The sending domain {from_registered} imitates {brand} but "
            f"is not a {brand} domain.",
        )

    name_tokens = set(re.split(r"[^a-z0-9]+", from_name.lower()))
    for keyword, brand_key in BRAND_KEYWORDS.items():
        official = (
            from_registered in BRAND_DOMAINS[brand_key]
            or _EXTRACT(from_domain).domain == brand_key
        )
        if brand_mentioned(keyword, name_tokens) and not official:
            name = BRAND_DISPLAY_NAMES[brand_key]
            assessment.flag(
                "MEDIUM",
                f"The sender's name says {name}, but the email came from "
                f"{from_address}, which is not a {name} address.",
            )
            break

    if from_registered in FREE_EMAIL_DOMAINS:
        details["free_email"] = True
        assessment.note(
            f"The email was sent from a free personal account "
            f"({from_registered}). That's normal for individuals but "
            "unusual for a company's billing or payment requests."
        )

    if not from_domain.isascii() or "xn--" in from_domain:
        decoded = _decode_host(from_domain)
        if len(_scripts_in(decoded)) > 1:
            assessment.flag(
                "HIGH",
                f"The sending domain mixes letters from different "
                f"alphabets ({decoded}), a common way to imitate a "
                "familiar name.",
            )

    if return_address and _registered(return_domain) != from_registered:
        assessment.note(
            f"Delivery problems are reported to {return_domain}. This is "
            "common when a company sends mail through an email service."
        )


def _check_authentication(
    assessment: _Assessment,
    message: EmailMessage,
    details: dict,
) -> None:
    received = message.get_all("Received") or []
    details["received_hops"] = len(received)

    results = _parse_authentication_results(message)
    details["authentication"] = results

    if not results:
        if not received:
            assessment.note(
                "The email has no delivery information. It may have been "
                "forwarded, or saved in a way that leaves out the "
                "original details, so PreClear couldn't check how it was "
                "delivered. To confirm the sender, paste the email's "
                "original instead (in Outlook: View message source)."
            )
        else:
            assessment.note(
                "The receiving mail server didn't record sender "
                "verification results, so PreClear couldn't confirm the "
                "sender's identity."
            )
        return

    dmarc = results.get("dmarc")
    spf = results.get("spf")
    dkim = results.get("dkim")

    if dmarc == "fail":
        assessment.flag(
            "HIGH",
            "Sender verification failed: the receiving mail server "
            "reported a DMARC failure, meaning the email did not "
            "provably come from the domain it claims.",
        )
    elif results.get("compauth") == "fail":
        assessment.flag(
            "MEDIUM",
            "Microsoft's mail system could not verify that this email "
            "came from the domain it claims.",
        )
    elif spf in {"fail", "softfail"} and dkim not in {"pass"}:
        assessment.flag(
            "MEDIUM",
            "The sender's domain could not be verified (SPF did not pass "
            "and there was no valid DKIM signature). Forwarded messages "
            "can fail this check too.",
        )
    elif dmarc == "pass":
        assessment.note(
            "The receiving mail server verified that the email came from "
            "its sender's domain (DMARC passed). This confirms the "
            "domain, not that the message itself is safe."
        )


def _check_trusted_sender(
    assessment: _Assessment,
    details: dict,
    trusted,
) -> None:
    """
    Compares the sender with the organization's own domains and trusted
    vendors. Mail that really comes from a trusted vendor is recognized,
    mail that only pretends to is called out, and lookalike domains are
    flagged as the likely start of invoice fraud.
    """
    if not trusted:
        return

    from_domain = details.get("from_domain") or ""
    from_address = details.get("from_address") or ""
    auth = details.get("authentication") or {}

    entry = trusted.match(from_domain) if from_domain else None

    if entry is not None:
        details["trusted_sender"] = {"label": entry.label, "kind": entry.kind}

        failed = (
            auth.get("dmarc") == "fail"
            or auth.get("compauth") == "fail"
            or (
                auth.get("spf") in {"fail", "softfail"}
                and auth.get("dkim") != "pass"
            )
        )

        if failed:
            assessment.flag(
                "HIGH",
                f"The email claims to come from {entry.label} "
                f"({entry.domain}), {entry.description}, but sender "
                "verification failed. Someone may be impersonating them.",
            )
        elif auth.get("dmarc") == "pass":
            assessment.note(
                f"The email was verified as coming from {entry.label} "
                f"({entry.domain}), {entry.description}."
            )
        else:
            assessment.note(
                f"The email appears to come from {entry.label} "
                f"({entry.domain}), {entry.description}, but the "
                "receiving mail server didn't record a verification "
                "result, so PreClear couldn't confirm it."
            )

    elif from_domain:
        lookalike = trusted.lookalike(from_domain)

        if lookalike is not None:
            target = lookalike.entry
            assessment.flag(
                "HIGH",
                f"The sender's domain {from_domain} imitates "
                f"{target.label} ({target.domain}), {target.description}. "
                f"It {lookalike.reason}. Lookalike sender domains are how "
                "most invoice fraud starts.",
            )
        else:
            name = (details.get("from_name") or "").lower()
            for candidate in trusted.entries:
                label = candidate.label.lower()
                if len(label) >= 4 and re.search(
                    rf"(?<![a-z0-9]){re.escape(label)}(?![a-z0-9])", name
                ):
                    assessment.flag(
                        "MEDIUM",
                        f"The sender's name says {candidate.label}, but the "
                        f"email came from {from_address}, not "
                        f"{candidate.domain}.",
                    )
                    break

    reply_to = details.get("reply_to") or ""
    if "@" in reply_to:
        reply_domain = _registered(reply_to.rsplit("@", 1)[-1])
        reply_lookalike = trusted.lookalike(reply_domain)
        if reply_lookalike is not None:
            target = reply_lookalike.entry
            assessment.flag(
                "HIGH",
                f"Replies would go to {reply_to}, at a domain that "
                f"imitates {target.label} ({target.domain}).",
            )


def _check_requests(
    assessment: _Assessment,
    subject: str,
    text: str,
    details: dict,
) -> None:
    combined = f"{subject}\n{text}"
    found = []

    # Shared with the text message checker. In emails each finding is a
    # caution; emails carry many other signals that decide the rest.
    for signal in find_signals(combined):
        found.append(signal.key)
        assessment.flag("MEDIUM", signal.reason)

    details["requests"] = found

    if "gift_cards" in found and "boss_favor" in found:
        assessment.flag(
            "HIGH",
            "A private, urgent favor involving gift cards is one of the most "
            "common scams aimed at employees. Confirm with the person "
            "directly, by phone or in person.",
        )

    if is_urgent(combined):
        details["urgent"] = True
        if found:
            assessment.note(
                "The message also pushes you to act quickly. Pressure "
                "plus a request is the pattern behind most email scams."
            )

    if "payment_change" in found and details.get("trusted_sender"):
        label = details["trusted_sender"]["label"]
        assessment.note(
            f"Even genuine accounts at trusted companies are sometimes "
            f"taken over. Confirm any change to payment details by calling "
            f"{label} at a number you already have."
        )

    if "payment_change" in found and details.get("free_email"):
        assessment.flag(
            "HIGH",
            "A request to change payment details coming from a free "
            "personal email account is a hallmark of invoice fraud.",
        )


def _link_mismatch(href_host: str, text: str) -> str | None:
    """Returns the domain shown in a link's text if it differs from where it goes."""
    text = text.strip().rstrip(".")

    if not text or " " in text or not LOOKS_LIKE_ADDRESS.match(text):
        return None

    shown = re.sub(r"^https?://", "", text, flags=re.IGNORECASE)
    shown_host = re.split(r"[/?#:]", shown, 1)[0].lower()

    if not shown_host or "." not in shown_host:
        return None

    if _registered(shown_host) == _registered(href_host):
        return None

    return shown_host


def _check_links(
    assessment: _Assessment,
    html_links: list[tuple[str, str]],
    text_urls: list[str],
    details: dict,
    lookup_budget: int,
    trusted=None,
) -> int:
    """Analyzes every link. Returns the reputation budget left over."""
    candidates: list[tuple[str, str]] = []
    seen = set()

    for href, text in html_links + [(url, "") for url in text_urls]:
        if href.lower().startswith(("#", "cid:")):
            continue
        key = href.strip()
        if key in seen:
            continue
        seen.add(key)
        candidates.append((href, text))

    details["link_count"] = len(candidates)

    if len(candidates) > MAX_LINKS_ANALYZED:
        assessment.note(
            f"The email has {len(candidates)} links. PreClear checked "
            f"the first {MAX_LINKS_ANALYZED}."
        )

    results = []

    for href, text in candidates[:MAX_LINKS_ANALYZED]:
        try:
            result = analyze_link(
                href,
                check_reputation=False,
                trusted=trusted,
            )
        except InvalidLinkError:
            continue

        link_details = result["details"]
        host = (link_details.get("inner") or link_details).get("host", "")

        mismatch = _link_mismatch(host, text) if host else None

        results.append({
            "href": href,
            "text": text,
            "host": host,
            "result": result,
            "mismatch": mismatch,
        })

    # Spend the reputation budget on the most suspicious distinct hosts.
    by_risk = sorted(
        results,
        key=lambda item: RISK_ORDER[item["result"]["risk_level"]],
        reverse=True,
    )
    looked_up = set()

    for item in by_risk:
        if lookup_budget <= 0:
            break
        host = item["host"]
        if not host or host in looked_up:
            continue
        looked_up.add(host)
        lookup_budget -= 1
        try:
            item["result"] = analyze_link(
                item["href"],
                check_reputation=True,
                trusted=trusted,
            )
        except InvalidLinkError:
            pass

    stored_links = []
    flagged = 0

    for item in sorted(
        results,
        key=lambda item: (
            item["mismatch"] is None,
            -RISK_ORDER[item["result"]["risk_level"]],
        ),
    ):
        result = item["result"]
        label = item["host"] or result["filename"]

        if item["mismatch"]:
            assessment.flag(
                "HIGH",
                f"A link's text shows {item['mismatch']}, but it actually "
                f"goes to {item['host']}.",
            )

        if result["risk_level"] != "LOW":
            flagged += 1
            if flagged <= 5:
                worst = [
                    reason for reason in result["reasons"]
                    if not reason.startswith("The link does not use an encrypted")
                ][:2]
                assessment.raise_to(result["risk_level"])
                for reason in worst:
                    assessment.reasons.append(f"Link to {label}: {reason}")

        stored_links.append({
            "url": result["target"][:2048],
            "host": item["host"],
            "text": item["text"][:200],
            "risk_level": result["risk_level"],
            "decision": result["decision"],
            "mismatch": item["mismatch"],
        })

    if flagged > 5:
        assessment.note(
            f"{flagged - 5} more links also showed warning signs."
        )

    safe_count = sum(1 for item in results if item["result"]["risk_level"] == "LOW")
    if results and safe_count == len(results):
        assessment.note(
            f"PreClear checked {len(results)} link"
            f"{'' if len(results) == 1 else 's'} without visiting "
            f"{'it' if len(results) == 1 else 'them'} and found no "
            "warning signs in the addresses."
        )

    details["links"] = stored_links[:MAX_LINKS_ANALYZED]

    return lookup_budget


def _check_attachments(
    assessment: _Assessment,
    attachments: list[EmailMessage],
    details: dict,
    trusted=None,
) -> int:
    """Scans attachments. Returns how many reputation lookups were used."""
    stored = []
    lookups_used = 0
    found_qr = False

    for index, part in enumerate(attachments[:MAX_ATTACHMENTS_ANALYZED]):
        name = part.get_filename() or (
            f"inline image {index + 1}"
            if part.get_content_type().startswith("image/")
            else f"attachment-{index + 1}"
        )

        if part.get_content_type() == "message/rfc822":
            assessment.note(
                f"The email contains another email as an attachment "
                f"({name}). Save that message as .eml and check it "
                "separately."
            )
            stored.append({"name": name, "decision": "NOT_CHECKED"})
            continue

        try:
            payload = part.get_payload(decode=True) or b""
        except (ValueError, AssertionError):
            payload = b""

        check = lookups_used < MAX_ATTACHMENT_LOOKUPS
        if check:
            lookups_used += 1

        result = analyze_file(
            filename=name,
            content=payload,
            content_type=part.get_content_type(),
            check_reputation=check,
        )

        if result["risk_level"] != "LOW":
            assessment.raise_to(result["risk_level"])
            for reason in result["reasons"][:2]:
                assessment.reasons.append(
                    f"Attachment {result['filename']}: {reason}"
                )

        item = {
            "name": result["filename"],
            "size": result["file_size"],
            "sha256": result["sha256"],
            "detected_type": result.get("detected_type"),
            "risk_level": result["risk_level"],
            "decision": result["decision"],
        }

        budget = 1 if lookups_used < REPUTATION_LOOKUP_BUDGET - 1 else 0
        qr = (
            analyze_qr_in_file(
                payload,
                result,
                reputation_lookups=budget,
                trusted=trusted,
            )
            if payload
            else None
        )

        if qr is not None:
            lookups_used += budget if qr["codes"] else 0

            if qr["codes"]:
                found_qr = True
                item["qr"] = []
                for code in qr["codes"]:
                    where = result["filename"]
                    if code.get("page"):
                        where += f", page {code['page']}"
                    item["qr"].append({
                        "summary": code["summary"],
                        "display": code["display"],
                        "decision": code["decision"],
                        "page": code.get("page"),
                    })
                    assessment.reasons.append(
                        f"QR code in {where}: {code['summary']}"
                    )
                    if code["risk_level"] != "LOW":
                        assessment.raise_to(code["risk_level"])
                        for reason in code["reasons"][:2]:
                            assessment.reasons.append(
                                f"QR code in {where}: {reason}"
                            )

                # The image itself may be harmless; the code decides.
                if RISK_ORDER[qr["risk_level"]] > RISK_ORDER[item["risk_level"]]:
                    item["risk_level"] = qr["risk_level"]
                    item["decision"] = DECISION_FOR_RISK[qr["risk_level"]]

        stored.append(item)

    if found_qr:
        details["has_qr"] = True
        assessment.note(
            "The email contains a QR code. Phishing emails use QR codes "
            "because the link is a picture, which email security filters "
            "can't read. Don't scan a code from an email you weren't "
            "expecting."
        )

    if len(attachments) > MAX_ATTACHMENTS_ANALYZED:
        assessment.note(
            f"The email has {len(attachments)} attachments. PreClear "
            f"checked the first {MAX_ATTACHMENTS_ANALYZED}."
        )

    if attachments and all(
        item.get("risk_level") == "LOW" for item in stored
    ):
        assessment.note(
            f"PreClear scanned {len(stored)} attachment"
            f"{'' if len(stored) == 1 else 's'} and found no obvious "
            "warning signs."
        )

    details["attachments"] = stored

    return lookups_used


# ---------------------------------------------------------------- analysis


def _email_checks(details: dict, attachments: list, encrypted: bool, trusted) -> list[dict]:
    """The "What was checked" list for an email."""
    checks = [
        check(
            "Sender",
            DONE,
            "Checked the sender, reply-to address and display name for "
            "disguises.",
        ),
    ]

    if details.get("authentication"):
        checks.append(check(
            "Sender verification",
            DONE,
            "Read the receiving mail server's SPF, DKIM and DMARC results.",
        ))
    else:
        checks.append(check(
            "Sender verification",
            LIMITED,
            "The email didn't include the receiving server's verification "
            "results, so the sender couldn't be confirmed. Pasting the "
            "email's original usually fixes this.",
        ))

    checks.append(
        check(
            "Your trusted domains",
            DONE,
            "Compared the sender and links with your trusted domains.",
        )
        if trusted
        else check(
            "Your trusted domains",
            NOT_NEEDED,
            "Your organization hasn't listed trusted domains yet.",
        )
    )

    checks.append(check(
        "Wording",
        DONE,
        "Checked what the message asks for against common scams.",
    ))

    link_count = details.get("link_count", 0)
    if not link_count:
        checks.append(check("Links", NOT_NEEDED, "The email has no links."))
    elif link_count > MAX_LINKS_ANALYZED:
        checks.append(check(
            "Links",
            LIMITED,
            f"Checked the first {MAX_LINKS_ANALYZED} of {link_count} links "
            "without visiting them.",
        ))
    else:
        checks.append(check(
            "Links",
            DONE,
            f"Checked {link_count} link{'' if link_count == 1 else 's'} "
            f"without visiting {'it' if link_count == 1 else 'them'}.",
        ))

    count = len(attachments)
    if not count:
        checks.append(check("Attachments", NOT_NEEDED, "The email has no attachments or images."))
    elif count > MAX_ATTACHMENTS_ANALYZED:
        checks.append(check(
            "Attachments",
            LIMITED,
            f"Scanned the first {MAX_ATTACHMENTS_ANALYZED} of {count}.",
        ))
    else:
        checks.append(check(
            "Attachments",
            DONE,
            f"Scanned {count} attachment{'' if count == 1 else 's'} or "
            "image" + ("" if count == 1 else "s") + ", including any QR codes.",
        ))

    if encrypted:
        checks.append(check(
            "Encrypted content",
            LIMITED,
            "Part of the email is encrypted and couldn't be inspected.",
        ))

    hosts = {item.get("host") for item in details.get("links", []) if item.get("host")}
    checks.append(budget_reputation_check(
        len(hosts) + min(count, MAX_ATTACHMENTS_ANALYZED),
        REPUTATION_LOOKUP_BUDGET,
    ))

    return checks


def analyze_email(
    filename: str,
    content: bytes,
    trusted=None,
) -> dict:
    """
    Analyzes a saved email. Blocking (attachment scans and VirusTotal
    lookups), so async routes must call it through run_in_threadpool.

    Raises InvalidEmailError if the upload isn't a readable email.
    """
    try:
        message = BytesParser(policy=policy.default).parsebytes(content)
    except Exception as error:  # the parser can raise many error types
        raise InvalidEmailError("unparseable") from error

    if not (message.get("From") or message.get("Subject") or message.get("Received")):
        raise InvalidEmailError("no_headers")

    assessment = _Assessment()
    details: dict = {}

    subject = " ".join(str(message.get("Subject") or "").split())
    details["subject"] = subject[:500]
    details["date"] = str(message.get("Date") or "")[:100]
    details["message_id"] = str(message.get("Message-ID") or "")[:300]

    # Walk the message once, with limits, collecting body text, links
    # and attachments.
    texts: list[str] = []
    plain_texts: list[str] = []
    html_links: list[tuple[str, str]] = []
    form_actions: list[str] = []
    remote_images = 0
    has_script = False
    attachments: list[EmailMessage] = []
    encrypted = False

    for count, part in enumerate(message.walk()):
        if count >= MAX_MIME_PARTS:
            assessment.note(
                "The email has an unusually complex structure. PreClear "
                f"checked its first {MAX_MIME_PARTS} parts."
            )
            break

        content_type = part.get_content_type()

        if content_type in {
            "application/pkcs7-mime", "application/x-pkcs7-mime",
            "application/pgp-encrypted",
        }:
            encrypted = True

        if part.is_multipart():
            continue

        disposition = part.get_content_disposition()

        # Attachments, plus images shown inside the message, which are
        # where phishing emails hide QR codes.
        if disposition == "attachment" or (
            part.get_filename() and content_type not in {"text/plain", "text/html"}
        ) or content_type == "message/rfc822" or content_type.startswith("image/"):
            attachments.append(part)
            continue

        if content_type == "text/plain":
            plain = _part_text(part)
            plain_texts.append(plain)
            texts.append(plain)

        elif content_type == "text/html":
            html = _part_text(part)
            collector = _LinkCollector()
            try:
                collector.feed(html)
                collector.close()
            except Exception:
                pass
            html_links.extend(collector.links)
            form_actions.extend(collector.form_actions)
            remote_images += collector.remote_images
            has_script = has_script or collector.has_script
            texts.append(" ".join(collector.text_parts))

    body_text = "\n".join(texts)[:MAX_BODY_CHARS]

    _check_sender(assessment, message, details)
    _check_authentication(assessment, message, details)
    _check_trusted_sender(assessment, details, trusted)
    _check_requests(assessment, subject, body_text, details)

    if form_actions:
        assessment.flag(
            "HIGH",
            "The email contains a form you can type into. Legitimate "
            "companies don't ask for information through forms inside "
            "an email.",
        )

    if has_script:
        assessment.flag(
            "MEDIUM",
            "The email contains script code, which legitimate business "
            "email doesn't need.",
        )

    if remote_images:
        details["remote_images"] = remote_images
        assessment.note(
            f"The email loads {remote_images} image"
            f"{'' if remote_images == 1 else 's'} from the internet. "
            "Opening it can tell the sender that you read it."
        )

    if encrypted:
        assessment.note(
            "Part of the email is encrypted, so PreClear could not "
            "inspect it."
        )

    lookups_used = _check_attachments(
        assessment,
        attachments,
        details,
        trusted,
    )

    # Addresses typed in the plain-text body. Links in HTML were already
    # collected from the actual link targets.
    text_urls = URL_IN_TEXT.findall("\n".join(plain_texts)[:MAX_BODY_CHARS])

    _check_links(
        assessment,
        html_links,
        text_urls,
        details,
        REPUTATION_LOOKUP_BUDGET - lookups_used,
        trusted,
    )

    details["checks"] = _email_checks(details, attachments, encrypted, trusted)

    if not assessment.reasons:
        assessment.note(
            "No warning signs were found in the sender, message, links "
            "or attachments."
        )

    decision = assessment.decision

    if decision == "LOOKS_SAFE":
        explanation = (
            "PreClear did not find warning signs in this email. Still "
            "ask: were you expecting it, and is it asking you to act? "
            "If it asks for money or a sign-in, check another way first."
        )
    elif decision == "USE_CAUTION":
        explanation = (
            "This email has characteristics that deserve verification "
            "before you act on it. Contact the sender another way, using "
            "a phone number or address you already have, before you "
            "click, pay or reply."
        )
    else:
        explanation = (
            "This email shows strong signs of fraud or phishing. Do not "
            "click its links, open its attachments or act on its "
            "requests. Report it to whoever handles security for your "
            "organization."
        )

    from_address = details.get("from_address") or "unknown sender"
    label = subject or f"Email from {from_address}"
    if len(label) > MAX_LABEL_LENGTH:
        label = label[: MAX_LABEL_LENGTH - 3] + "..."

    return {
        "filename": label,
        "extension": ".eml",
        "mime_type": "message/rfc822",
        "file_size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "target": subject[:2000] or None,
        "details": details,
        "details_json": json.dumps(details),
        "risk_level": assessment.risk_level,
        "virustotal": {"available": False, "found": False, "error": "not_applicable"},
        "decision": decision,
        "explanation": explanation,
        "reasons": assessment.reasons,
    }
