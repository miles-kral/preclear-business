"""
QR code analysis.

PreClear decodes QR codes from images and explains what each one would
do if scanned with a phone. Links go through the link analyzer, so they
are checked without being visited. Secrets that some QR codes carry
(Wi-Fi passwords, authenticator keys) are never stored.
"""
from __future__ import annotations

import json
import re
from io import BytesIO
from urllib.parse import parse_qs, unquote, urlsplit

from PIL import Image, UnidentifiedImageError

from app.services.coverage import (
    DONE,
    LIMITED,
    UNAVAILABLE,
    check,
)
from app.services.link_analysis import (
    InvalidLinkError,
    analyze_link,
)


# Only these image formats are opened, which keeps Pillow's rarely used
# decoders out of reach of uploaded files.
ALLOWED_IMAGE_FORMATS = ["PNG", "JPEG", "GIF", "WEBP", "BMP"]

# Images larger than this are not decoded, to guard against images built
# to exhaust memory when expanded. JPEG photos are first shrunk while
# decoding (cheaply), so large phone photos still fit.
MAX_IMAGE_PIXELS = 50_000_000

# PDFs: how many pages are checked, and the largest rendered page size.
MAX_PDF_PAGES = 5
MAX_PDF_RENDER_DIMENSION = 3000
MAX_PDF_RENDER_SCALE = 2.5

# Very large images are shrunk before decoding to bound the work.
MAX_DECODE_DIMENSION = 4000

MAX_CODES = 10

MAX_DISPLAY_LENGTH = 1000

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

DECISION_FOR_RISK = {
    "LOW": "LOOKS_SAFE",
    "MEDIUM": "USE_CAUTION",
    "HIGH": "DO_NOT_OPEN",
}

CRYPTO_SCHEMES = {
    "bitcoin": "Bitcoin", "ethereum": "Ethereum", "litecoin": "Litecoin",
    "monero": "Monero", "dogecoin": "Dogecoin", "bitcoincash": "Bitcoin Cash",
    "solana": "Solana", "tron": "Tron",
}

CRYPTO_ADDRESS = re.compile(
    r"^(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[0-9a-fA-F]{40})$"
)

URL_IN_TEXT = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'()\[\]{}]+",
    re.IGNORECASE,
)


def _zxing():
    # Imported lazily so the rest of the app still starts if the package
    # is missing; QR decoding is simply skipped in that case.
    try:
        import zxingcpp
    except ImportError:
        return None
    return zxingcpp


# ---------------------------------------------------------------- decoding


def _read_codes(image) -> list[str]:
    """Decodes QR codes from an opened grayscale PIL image."""
    zxingcpp = _zxing()

    formats = [
        zxingcpp.BarcodeFormat.QRCode,
        zxingcpp.BarcodeFormat.MicroQRCode,
        zxingcpp.BarcodeFormat.RMQRCode,
    ]

    payloads = []
    for result in zxingcpp.read_barcodes(image, formats=formats):
        if result.valid and result.text and result.text not in payloads:
            payloads.append(result.text)

    return payloads


def decode_qr_codes(content: bytes) -> tuple[list[str], str | None]:
    """
    Returns (decoded payloads, problem) for an image. problem is a short
    code when the image couldn't be checked, otherwise None.
    """
    if _zxing() is None:
        return [], "decoder_unavailable"

    try:
        image = Image.open(
            BytesIO(content),
            formats=ALLOWED_IMAGE_FORMATS,
        )
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        return [], "unreadable"

    # Big JPEGs (phone photos) can be decoded at reduced size directly,
    # which is fast and never expands the full image in memory.
    if image.format == "JPEG":
        image.draft("L", (MAX_DECODE_DIMENSION, MAX_DECODE_DIMENSION))

    width, height = image.size

    if width * height > MAX_IMAGE_PIXELS:
        return [], "too_large"

    try:
        # The first frame is enough for animated images.
        image.seek(0)
        image = image.convert("L")

        if max(width, height) > MAX_DECODE_DIMENSION:
            image.thumbnail((MAX_DECODE_DIMENSION, MAX_DECODE_DIMENSION))

        payloads = _read_codes(image)

    except (OSError, ValueError, Image.DecompressionBombError, RuntimeError):
        return [], "unreadable"

    return payloads[:MAX_CODES], None


def decode_pdf_qr_codes(
    content: bytes,
) -> tuple[list[tuple[int, str]], str | None, int]:
    """
    Renders the first pages of a PDF and decodes QR codes on them.
    Returns ([(page number, payload)], problem, pages checked).
    """
    if _zxing() is None:
        return [], "decoder_unavailable", 0

    try:
        import pypdfium2 as pdfium
    except ImportError:
        return [], "decoder_unavailable", 0

    try:
        document = pdfium.PdfDocument(content)
    except pdfium.PdfiumError as error:
        if "password" in str(error).lower():
            return [], "encrypted", 0
        return [], "unreadable", 0

    found: list[tuple[int, str]] = []
    pages_checked = 0

    try:
        page_count = len(document)

        for index in range(min(page_count, MAX_PDF_PAGES)):
            page = document[index]
            try:
                width, height = page.get_size()
                if width <= 0 or height <= 0:
                    continue

                # PDF sizes are in points (1/72 inch). Scale so the
                # rendered page stays within a fixed pixel budget.
                scale = min(
                    MAX_PDF_RENDER_SCALE,
                    MAX_PDF_RENDER_DIMENSION / max(width, height),
                )

                bitmap = page.render(
                    scale=scale,
                    grayscale=True,
                    may_draw_forms=False,
                )
                image = bitmap.to_pil().convert("L")
                pages_checked += 1

                for payload in _read_codes(image):
                    if all(payload != existing for _, existing in found):
                        found.append((index + 1, payload))

            finally:
                page.close()

            if len(found) >= MAX_CODES:
                break

    except (pdfium.PdfiumError, OSError, ValueError, RuntimeError):
        return found[:MAX_CODES], "unreadable", pages_checked

    finally:
        document.close()

    problem = "more_pages" if page_count > MAX_PDF_PAGES else None

    return found[:MAX_CODES], problem, pages_checked


# ----------------------------------------------------------------- payloads


def _shorten(text: str) -> str:
    text = " ".join(str(text).split())
    if len(text) > MAX_DISPLAY_LENGTH:
        return text[: MAX_DISPLAY_LENGTH - 3] + "..."
    return text


def _wifi_fields(payload: str) -> dict:
    """Parses WIFI:T:WPA;S:name;P:secret;; into fields, honoring \\ escapes."""
    fields = {}
    body = payload[5:]
    key, value, escaped, reading_key = "", "", False, True

    for char in body:
        if escaped:
            value += char
            escaped = False
        elif char == "\\":
            escaped = True
        elif reading_key and char == ":":
            reading_key = False
        elif reading_key:
            key += char
        elif char == ";":
            fields[key.upper()] = value
            key, value, reading_key = "", "", True
        else:
            value += char

    return fields


def _link_item(url: str, check_reputation: bool, trusted=None) -> dict:
    try:
        result = analyze_link(
            url,
            check_reputation=check_reputation,
            trusted=trusted,
        )
    except InvalidLinkError:
        return {
            "kind": "text",
            "display": _shorten(url),
            "risk_level": "MEDIUM",
            "reasons": ["The code contains an address PreClear could not read."],
        }

    link_details = result["details"]
    host = (link_details.get("inner") or link_details).get("host")
    scheme = link_details.get("scheme", "")

    if host:
        summary = f"Opens a web page at {host}."
    else:
        summary = {
            "mailto": "Starts a new email.",
            "tel": "Starts a phone call.",
            "sms": "Starts a text message.",
        }.get(scheme, f"Opens an app link ({scheme}:) instead of a web page.")

    return {
        "kind": "link",
        "display": _shorten(result["target"]),
        "host": host,
        "risk_level": result["risk_level"],
        "reasons": [
            reason for reason in result["reasons"]
            if reason != "No warning signs were found in the address itself."
        ],
        "summary": summary,
    }


def analyze_payload(
    payload: str,
    check_reputation: bool = True,
    trusted=None,
) -> dict:
    """
    Explains what a QR code would do. Returns a dict with kind, display
    (safe to store), risk_level, reasons and summary.
    """
    text = payload.strip()
    lower = text.lower()

    # Authenticator setup. The secret key is never stored or shown.
    if lower.startswith("otpauth-migration:"):
        return {
            "kind": "authenticator_export",
            "display": "Authenticator export (secret keys removed)",
            "risk_level": "HIGH",
            "summary": "Transfers authenticator accounts to another device.",
            "reasons": [
                "This code exports the secret keys for one or more "
                "authenticator accounts. Anyone who scans it can generate "
                "those sign-in codes. Never share or scan a code like this "
                "unless you are moving your own accounts to your own phone.",
            ],
        }

    if lower.startswith("otpauth:"):
        parts = urlsplit(text)
        label = unquote(parts.path.lstrip("/")) or "an account"
        issuer = parse_qs(parts.query).get("issuer", [""])[0]
        account = f"{label} ({issuer})" if issuer and issuer not in label else label
        return {
            "kind": "authenticator",
            "display": f"Authenticator setup for {_shorten(account)} (secret key removed)",
            "risk_level": "HIGH",
            "summary": f"Adds {_shorten(account)} to an authenticator app.",
            "reasons": [
                f"This code adds an authenticator account ({_shorten(account)}) "
                "to whoever scans it. Only scan setup codes shown on the "
                "website where you are turning on two-step sign-in. A setup "
                "code sent to you by someone else can be used to take over "
                "an account.",
            ],
        }

    # Wi-Fi network settings. The password is never stored or shown.
    if lower.startswith("wifi:"):
        fields = _wifi_fields(text)
        name = fields.get("S") or "an unnamed network"
        security = (fields.get("T") or "").upper()
        open_network = security in {"", "NOPASS"} and not fields.get("P")

        reasons = []
        risk = "LOW"

        if open_network:
            risk = "MEDIUM"
            reasons.append(
                f"This code connects to the Wi-Fi network \"{name}\", which "
                "has no password. Anyone nearby could watch traffic on an "
                "open network, and attackers set up open networks with "
                "familiar names."
            )
        else:
            reasons.append(
                f"This code connects to the Wi-Fi network \"{name}\". Only "
                "join it if you know who runs the network."
            )

        if fields.get("H", "").lower() == "true":
            risk = "MEDIUM"
            reasons.append(
                "The network is hidden, so it won't appear in your device's "
                "list of networks."
            )

        return {
            "kind": "wifi",
            "display": f"Wi-Fi network \"{_shorten(name)}\" "
                       f"({'no password' if open_network else security or 'secured'}; password removed)",
            "risk_level": risk,
            "summary": f"Joins the Wi-Fi network \"{_shorten(name)}\".",
            "reasons": reasons,
        }

    # Text messages in the SMSTO:number:message format.
    if lower.startswith("smsto:"):
        _, _, rest = text.partition(":")
        number, _, message = rest.partition(":")
        digits = re.sub(r"\D", "", number)
        risk = "MEDIUM" if 0 < len(digits) <= 6 else "LOW"
        reasons = [
            f"This code starts a text message to {number or 'a number'}"
            + (f" saying \"{_shorten(message)}\"." if message else ".")
        ]
        if risk == "MEDIUM":
            reasons.append(
                "Short numbers like this can be premium services that add "
                "charges to a phone bill."
            )
        return {
            "kind": "sms",
            "display": _shorten(text),
            "risk_level": risk,
            "summary": f"Starts a text message to {number}.",
            "reasons": reasons,
        }

    # Contact cards and calendar events, which can carry links.
    if lower.startswith(("begin:vcard", "mecard:", "begin:vevent", "begin:vcalendar")):
        kind = "event" if "vevent" in lower or "vcalendar" in lower else "contact"
        item = {
            "kind": kind,
            "display": _shorten(text),
            "risk_level": "LOW",
            "summary": "Adds a calendar event." if kind == "event" else "Adds a contact card.",
            "reasons": [
                "This code adds a calendar event." if kind == "event"
                else "This code adds a contact card to your phone."
            ],
        }
        for url in URL_IN_TEXT.findall(text)[:3]:
            link = _link_item(url, check_reputation, trusted)
            if RISK_ORDER[link["risk_level"]] > RISK_ORDER[item["risk_level"]]:
                item["risk_level"] = link["risk_level"]
            item["reasons"] += [f"Link inside it: {r}" for r in link["reasons"][:2]]
        return item

    # Cryptocurrency payment requests.
    scheme = lower.split(":", 1)[0] if ":" in lower else ""
    if scheme in CRYPTO_SCHEMES or CRYPTO_ADDRESS.match(text):
        coin = CRYPTO_SCHEMES.get(scheme, "cryptocurrency")
        address = text.split(":", 1)[1].split("?")[0] if scheme else text
        return {
            "kind": "crypto",
            "display": _shorten(text),
            "risk_level": "MEDIUM",
            "summary": f"Requests a {coin} payment.",
            "reasons": [
                f"This code requests a {coin} payment to {_shorten(address)}. "
                "Cryptocurrency payments can't be reversed, and scammers "
                "favor them. Confirm any payment request by phone first.",
            ],
        }

    # European bank-transfer codes (EPC "BCD" format) and UPI payments.
    if text.startswith("BCD\n") or lower.startswith("upi://pay"):
        return {
            "kind": "payment",
            "display": _shorten(text),
            "risk_level": "MEDIUM",
            "summary": "Fills in a bank payment.",
            "reasons": [
                "This code fills in a bank payment. Check the recipient "
                "and amount, and confirm the account details by calling "
                "the requester at a number you already have.",
            ],
        }

    # Anything with a scheme (http, https, mailto, tel, javascript, app
    # links) or a bare web address goes to the link analyzer.
    if re.match(r"^[a-z][a-z0-9+.-]*:", lower) or lower.startswith("www."):
        if scheme == "geo":
            return {
                "kind": "location",
                "display": _shorten(text),
                "risk_level": "LOW",
                "summary": "Opens a map location.",
                "reasons": ["This code opens a location in a map app."],
            }
        return _link_item(text, check_reputation, trusted)

    if re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+(/\S*)?$", lower):
        return _link_item(text, check_reputation, trusted)

    # Plain text, possibly with links inside.
    item = {
        "kind": "text",
        "display": _shorten(text),
        "risk_level": "LOW",
        "summary": "Shows text.",
        "reasons": ["This code contains plain text, shown below."],
    }
    for url in URL_IN_TEXT.findall(text)[:3]:
        link = _link_item(url, check_reputation, trusted)
        if RISK_ORDER[link["risk_level"]] > RISK_ORDER[item["risk_level"]]:
            item["risk_level"] = link["risk_level"]
        item["reasons"] += [f"Link inside it: {r}" for r in link["reasons"][:2]]
    return item


def _explain_payloads(
    located: list[tuple[int | None, str]],
    reputation_lookups: int,
    trusted=None,
) -> tuple[list[dict], str]:
    codes = []
    risk = "LOW"

    for page, payload in located:
        item = analyze_payload(
            payload,
            check_reputation=reputation_lookups > 0,
            trusted=trusted,
        )
        if item["kind"] == "link" and reputation_lookups > 0:
            reputation_lookups -= 1

        item["decision"] = DECISION_FOR_RISK[item["risk_level"]]
        item["page"] = page
        codes.append(item)

        if RISK_ORDER[item["risk_level"]] > RISK_ORDER[risk]:
            risk = item["risk_level"]

    return codes, risk


def analyze_qr_image(
    content: bytes,
    reputation_lookups: int = 3,
    trusted=None,
) -> dict:
    """
    Decodes and explains every QR code in an image. Returns
    {"codes": [...], "risk_level": ..., "problem": ..., "source": "image"}.
    """
    payloads, problem = decode_qr_codes(content)

    codes, risk = _explain_payloads(
        [(None, payload) for payload in payloads],
        reputation_lookups,
        trusted,
    )

    return {
        "codes": codes,
        "risk_level": risk,
        "problem": problem,
        "source": "image",
    }


def analyze_qr_pdf(
    content: bytes,
    reputation_lookups: int = 3,
    trusted=None,
) -> dict:
    """Decodes and explains QR codes on the first pages of a PDF."""
    located, problem, pages_checked = decode_pdf_qr_codes(content)

    codes, risk = _explain_payloads(located, reputation_lookups, trusted)

    return {
        "codes": codes,
        "risk_level": risk,
        "problem": problem,
        "source": "pdf",
        "pages_checked": pages_checked,
    }


def analyze_qr_in_file(
    content: bytes,
    file_result: dict,
    reputation_lookups: int = 3,
    trusted=None,
) -> dict | None:
    """Checks an image or PDF for QR codes. Returns None for other files."""
    if is_image_result(file_result):
        return analyze_qr_image(content, reputation_lookups, trusted)

    if is_pdf_result(file_result):
        return analyze_qr_pdf(content, reputation_lookups, trusted)

    return None


IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".heic", ".heif",
}


def is_image_result(file_result: dict) -> bool:
    return (
        file_result.get("detected_type") == "image"
        or (file_result.get("extension") or "") in IMAGE_EXTENSIONS
    )


def is_pdf_result(file_result: dict) -> bool:
    return file_result.get("detected_type") == "pdf"


def _qr_check(qr: dict) -> dict:
    """Describes the QR code search for the "What was checked" list."""
    problem = qr.get("problem")
    count = len(qr.get("codes") or [])
    found = (
        f"Found {count} QR code{'' if count == 1 else 's'} and checked "
        "what each one contains."
        if count
        else "Looked for QR codes and found none."
    )

    if problem == "decoder_unavailable":
        return check("QR codes", UNAVAILABLE, "The QR code reader isn't installed.")

    if problem == "encrypted":
        return check("QR codes", LIMITED, "The PDF is password-protected, so its pages couldn't be checked.")

    if problem == "too_large":
        return check("QR codes", LIMITED, "The image is too large to check for QR codes.")

    if problem == "unreadable" and qr.get("source") != "pdf":
        return check("QR codes", LIMITED, "The image format couldn't be read.")

    if problem in {"more_pages", "unreadable"} and qr.get("source") == "pdf":
        return check(
            "QR codes",
            LIMITED,
            f"Checked the first {qr.get('pages_checked', 0)} pages. " + found,
        )

    return check("QR codes", DONE, found)


def combine_with_file_result(
    file_result: dict,
    qr: dict,
) -> tuple[dict, str]:
    """
    Merges QR findings into a file analysis. Returns (result, analysis
    type), where the type is "qr" if the image contained QR codes.
    """
    result = dict(file_result)
    codes = qr["codes"]

    result["checks"] = list(file_result.get("checks") or []) + [
        _qr_check(qr)
    ]

    is_pdf = qr.get("source") == "pdf"

    if not codes:
        reasons = list(result["reasons"])
        problem = qr["problem"]

        if problem == "too_large":
            reasons.append(
                "The image is too large for PreClear to check for QR codes."
            )
        elif problem == "unreadable" and not is_pdf:
            reasons.append(
                "PreClear couldn't read this image format to look for QR "
                "codes. A screenshot or JPEG photo works best."
            )
        elif problem == "encrypted":
            reasons.append(
                "The PDF is password-protected, which prevents its contents "
                "from being inspected, including any QR codes. Confirm the "
                "password with the sender by another channel, not from the "
                "same message."
            )
            # Locked files are a common way to slip past scanners, so they
            # earn a caution, matching encrypted Office files.
            if result["risk_level"] == "LOW":
                result["risk_level"] = "MEDIUM"
                result["decision"] = "USE_CAUTION"
                result["explanation"] = (
                    "PreClear identified characteristics that deserve "
                    "additional verification before the file is opened "
                    "or distributed internally."
                )
        elif is_pdf and qr.get("pages_checked"):
            pages = qr["pages_checked"]
            reasons.append(
                f"PreClear checked the first {pages} page"
                f"{'' if pages == 1 else 's'} for QR codes and found none."
                if problem == "more_pages"
                else "PreClear checked the PDF for QR codes and found none."
            )
        elif problem is None and not is_pdf:
            reasons.append(
                "PreClear looked for QR codes in this image and found none."
            )

        result["reasons"] = reasons
        return result, "file"

    risk = file_result["risk_level"]
    if RISK_ORDER[qr["risk_level"]] > RISK_ORDER[risk]:
        risk = qr["risk_level"]

    count = len(codes)
    container = "PDF" if is_pdf else "image"
    reasons = [
        f"The {container} contains {count} QR code{'' if count == 1 else 's'}. "
        "PreClear decoded "
        + ("it" if count == 1 else "them")
        + " without visiting anything."
    ]

    if is_pdf and qr.get("problem") == "more_pages":
        reasons.append(
            f"PreClear checked the first {qr.get('pages_checked')} pages "
            "for QR codes."
        )

    for index, code in enumerate(codes, 1):
        prefix = "QR code" if count == 1 else f"QR code {index}"
        if code.get("page"):
            prefix += f" (page {code['page']})"
        prefix += ": "
        reasons.append(prefix + code["summary"])
        reasons += [prefix + reason for reason in code["reasons"]]

    default_file_reason = (
        "No obvious high-risk file characteristics were identified "
        "by the initial inspection."
    )
    reasons += [
        f"{'PDF' if is_pdf else 'Image'} file: {reason}"
        for reason in file_result["reasons"]
        if reason != default_file_reason
    ]

    decision = DECISION_FOR_RISK[risk]

    if decision == "LOOKS_SAFE":
        explanation = (
            "PreClear did not find warning signs in this QR code. PreClear "
            "checks what a code contains without visiting it. If you "
            "weren't expecting the code, go to the organization's site by "
            "typing its address yourself instead of scanning."
        )
    elif decision == "USE_CAUTION":
        explanation = (
            "This QR code has characteristics that deserve verification "
            "before you scan it. QR codes hide where they lead, so confirm "
            "with whoever posted or sent it."
        )
    else:
        explanation = (
            "This QR code shows strong signs of being deceptive or "
            "dangerous. Do not scan it with your phone."
        )

    label = (
        f"QR code{'' if count == 1 else 's'} in {file_result['filename']}"
    )
    if len(label) > 255:
        label = label[:252] + "..."

    stored_codes = [
        {
            "kind": code["kind"],
            "display": code["display"],
            "host": code.get("host"),
            "summary": code["summary"],
            "risk_level": code["risk_level"],
            "decision": code["decision"],
            "page": code.get("page"),
        }
        for code in codes
    ]

    result.update({
        "filename": label,
        "target": codes[0]["display"],
        "details": {
            "source_file": file_result["filename"],
            "codes": stored_codes,
        },
        "risk_level": risk,
        "decision": decision,
        "explanation": explanation,
        "reasons": reasons,
    })
    result["details_json"] = json.dumps(result["details"])

    return result, "qr"
