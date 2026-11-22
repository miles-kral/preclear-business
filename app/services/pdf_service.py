import json

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


PRECLEAR_BLUE = colors.HexColor(
    "#0A3278"
)

TEXT = colors.HexColor(
    "#101828"
)

MUTED = colors.HexColor(
    "#667085"
)

BORDER = colors.HexColor(
    "#E4E7EC"
)

SURFACE = colors.HexColor(
    "#F9FAFB"
)

SAFE = colors.HexColor(
    "#15803D"
)

SAFE_SOFT = colors.HexColor(
    "#ECFDF3"
)

CAUTION = colors.HexColor(
    "#B45309"
)

CAUTION_SOFT = colors.HexColor(
    "#FFF7ED"
)

DANGER = colors.HexColor(
    "#B42318"
)

DANGER_SOFT = colors.HexColor(
    "#FEF3F2"
)


BASE_DIR = Path(__file__).resolve().parent.parent

PRECLEAR_SHIELD_PATH = (
    BASE_DIR
    / "static"
    / "preclear-shield.png"
)

def _format_datetime(
    value: datetime | None,
) -> str:
    if value is None:
        return "—"

    if value.tzinfo is None:
        value = value.replace(
            tzinfo=timezone.utc
        )

    local_value = value.astimezone()

    return (
        f"{local_value.strftime('%b')} "
        f"{local_value.day}, "
        f"{local_value.year} · "
        f"{local_value.strftime('%I:%M %p').lstrip('0')}"
    )


def _safe(
    value,
) -> str:
    """
    Escapes text for a ReportLab Paragraph. Paragraph text is markup, so
    an unescaped file name, link or note could change the PDF's content
    (for example with <font> tags) or make ReportLab try to load a file
    from the server (with an <img> tag). Every value that comes from a
    user, a file or a link must pass through here.
    """
    return _xml_escape(
        "" if value is None else str(value)
    )


def _load_details(
    analysis,
) -> dict:
    try:
        details = json.loads(
            getattr(analysis, "details_json", None) or "{}"
        )
    except (TypeError, ValueError):
        return {}

    return details if isinstance(details, dict) else {}


def _fit_style(
    text,
    base_style,
):
    """
    Returns a style that wraps at any character when the text has a very
    long unbroken run (such as a link), so it can't overflow its column.
    """
    longest = max(
        (len(part) for part in str(text or "").split()),
        default=0,
    )

    if longest <= 24:
        return base_style

    return ParagraphStyle(
        f"{base_style.name}Wrap",
        parent=base_style,
        wordWrap="CJK",
    )


def _decision_label(
    decision: str,
    analysis_type: str | None = None,
) -> str:
    if decision == "DO_NOT_OPEN" and analysis_type == "link":
        return "Do Not Visit"

    if decision == "DO_NOT_OPEN" and analysis_type == "email":
        return "Do Not Trust"

    if decision == "DO_NOT_OPEN" and analysis_type == "qr":
        return "Do Not Scan"

    labels = {
        "LOOKS_SAFE": "Looks Safe",
        "USE_CAUTION": "Use Caution",
        "DO_NOT_OPEN": "Do Not Open",
    }

    return labels.get(
        decision,
        decision.replace(
            "_",
            " ",
        ).title(),
    )


def _decision_colors(
    decision: str,
):
    if decision == "LOOKS_SAFE":
        return SAFE, SAFE_SOFT

    if decision == "USE_CAUTION":
        return CAUTION, CAUTION_SOFT

    return DANGER, DANGER_SOFT


def _review_label(
    status: str | None,
) -> str:
    if not status:
        return "Open"

    return status.replace(
        "_",
        " ",
    ).title()


def _make_styles():
    styles = getSampleStyleSheet()

    title = ParagraphStyle(
        "PreClearTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=TEXT,
        spaceAfter=4,
    )

    eyebrow = ParagraphStyle(
        "PreClearEyebrow",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=PRECLEAR_BLUE,
        uppercase=True,
        spaceAfter=7,
    )

    subtitle = ParagraphStyle(
        "PreClearSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=MUTED,
    )

    section = ParagraphStyle(
        "PreClearSection",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=TEXT,
        spaceAfter=8,
    )

    body = ParagraphStyle(
        "PreClearBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.8,
        leading=13,
        textColor=TEXT,
    )

    small = ParagraphStyle(
        "PreClearSmall",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.6,
        leading=11,
        textColor=MUTED,
    )

    label = ParagraphStyle(
        "PreClearLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7,
        leading=9,
        textColor=MUTED,
    )

    hash_style = ParagraphStyle(
        "PreClearHash",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7,
        leading=10,
        textColor=TEXT,
        wordWrap="CJK",
    )

    return {
        "title": title,
        "eyebrow": eyebrow,
        "subtitle": subtitle,
        "section": section,
        "body": body,
        "small": small,
        "label": label,
        "hash": hash_style,
    }

def _draw_pdf_footer(
    canvas,
    document,
):
    canvas.saveState()

    page_number = canvas.getPageNumber()

    exported_at = datetime.now(
        timezone.utc
    ).astimezone()

    export_text = (
        f"Exported "
        f"{exported_at.strftime('%b')} "
        f"{exported_at.day}, "
        f"{exported_at.year} · "
        f"{exported_at.strftime('%I:%M %p').lstrip('0')}"
    )

    canvas.setStrokeColor(
        BORDER
    )

    canvas.setLineWidth(
        0.5
    )

    canvas.line(
        document.leftMargin,
        0.47 * inch,
        letter[0] - document.rightMargin,
        0.47 * inch,
    )

    canvas.setFont(
        "Helvetica",
        7,
    )

    canvas.setFillColor(
        MUTED
    )

    canvas.drawString(
        document.leftMargin,
        0.28 * inch,
        export_text,
    )

    canvas.drawRightString(
        letter[0] - document.rightMargin,
        0.28 * inch,
        f"Page {page_number}",
    )

    canvas.restoreState()


def _field_table(
    rows,
    styles,
):
    table_rows = []

    for label, value in rows:
        table_rows.append(
            [
                Paragraph(
                    label,
                    styles["label"],
                ),
                Paragraph(
                    _safe(value),
                    styles["body"],
                ),
            ]
        )

    table = Table(
        table_rows,
        colWidths=[
            1.55 * inch,
            4.75 * inch,
        ],
        hAlign="CENTER",
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    SURFACE,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    BORDER,
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    BORDER,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    return table


def _item_table(
    title,
    rows,
    styles,
):
    """A two-column table of items (text and decision) for evidence PDFs."""
    table_rows = [
        [
            Paragraph(title, styles["label"]),
            Paragraph("DECISION", styles["label"]),
        ]
    ]

    for text, decision in rows:
        table_rows.append(
            [
                Paragraph(
                    _safe(text),
                    _fit_style(text, styles["small"]),
                ),
                Paragraph(
                    _safe(decision),
                    styles["small"],
                ),
            ]
        )

    table = Table(
        table_rows,
        repeatRows=1,
        colWidths=[
            4.9 * inch,
            1.4 * inch,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), SURFACE),
                ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    return table


def _append_qr_evidence(
    story,
    details: dict,
    styles,
) -> None:
    """Adds the image name and each decoded QR code for a QR analysis."""
    codes = details.get("codes") or []

    story.append(
        _field_table(
            [
                ("Analysis Type", "QR code"),
                ("Source File", details.get("source_file") or "Unknown"),
                ("Codes Found", len(codes)),
            ],
            styles,
        )
    )

    if codes:
        story.append(Spacer(1, 12))
        story.append(
            _item_table(
                "QR CODE CONTENTS (SHOWN AS TEXT, SECRETS REMOVED)",
                [
                    (
                        (f"Page {code['page']}: " if code.get("page") else "")
                        + f"{code.get('summary')} {code.get('display')}",
                        _decision_label(code.get("decision") or "", "qr"),
                    )
                    for code in codes
                ],
                styles,
            )
        )


def _append_email_evidence(
    story,
    details: dict,
    styles,
) -> None:
    """Adds sender, verification, attachment and link evidence for an email."""
    auth = details.get("authentication") or {}

    if auth:
        verification = (
            f"SPF {auth.get('spf') or 'none'} · "
            f"DKIM {auth.get('dkim') or 'none'} · "
            f"DMARC {auth.get('dmarc') or 'none'}"
        )
    else:
        verification = "Not recorded"

    sender = details.get("from_address") or "Not readable"
    if details.get("from_name"):
        sender = f"{details['from_name']} <{sender}>"

    story.append(
        _field_table(
            [
                ("From", sender),
                ("Reply-To", details.get("reply_to") or "Same as sender"),
                ("Sender Verification", verification),
                ("Sent", details.get("date") or "Unknown"),
                ("Links Checked", len(details.get("links") or [])),
                (
                    "Attachments Scanned",
                    len(details.get("attachments") or []),
                ),
            ],
            styles,
        )
    )

    def item_table(title, rows):
        return _item_table(title, rows, styles)

    attachments = details.get("attachments") or []

    if attachments:
        rows = []

        for item in attachments:
            text = item.get("name") or "attachment"
            for code in item.get("qr") or []:
                page = f" page {code['page']}" if code.get("page") else ""
                text += f" (QR code{page}: {code.get('summary')} {code.get('display')})"
            rows.append(
                (
                    text,
                    _decision_label(item.get("decision") or "NOT_CHECKED"),
                )
            )

        story.append(Spacer(1, 12))
        story.append(item_table("ATTACHMENT", rows))

    links = details.get("links") or []

    if links:
        rows = []

        for item in links:
            text = item.get("url") or item.get("host") or "link"
            if item.get("mismatch"):
                text = f"{text} (link text shows {item['mismatch']})"
            rows.append(
                (
                    text,
                    _decision_label(item.get("decision") or "", "link"),
                )
            )

        story.append(Spacer(1, 12))
        story.append(item_table("LINK (SHOWN AS TEXT, NOT VISITED)", rows))


def build_evidence_record_pdf(
    *,
    analysis,
    organization,
    reviewed_by_user=None,
) -> bytes:
    is_link = (
        getattr(analysis, "analysis_type", "file") == "link"
    )

    is_email = (
        getattr(analysis, "analysis_type", "file") == "email"
    )

    is_qr = (
        getattr(analysis, "analysis_type", "file") == "qr"
    )

    details = _load_details(analysis)

    link_info = details.get("inner") or details

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.62 * inch,
        bottomMargin=0.72 * inch,
        title=(
            f"Evidence Record PC-{analysis.id}"
        ),
        author="PreClear Business",
    )

    styles = _make_styles()

    story = []

    if PRECLEAR_SHIELD_PATH.exists():

        shield = Image(
            str(PRECLEAR_SHIELD_PATH),
            width=0.50 * inch,
            height=0.50 * inch,
        )

        brand = Paragraph(
            "<b>PreClear Business</b>",
            styles["eyebrow"],
        )

        brand_header = Table(
            [
                [
                    shield,
                    brand,
                ]
            ],
            colWidths=[
                0.55 * inch,
                5.75 * inch,
            ],
            hAlign="CENTER",
        )

        brand_header.setStyle(
            TableStyle(
                [
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        0,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        0,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        0,
                    ),
                ]
            )
        )

        story.append(
            brand_header
        )

    else:

        story.append(
            Paragraph(
                "PreClear Business",
                styles["eyebrow"],
            )
        )


    story.append(
        Spacer(
            1,
            8,
        )
    )

    story.append(
        Paragraph(
            "Evidence Record",
            styles["title"],
        )
    )

    story.append(
        Paragraph(
            (
                "Preserved evidence supporting a "
                "PreClear Trust Decision."
            ),
            styles["subtitle"],
        )
    )

    story.append(
        Spacer(
            1,
            18,
        )
    )

    decision_color, decision_bg = (
        _decision_colors(
            analysis.decision
        )
    )

    decision_table = Table(
        [
            [
                Paragraph(
                    "TRUST DECISION",
                    styles["label"],
                ),
                Paragraph(
                    "RISK LEVEL",
                    styles["label"],
                ),
                Paragraph(
                    "REVIEW STATUS",
                    styles["label"],
                ),
            ],
            [
                Paragraph(
                    (
                        f"<b>{_decision_label(analysis.decision, getattr(analysis, 'analysis_type', None))}</b>"
                    ),
                    styles["body"],
                ),
                Paragraph(
                    (
                        f"<b>{analysis.risk_level.title()}</b>"
                    ),
                    styles["body"],
                ),
                Paragraph(
                    (
                        f"<b>{_review_label(analysis.review_status)}</b>"
                    ),
                    styles["body"],
                ),
            ],
        ],
        colWidths=[
            2.25 * inch,
            1.75 * inch,
            2.3 * inch,
        ],
    )

    decision_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    decision_bg,
                ),
                (
                    "TEXTCOLOR",
                    (0, 1),
                    (0, 1),
                    decision_color,
                ),
                (
                    "BACKGROUND",
                    (1, 0),
                    (-1, -1),
                    SURFACE,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    BORDER,
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    BORDER,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    story.append(
        decision_table
    )

    story.append(
        Spacer(
            1,
            20,
        )
    )

    story.append(
        Paragraph(
            "Record Identity",
            styles["section"],
        )
    )

    story.append(
        _field_table(
            [
                (
                    "Evidence Record",
                    f"PC-{analysis.id}",
                ),
                (
                    "Organization",
                    organization.name,
                ),
                (
                    "Subject" if is_email
                    else (
                        "QR Code" if is_qr
                        else ("Link" if is_link else "Filename")
                    ),
                    analysis.filename,
                ),
                (
                    "Environment",
                    (
                        analysis.environment.name
                        if analysis.environment
                        else "—"
                    ),
                ),
                (
                    "Source",
                    (
                        analysis.source.replace(
                            "_",
                            " ",
                        ).title()
                        if analysis.source
                        else "—"
                    ),
                ),
                (
                    "Analyzed By",
                    (
                        analysis.user.name
                        if analysis.user
                        else "System"
                    ),
                ),
                (
                    "Recorded",
                    _format_datetime(
                        analysis.created_at
                    ),
                ),
            ],
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            20,
        )
    )

    story.append(
        Paragraph(
            "Decision Rationale",
            styles["section"],
        )
    )

    story.append(
        Paragraph(
            _safe(analysis.explanation),
            styles["body"],
        )
    )

    story.append(
        Spacer(
            1,
            10,
        )
    )

    try:
        reasons = json.loads(
            analysis.reasons
        )
    except (
        TypeError,
        json.JSONDecodeError,
    ):
        reasons = [
            analysis.reasons
        ]

    for reason in reasons:
        story.append(
            Paragraph(
                f"• {_safe(reason)}",
                styles["body"],
            )
        )

        story.append(
            Spacer(
                1,
                3,
            )
        )

        story.append(
        Spacer(
            1,
            17,
        )
    )


# ---------------------------------------------------------
# THREAT INTELLIGENCE
# ---------------------------------------------------------

    # Emails have no single reputation lookup; their attachments and
    # links were checked individually and appear in the rationale.
    if not is_email and not is_qr:

        story.append(
            Paragraph(
                "Threat Intelligence",
                styles["section"],
            )
        )

        vt_subject = (
            "domain" if is_link else "SHA-256 fingerprint"
        )

        if analysis.virustotal_found is None:

            reputation_label = (
                "Intelligence Unavailable"
            )

            reputation_text = (
                "VirusTotal threat intelligence was not "
                "available when this analysis was performed. "
                "PreClear's Trust Decision was based on the "
                "other security indicators identified during "
                "analysis."
            )

        elif analysis.virustotal_found:

            malicious_count = (
                analysis.virustotal_malicious
                or 0
            )

            suspicious_count = (
                analysis.virustotal_suspicious
                or 0
            )

            undetected_count = (
                analysis.virustotal_undetected
                or 0
            )

            harmless_count = (
                analysis.virustotal_harmless
                or 0
            )

            if malicious_count > 0:

                reputation_label = (
                    "Threat Detected"
                )

                reputation_text = (
                    f"VirusTotal recognized this {vt_subject} "
                    "and reported malicious "
                    "detections from participating security "
                    "engines."
                )

            elif suspicious_count > 0:

                reputation_label = (
                    "Suspicious Reputation"
                )

                reputation_text = (
                    f"VirusTotal recognized this {vt_subject} "
                    "and reported suspicious "
                    "detections that contributed to "
                    "PreClear's Trust Decision."
                )

            else:

                reputation_label = (
                    "No Threat Detections"
                )

                reputation_text = (
                    "VirusTotal recognized this "
                    + ("domain" if is_link else "file fingerprint")
                    + " and reported no malicious "
                    "or suspicious detections in the latest "
                    "available analysis."
                )

        else:

            reputation_label = (
                "No Existing Reputation"
            )

            reputation_text = (
                f"This {vt_subject} was not found in "
                "VirusTotal's available threat intelligence. "
                "PreClear's Trust Decision is based on the "
                "other security indicators identified during "
                "analysis."
            )


        story.append(
            _field_table(
                [
                    (
                        "VirusTotal Reputation",
                        reputation_label,
                    ),
                ],
                styles,
            )
        )


        if analysis.virustotal_found:

            story.append(
                Spacer(
                    1,
                    10,
                )
            )

            vt_table = Table(
                [
                    [
                        Paragraph(
                            "MALICIOUS",
                            styles["label"],
                        ),
                        Paragraph(
                            "SUSPICIOUS",
                            styles["label"],
                        ),
                        Paragraph(
                            "UNDETECTED",
                            styles["label"],
                        ),
                        Paragraph(
                            "HARMLESS",
                            styles["label"],
                        ),
                    ],
                    [
                        Paragraph(
                            f"<b>{malicious_count}</b>",
                            styles["body"],
                        ),
                        Paragraph(
                            f"<b>{suspicious_count}</b>",
                            styles["body"],
                        ),
                        Paragraph(
                            f"<b>{undetected_count}</b>",
                            styles["body"],
                        ),
                        Paragraph(
                            f"<b>{harmless_count}</b>",
                            styles["body"],
                        ),
                    ],
                ],
                colWidths=[
                    1.575 * inch,
                    1.575 * inch,
                    1.575 * inch,
                    1.575 * inch,
                ],
                hAlign="CENTER",
            )

            vt_table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            SURFACE,
                        ),
                        (
                            "BOX",
                            (0, 0),
                            (-1, -1),
                            0.6,
                            BORDER,
                        ),
                        (
                            "INNERGRID",
                            (0, 0),
                            (-1, -1),
                            0.4,
                            BORDER,
                        ),
                        (
                            "ALIGN",
                            (0, 0),
                            (-1, -1),
                            "CENTER",
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "MIDDLE",
                        ),
                        (
                            "TOPPADDING",
                            (0, 0),
                            (-1, -1),
                            8,
                        ),
                        (
                            "BOTTOMPADDING",
                            (0, 0),
                            (-1, -1),
                            8,
                        ),
                    ]
                )
            )

            story.append(
                vt_table
            )


        story.append(
            Spacer(
                1,
                10,
            )
        )

        if is_link:
            reputation_text += (
                " Only the link's domain was looked up, "
                "never the full link."
            )

        story.append(
            Paragraph(
                reputation_text,
                styles["body"],
            )
        )

        story.append(
            Spacer(
                1,
                17,
            )
        )


    story.append(
        Paragraph(
            "Email Evidence" if is_email
            else (
                "QR Code Evidence" if is_qr
                else ("Link Evidence" if is_link else "File Evidence")
            ),
            styles["section"],
        )
    )

    if is_email:

        _append_email_evidence(
            story,
            details,
            styles,
        )

    elif is_qr:

        _append_qr_evidence(
            story,
            details,
            styles,
        )

    elif is_link:

        scheme = link_info.get("scheme")

        connection = {
            "https": "Encrypted (https)",
            "http": "Not encrypted (http)",
        }.get(scheme, scheme or "Unknown")

        link_rows = [
            (
                "Analysis Type",
                "Link",
            ),
            (
                "Domain",
                link_info.get("registered_domain")
                or link_info.get("host")
                or "Not applicable",
            ),
            (
                "Connection",
                connection,
            ),
        ]

        if details.get("unwrapped_from"):
            link_rows.append(
                (
                    "Rewritten By",
                    details["unwrapped_from"],
                )
            )

        story.append(
            _field_table(
                link_rows,
                styles,
            )
        )

        # Long addresses have no spaces, so this style lets them wrap
        # at any character instead of running off the page.
        address_style = ParagraphStyle(
            "PreClearAddress",
            parent=styles["hash"],
            wordWrap="CJK",
        )

        address_rows = [
            [
                Paragraph(
                    "FULL ADDRESS (SHOWN AS TEXT, NOT A LINK)",
                    styles["label"],
                ),
            ],
            [
                Paragraph(
                    _safe(analysis.target or analysis.filename),
                    address_style,
                ),
            ],
        ]

        if details.get("inner"):
            address_rows += [
                [
                    Paragraph(
                        "ORIGINAL DESTINATION INSIDE THE REWRITTEN LINK",
                        styles["label"],
                    ),
                ],
                [
                    Paragraph(
                        _safe(details["inner"].get("link")),
                        address_style,
                    ),
                ],
            ]

        address_table = Table(
            address_rows,
            colWidths=[
                6.3 * inch,
            ],
        )

        address_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        SURFACE,
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.6,
                        BORDER,
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        9,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        9,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                ]
            )
        )

        story.append(
            Spacer(
                1,
                12,
            )
        )

        story.append(
            address_table
        )

    else:

        story.append(
            _field_table(
                [
                    (
                        "Extension",
                        analysis.extension
                        or "Unknown",
                    ),
                    (
                        "MIME Type",
                        analysis.mime_type
                        or "Unknown",
                    ),
                    (
                        "File Size",
                        f"{analysis.file_size:,} bytes",
                    ),
                ],
                styles,
            )
        )

    story.append(
        Spacer(
            1,
            12,
        )
    )

    hash_table = Table(
        [
            [
                Paragraph(
                    "SHA-256 FINGERPRINT OF THE ADDRESS"
                    if is_link
                    else (
                        "SHA-256 FINGERPRINT OF THE MESSAGE"
                        if is_email
                        else (
                            "SHA-256 FINGERPRINT OF THE FILE"
                            if is_qr
                            else "SHA-256 FINGERPRINT"
                        )
                    ),
                    styles["label"],
                ),
            ],
            [
                Paragraph(
                    _safe(analysis.sha256),
                    styles["hash"],
                ),
            ],
        ],
        colWidths=[
            6.3 * inch,
        ],
    )

    hash_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    SURFACE,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    BORDER,
                ),
                (
                    "LINEBELOW",
                    (0, 0),
                    (-1, 0),
                    0.4,
                    BORDER,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    story.append(
        hash_table
    )

    story.append(
        Spacer(
            1,
            20,
        )
    )

    story.append(
        Paragraph(
            "Review & Resolution",
            styles["section"],
        )
    )

    reviewer_name = (
        reviewed_by_user.name
        if reviewed_by_user
        else "—"
    )

    story.append(
        _field_table(
            [
                (
                    "Review Status",
                    _review_label(
                        analysis.review_status
                    ),
                ),
                (
                    "Reviewed By",
                    reviewer_name,
                ),
                (
                    "Reviewed",
                    _format_datetime(
                        analysis.reviewed_at
                    ),
                ),
                (
                    "Resolution",
                    (
                        "Completed"
                        if analysis.review_status
                        == "resolved"
                        else "Pending"
                    ),
                ),
            ],
            styles,
        )
    )

    if analysis.resolution_note:

        story.append(
            Spacer(
                1,
                12,
            )
        )

        story.append(
            KeepTogether(
                [
                    Paragraph(
                        "Resolution Note",
                        styles["label"],
                    ),
                    Spacer(
                        1,
                        5,
                    ),
                    Paragraph(
                        _safe(analysis.resolution_note),
                        styles["body"],
                    ),
                ]
            )
        )

    story.append(
        Spacer(
            1,
            24,
        )
    )

    story.append(
        Paragraph(
            (
                "Generated by PreClear Business. "
                "This report reflects the Evidence Record "
                "stored at the time of export."
            ),
            styles["small"],
        )
    )

    document.build(
        story,
        onFirstPage=_draw_pdf_footer,
        onLaterPages=_draw_pdf_footer,
    )

    pdf_bytes = buffer.getvalue()

    buffer.close()

    return pdf_bytes

def build_decision_ledger_pdf(
    *,
    analyses,
    organization,
) -> bytes:
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.45 * inch,
        leftMargin=0.45 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.72 * inch,
        title="Decision Ledger",
        author="PreClear Business",
    )

    styles = _make_styles()

    story = []

    if PRECLEAR_SHIELD_PATH.exists():

        shield = Image(
            str(PRECLEAR_SHIELD_PATH),
            width=0.50 * inch,
            height=0.50 * inch,
        )

        brand = Paragraph(
            "<b>PreClear Business</b>",
            styles["eyebrow"],
        )

        brand_header = Table(
            [[shield, brand]],
            colWidths=[
                0.55 * inch,
                6.1 * inch,
            ],
            hAlign="CENTER",
        )

        brand_header.setStyle(
            TableStyle(
                [
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        0,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        0,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        0,
                    ),
                ]
            )
        )

        story.append(
            brand_header
        )

    else:

        story.append(
            Paragraph(
                "PreClear Business",
                styles["eyebrow"],
            )
        )

    story.append(
        Spacer(
            1,
            8,
        )
    )

    story.append(
        Paragraph(
            "Decision Ledger",
            styles["title"],
        )
    )

    story.append(
        Paragraph(
            (
                f"{_safe(organization.name)} · "
                "Trust Decision and Evidence Record history."
            ),
            styles["subtitle"],
        )
    )

    story.append(
        Spacer(
            1,
            18,
        )
    )

    total = len(
        analyses
    )

    safe = sum(
        1
        for analysis in analyses
        if analysis.decision == "LOOKS_SAFE"
    )

    caution = sum(
        1
        for analysis in analyses
        if analysis.decision == "USE_CAUTION"
    )

    danger = sum(
        1
        for analysis in analyses
        if analysis.decision == "DO_NOT_OPEN"
    )

    summary_table = Table(
        [
            [
                Paragraph(
                    "TOTAL DECISIONS",
                    styles["label"],
                ),
                Paragraph(
                    "LOOKS SAFE",
                    styles["label"],
                ),
                Paragraph(
                    "USE CAUTION",
                    styles["label"],
                ),
                Paragraph(
                    "DO NOT OPEN",
                    styles["label"],
                ),
            ],
            [
                Paragraph(
                    f"<b>{total}</b>",
                    styles["body"],
                ),
                Paragraph(
                    f"<b>{safe}</b>",
                    styles["body"],
                ),
                Paragraph(
                    f"<b>{caution}</b>",
                    styles["body"],
                ),
                Paragraph(
                    f"<b>{danger}</b>",
                    styles["body"],
                ),
            ],
        ],
        colWidths=[
            1.65 * inch,
            1.65 * inch,
            1.65 * inch,
            1.65 * inch,
        ],
    )

    summary_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor(
                        "#EDF3FF"
                    ),
                ),
                (
                    "TEXTCOLOR",
                    (0, 1),
                    (0, 1),
                    PRECLEAR_BLUE,
                ),
                (
                    "BACKGROUND",
                    (1, 0),
                    (1, -1),
                    SAFE_SOFT,
                ),
                (
                    "TEXTCOLOR",
                    (1, 1),
                    (1, 1),
                    SAFE,
                ),
                (
                    "BACKGROUND",
                    (2, 0),
                    (2, -1),
                    CAUTION_SOFT,
                ),
                (
                    "TEXTCOLOR",
                    (2, 1),
                    (2, 1),
                    CAUTION,
                ),
                (
                    "BACKGROUND",
                    (3, 0),
                    (3, -1),
                    DANGER_SOFT,
                ),
                (
                    "TEXTCOLOR",
                    (3, 1),
                    (3, 1),
                    DANGER,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    BORDER,
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    BORDER,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    story.append(
        summary_table
    )

    story.append(
        Spacer(
            1,
            18,
        )
    )

    story.append(
        Paragraph(
            "Evidence Records",
            styles["section"],
        )
    )

    table_rows = [
        [
            Paragraph(
                "FILE",
                styles["label"],
            ),
            Paragraph(
                "ENVIRONMENT",
                styles["label"],
            ),
            Paragraph(
                "ANALYZED BY",
                styles["label"],
            ),
            Paragraph(
                "RECORDED",
                styles["label"],
            ),
            Paragraph(
                "REVIEW",
                styles["label"],
            ),
            Paragraph(
                "TRUST DECISION",
                styles["label"],
            ),
        ]
    ]

    for analysis in analyses:

        table_rows.append(
            [
                Paragraph(
                    _safe(analysis.filename),
                    _fit_style(
                        analysis.filename,
                        styles["small"],
                    ),
                ),
                Paragraph(
                    _safe(
                        analysis.environment.name
                        if analysis.environment
                        else "—"
                    ),
                    styles["small"],
                ),
                Paragraph(
                    _safe(
                        analysis.user.name
                        if analysis.user
                        else "System"
                    ),
                    styles["small"],
                ),
                Paragraph(
                    _format_datetime(
                        analysis.created_at
                    ),
                    styles["small"],
                ),
                Paragraph(
                    _review_label(
                        analysis.review_status
                    ),
                    styles["small"],
                ),
                Paragraph(
                    _decision_label(
                        analysis.decision,
                        getattr(analysis, "analysis_type", None),
                    ),
                    styles["small"],
                ),
            ]
        )

    ledger_table = Table(
        table_rows,
        repeatRows=1,
        colWidths=[
            1.55 * inch,
            1.05 * inch,
            0.95 * inch,
            1.25 * inch,
            0.85 * inch,
            1.05 * inch,
        ],
        hAlign="CENTER",
    )

    ledger_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    SURFACE,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    BORDER,
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    BORDER,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(
        ledger_table
    )

    story.append(
        Spacer(
            1,
            20,
        )
    )

    story.append(
        Paragraph(
            (
                "Generated by PreClear Business. "
                "This report reflects the Decision Ledger "
                "stored at the time of export."
            ),
            styles["small"],
        )
    )

    document.build(
        story,
        onFirstPage=_draw_pdf_footer,
        onLaterPages=_draw_pdf_footer,
    )

    pdf_bytes = buffer.getvalue()

    buffer.close()

    return pdf_bytes

def build_activity_log_pdf(
    *,
    events,
    organization,
    activity_type: str = "",
    user_name: str = "",
    date_range: str = "",
) -> bytes:
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.45 * inch,
        leftMargin=0.45 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.72 * inch,
        title="Activity Log",
        author="PreClear Business",
    )

    styles = _make_styles()

    story = []

    if PRECLEAR_SHIELD_PATH.exists():

        shield = Image(
            str(PRECLEAR_SHIELD_PATH),
            width=0.50 * inch,
            height=0.50 * inch,
        )

        brand = Paragraph(
            "<b>PreClear Business</b>",
            styles["eyebrow"],
        )

        brand_header = Table(
            [[shield, brand]],
            colWidths=[
                0.55 * inch,
                6.1 * inch,
            ],
            hAlign="CENTER",
        )

        brand_header.setStyle(
            TableStyle(
                [
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        0,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        0,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        0,
                    ),
                ]
            )
        )

        story.append(
            brand_header
        )

    else:

        story.append(
            Paragraph(
                "PreClear Business",
                styles["eyebrow"],
            )
        )

    story.append(
        Spacer(
            1,
            8,
        )
    )

    story.append(
        Paragraph(
            "Activity Log",
            styles["title"],
        )
    )

    story.append(
        Paragraph(
            (
                f"{_safe(organization.name)} · "
                "Security, governance, and administrative activity."
            ),
            styles["subtitle"],
        )
    )

    story.append(
        Spacer(
            1,
            14,
        )
    )

    filter_parts = []

    if activity_type:
        labels = {
            "security": "Security",
            "team": "Team",
            "environment": "Environments",
        }

        filter_parts.append(
            "Activity Type: "
            + labels.get(
                activity_type,
                activity_type.title(),
            )
        )

    if user_name:
        filter_parts.append(
            f"Team Member: {user_name}"
        )

    if date_range:
        filter_parts.append(
            f"Date Range: Last {date_range} Days"
        )

    if filter_parts:

        filter_text = " · ".join(
            filter_parts
        )

    else:

        filter_text = "Filters: All Activity"

    story.append(
        Paragraph(
            _safe(filter_text),
            styles["small"],
        )
    )

    story.append(
        Spacer(
            1,
            16,
        )
    )

    story.append(
        Paragraph(
            f"{len(events)} Recorded Events",
            styles["section"],
        )
    )

    table_rows = [
        [
            Paragraph(
                "RECORDED",
                styles["label"],
            ),
            Paragraph(
                "ACTOR",
                styles["label"],
            ),
            Paragraph(
                "TYPE",
                styles["label"],
            ),
            Paragraph(
                "DESCRIPTION",
                styles["label"],
            ),
        ]
    ]

    for event in events:

        actor = (
            event.user.name
            if event.user
            else "System"
        )

        event_type = (
            event.event_type
            .replace(
                "_",
                " ",
            )
            .title()
        )

        table_rows.append(
            [
                Paragraph(
                    _format_datetime(
                        event.created_at
                    ),
                    styles["small"],
                ),
                Paragraph(
                    _safe(actor),
                    styles["small"],
                ),
                Paragraph(
                    _safe(event_type),
                    styles["small"],
                ),
                Paragraph(
                    _safe(event.description),
                    _fit_style(
                        event.description,
                        styles["small"],
                    ),
                ),
            ]
        )

    activity_table = Table(
        table_rows,
        repeatRows=1,
        colWidths=[
            1.35 * inch,
            1.05 * inch,
            1.35 * inch,
            3.05 * inch,
        ],
        hAlign="CENTER",
    )

    activity_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    SURFACE,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    BORDER,
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    BORDER,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(
        activity_table
    )

    story.append(
        Spacer(
            1,
            20,
        )
    )

    story.append(
        Paragraph(
            (
                "Generated by PreClear Business. "
                "This report reflects the Activity Log "
                "stored at the time of export."
            ),
            styles["small"],
        )
    )

    document.build(
        story,
        onFirstPage=_draw_pdf_footer,
        onLaterPages=_draw_pdf_footer,
    )

    pdf_bytes = buffer.getvalue()

    buffer.close()

    return pdf_bytes

def build_security_summary_pdf(
    *,
    organization,
    total_analyses: int,
    looks_safe_count: int,
    caution_count: int,
    danger_count: int,
    safe_pct: int,
    caution_pct: int,
    danger_pct: int,
    open_evidence_count: int,
    reviewed_evidence_count: int,
    resolved_evidence_count: int,
    recent_activity_count: int,
    environment_activity,
) -> bytes:

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.72 * inch,
        title="30-Day Security Summary",
        author="PreClear Business",
    )

    styles = _make_styles()

    story = []


    # ---------------------------------------------------------
    # BRAND HEADER
    # ---------------------------------------------------------

    if PRECLEAR_SHIELD_PATH.exists():

        shield = Image(
            str(PRECLEAR_SHIELD_PATH),
            width=0.50 * inch,
            height=0.50 * inch,
        )

        brand = Paragraph(
            "<b>PreClear Business</b>",
            styles["eyebrow"],
        )

        brand_header = Table(
            [[shield, brand]],
            colWidths=[
                0.55 * inch,
                6.0 * inch,
            ],
            hAlign="CENTER",
        )

        brand_header.setStyle(
            TableStyle(
                [
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        0,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        0,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        0,
                    ),
                ]
            )
        )

        story.append(
            brand_header
        )

    else:

        story.append(
            Paragraph(
                "PreClear Business",
                styles["eyebrow"],
            )
        )


    story.append(
        Spacer(
            1,
            8,
        )
    )

    story.append(
        Paragraph(
            "30-Day Security Summary",
            styles["title"],
        )
    )

    story.append(
        Paragraph(
            (
                f"{_safe(organization.name)} - "
                "Trust Decision, evidence, and "
                "organizational security activity."
            ),
            styles["subtitle"],
        )
    )

    story.append(
        Spacer(
            1,
            18,
        )
    )


    # ---------------------------------------------------------
    # REPORTING OVERVIEW
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Reporting Overview",
            styles["section"],
        )
    )

    overview_table = _field_table(
        [
            (
                "Organization",
                organization.name,
            ),
            (
                "Reporting Period",
                "Last 30 days",
            ),
            (
                "Total Analyses",
                total_analyses,
            ),
            (
                "Recorded Activity",
                recent_activity_count,
            ),
        ],
        styles,
    )

    story.append(
        overview_table
    )

    story.append(
        Spacer(
            1,
            18,
        )
    )


    # ---------------------------------------------------------
    # TRUST DECISION SUMMARY
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Trust Decision Summary",
            styles["section"],
        )
    )

    decision_table = Table(
        [
            [
                Paragraph(
                    "LOOKS SAFE",
                    styles["label"],
                ),
                Paragraph(
                    "USE CAUTION",
                    styles["label"],
                ),
                Paragraph(
                    "DO NOT OPEN",
                    styles["label"],
                ),
            ],
            [
                Paragraph(
                    (
                        f"<b>{looks_safe_count}</b><br/>"
                        f"{safe_pct}%"
                    ),
                    styles["body"],
                ),
                Paragraph(
                    (
                        f"<b>{caution_count}</b><br/>"
                        f"{caution_pct}%"
                    ),
                    styles["body"],
                ),
                Paragraph(
                    (
                        f"<b>{danger_count}</b><br/>"
                        f"{danger_pct}%"
                    ),
                    styles["body"],
                ),
            ],
        ],
        colWidths=[
            2.05 * inch,
            2.05 * inch,
            2.05 * inch,
        ],
        hAlign="CENTER",
    )

    decision_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    SAFE_SOFT,
                ),
                (
                    "BACKGROUND",
                    (1, 0),
                    (1, -1),
                    CAUTION_SOFT,
                ),
                (
                    "BACKGROUND",
                    (2, 0),
                    (2, -1),
                    DANGER_SOFT,
                ),
                (
                    "TEXTCOLOR",
                    (0, 1),
                    (0, 1),
                    SAFE,
                ),
                (
                    "TEXTCOLOR",
                    (1, 1),
                    (1, 1),
                    CAUTION,
                ),
                (
                    "TEXTCOLOR",
                    (2, 1),
                    (2, 1),
                    DANGER,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    BORDER,
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    BORDER,
                ),
                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER",
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
            ]
        )
    )

    story.append(
        decision_table
    )

    story.append(
        Spacer(
            1,
            18,
        )
    )


    # ---------------------------------------------------------
    # EVIDENCE REVIEW STATUS
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Evidence Review Status",
            styles["section"],
        )
    )

    evidence_table = Table(
        [
            [
                Paragraph(
                    "OPEN",
                    styles["label"],
                ),
                Paragraph(
                    "REVIEWED",
                    styles["label"],
                ),
                Paragraph(
                    "RESOLVED",
                    styles["label"],
                ),
            ],
            [
                Paragraph(
                    f"<b>{open_evidence_count}</b>",
                    styles["body"],
                ),
                Paragraph(
                    f"<b>{reviewed_evidence_count}</b>",
                    styles["body"],
                ),
                Paragraph(
                    f"<b>{resolved_evidence_count}</b>",
                    styles["body"],
                ),
            ],
        ],
        colWidths=[
            2.05 * inch,
            2.05 * inch,
            2.05 * inch,
        ],
        hAlign="CENTER",
    )

    evidence_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    SURFACE,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    BORDER,
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    BORDER,
                ),
                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER",
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
            ]
        )
    )

    story.append(
        evidence_table
    )

    story.append(
        Spacer(
            1,
            18,
        )
    )


    # ---------------------------------------------------------
    # ENVIRONMENT ACTIVITY
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Environment Activity",
            styles["section"],
        )
    )

    if environment_activity:

        environment_rows = [
            [
                Paragraph(
                    "ENVIRONMENT",
                    styles["label"],
                ),
                Paragraph(
                    "ANALYSES",
                    styles["label"],
                ),
                Paragraph(
                    "ATTENTION",
                    styles["label"],
                ),
            ]
        ]

        for item in environment_activity:

            environment_rows.append(
                [
                    Paragraph(
                        _safe(item["environment"].name),
                        styles["body"],
                    ),
                    Paragraph(
                        str(
                            item["analysis_count"]
                        ),
                        styles["body"],
                    ),
                    Paragraph(
                        str(
                            item["attention_count"]
                        ),
                        styles["body"],
                    ),
                ]
            )

        environment_table = Table(
            environment_rows,
            colWidths=[
                3.75 * inch,
                1.2 * inch,
                1.2 * inch,
            ],
            repeatRows=1,
            hAlign="CENTER",
        )

        environment_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        SURFACE,
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.6,
                        BORDER,
                    ),
                    (
                        "INNERGRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        BORDER,
                    ),
                    (
                        "ALIGN",
                        (1, 0),
                        (-1, -1),
                        "CENTER",
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                ]
            )
        )

        story.append(
            environment_table
        )

    else:

        story.append(
            Paragraph(
                (
                    "No environment activity was "
                    "recorded during this period."
                ),
                styles["body"],
            )
        )

    story.append(
        Spacer(
            1,
            18,
        )
    )


    # ---------------------------------------------------------
    # SECURITY SUMMARY
    # ---------------------------------------------------------

    attention_count = (
        caution_count
        + danger_count
    )

    story.append(
        Paragraph(
            "Security Summary",
            styles["section"],
        )
    )

    if total_analyses == 0:

        summary_text = (
            "No analyses were recorded during "
            "the reporting period."
        )

    elif attention_count == 0:

        summary_text = (
            f"PreClear completed {total_analyses} "
            "analyses during the reporting period. "
            "No Trust Decisions required additional "
            "attention."
        )

    else:

        summary_text = (
            f"PreClear completed {total_analyses} "
            "analyses during the reporting period. "
            f"{attention_count} "
            + (
                "analysis required"
                if attention_count == 1
                else "analyses required"
            )
            + " additional attention, including "
            f"{danger_count} Do Not Open "
            + (
                "decision."
                if danger_count == 1
                else "decisions."
            )
        )

    summary_box = Table(
        [
            [
                Paragraph(
                    summary_text,
                    styles["body"],
                )
            ]
        ],
        colWidths=[
            6.15 * inch,
        ],
        hAlign="CENTER",
    )

    summary_box.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor(
                        "#EDF3FF"
                    ),
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    colors.HexColor(
                        "#C9D8F2"
                    ),
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    12,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    12,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
            ]
        )
    )

    story.append(
        summary_box
    )


    document.build(
        story,
        onFirstPage=_draw_pdf_footer,
        onLaterPages=_draw_pdf_footer,
    )

    pdf_bytes = buffer.getvalue()

    buffer.close()

    return pdf_bytes