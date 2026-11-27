from __future__ import annotations

import hashlib
import mimetypes
import re
import unicodedata
from pathlib import Path

from app.services.virustotal_service import (
    lookup_file_hash,
)


# Uploads above this size are rejected before analysis.
MAX_UPLOAD_BYTES = 50 * 1024 * 1024

# Files above this size are analyzed but flagged for extra review.
LARGE_FILE_BYTES = 25 * 1024 * 1024

# Must match the column sizes on the Analysis model.
MAX_FILENAME_LENGTH = 255
MAX_EXTENSION_LENGTH = 40
MAX_MIME_LENGTH = 120


RISK_ORDER = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
}

DECISION_FOR_RISK = {
    "LOW": "LOOKS_SAFE",
    "MEDIUM": "USE_CAUTION",
    "HIGH": "DO_NOT_OPEN",
}


# File types that can run code or change the system when opened.
HIGH_RISK_EXTENSIONS = {
    ".exe", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle",
    ".bat", ".cmd", ".com", ".scr", ".pif", ".cpl", ".dll",
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".jar", ".lnk", ".scf", ".reg",
    ".application", ".gadget", ".sh", ".app", ".command",
}

# Compressed or installable files.
CAUTION_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".cab", ".dmg", ".pkg",
}

# Disk images are often used to slip programs past email filters.
DISK_IMAGE_EXTENSIONS = {
    ".iso", ".img", ".vhd", ".vhdx",
}

# Office files that can contain macros.
MACRO_EXTENSIONS = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".xlsb",
    ".pptm", ".potm", ".ppam", ".ppsm", ".sldm",
}

# Files that open in a browser and are often used for fake login pages.
WEB_CONTENT_EXTENSIONS = {
    ".html", ".htm", ".shtml", ".xhtml", ".mht", ".mhtml", ".svg",
}

ONENOTE_EXTENSIONS = {
    ".one", ".onepkg",
}

# Extensions people expect to be harmless documents or media. Used to
# spot names like "invoice.pdf.exe".
DOCUMENT_LIKE_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".rtf", ".csv", ".odt", ".ods", ".jpg", ".jpeg",
    ".png", ".gif", ".bmp", ".mp3", ".mp4", ".mov", ".wav",
}

# What a file's first bytes should look like for common extensions.
EXPECTED_SIGNATURES = {
    ".pdf": {"pdf"},
    ".docx": {"zip"}, ".xlsx": {"zip"}, ".pptx": {"zip"},
    ".dotx": {"zip"}, ".xltx": {"zip"}, ".potx": {"zip"},
    ".ppsx": {"zip"}, ".odt": {"zip"}, ".ods": {"zip"},
    ".odp": {"zip"}, ".epub": {"zip"}, ".zip": {"zip"},
    ".doc": {"ole"}, ".xls": {"ole"}, ".ppt": {"ole"},
    ".msg": {"ole"},
    ".rar": {"rar"}, ".7z": {"7z"}, ".gz": {"gzip"},
    ".png": {"image"}, ".jpg": {"image"}, ".jpeg": {"image"},
    ".gif": {"image"}, ".webp": {"image"},
}

# Office formats that normally use the zip layout. When one of these
# arrives in the older OLE layout instead, it is usually encrypted.
ZIP_OFFICE_EXTENSIONS = {
    ".docx", ".xlsx", ".pptx", ".dotx", ".xltx", ".potx", ".ppsx",
}

EXECUTABLE_SIGNATURES = {
    "windows_executable": "a Windows program",
    "linux_executable": "a Linux program",
    "mac_executable": "a Mac program",
}

# Invisible characters that can reverse or reorder how a file name is
# displayed, e.g. making "invoice[U+202E]fdp.exe" look like "invoiceexe.pdf".
BIDI_CONTROL_CHARACTERS = {
    "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d",
    "\u202e", "\u2066", "\u2067", "\u2068", "\u2069",
}

MIME_TYPE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$"
)


class _Assessment:
    """Collects reasons and only ever raises the risk level."""

    def __init__(self) -> None:
        self.risk_level = "LOW"
        self.reasons: list[str] = []

    def flag(self, risk_level: str, reason: str) -> None:
        if RISK_ORDER[risk_level] > RISK_ORDER[self.risk_level]:
            self.risk_level = risk_level
        self.reasons.append(reason)

    def note(self, reason: str) -> None:
        self.reasons.append(reason)

    @property
    def decision(self) -> str:
        return DECISION_FOR_RISK[self.risk_level]


def clean_filename(raw_name: str | None) -> tuple[str, bool]:
    """
    Returns a display-safe file name and whether hidden direction-control
    characters were removed from it.
    """
    name = (raw_name or "").replace("\\", "/").split("/")[-1]

    had_bidi = any(char in BIDI_CONTROL_CHARACTERS for char in name)

    name = "".join(
        char
        for char in name
        if char not in BIDI_CONTROL_CHARACTERS
        and unicodedata.category(char) != "Cc"
    ).strip()

    if not name:
        name = "unknown"

    if len(name) > MAX_FILENAME_LENGTH:
        suffix = Path(name).suffix[:MAX_EXTENSION_LENGTH]
        name = name[: MAX_FILENAME_LENGTH - len(suffix)] + suffix

    return name, had_bidi


def clean_mime_type(
    client_type: str | None,
    filename: str,
) -> str:
    """Uses the browser's content type only if it is well formed."""
    candidate = (client_type or "").split(";")[0].strip().lower()

    if (
        candidate
        and len(candidate) <= MAX_MIME_LENGTH
        and MIME_TYPE_PATTERN.match(candidate)
    ):
        return candidate

    guessed, _ = mimetypes.guess_type(filename)
    return guessed or "application/octet-stream"


def detect_signature(content: bytes) -> str | None:
    """Identifies a file's real type from its first bytes."""
    head = content[:1024]

    if head.startswith(b"MZ"):
        return "windows_executable"

    if head.startswith(b"\x7fELF"):
        return "linux_executable"

    if head[:4] in {
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    }:
        return "mac_executable"

    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "shortcut"

    if b"%PDF-" in head:
        return "pdf"

    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"

    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"

    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"

    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"

    if head.startswith(b"\x1f\x8b"):
        return "gzip"

    if (
        head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8"))
        or (head[:4] == b"RIFF" and head[8:12] == b"WEBP")
    ):
        return "image"

    if content[0x8001:0x8006] == b"CD001":
        return "disk_image"

    if head.startswith(b"#!"):
        return "script"

    text = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()

    if text.startswith((b"<!doctype html", b"<html", b"<script")):
        return "html"

    if text.startswith(b"<svg") or (
        text.startswith(b"<?xml") and b"<svg" in text
    ):
        return "svg"

    return None


def _check_extension(
    assessment: _Assessment,
    extension: str,
) -> None:
    if extension in HIGH_RISK_EXTENSIONS:
        assessment.flag(
            "HIGH",
            "This file type can execute code or make system changes.",
        )

    elif extension in DISK_IMAGE_EXTENSIONS:
        assessment.flag(
            "MEDIUM",
            "Disk image files can hide programs inside them and are "
            "sometimes used to get past email security filters.",
        )

    elif extension in MACRO_EXTENSIONS:
        assessment.flag(
            "MEDIUM",
            "This Office file type can contain macros. Do not enable "
            "macros or editing unless the sender is verified.",
        )

    elif extension in ONENOTE_EXTENSIONS:
        assessment.flag(
            "MEDIUM",
            "OneNote files can contain embedded attachments that run "
            "when clicked.",
        )

    elif extension in WEB_CONTENT_EXTENSIONS:
        assessment.flag(
            "MEDIUM",
            "Web page files open in a browser and are commonly used "
            "for fake sign-in pages. Do not enter a password into a "
            "page opened from an attachment.",
        )

    elif extension in CAUTION_EXTENSIONS:
        assessment.flag(
            "MEDIUM",
            "Compressed or installable files deserve additional "
            "verification.",
        )

    if not extension:
        assessment.flag(
            "MEDIUM",
            "The file does not have a recognizable extension.",
        )

    if extension == ".msg":
        assessment.note(
            "This is an Outlook message file (.msg). To check the "
            "email's sender, links and attachments, open the email in "
            "Outlook on the web or the new Outlook, choose More actions "
            "(...), then View, then View message source, and paste "
            "everything into Paste an Email's Original on the Analyze "
            "page."
        )


def _check_filename_tricks(
    assessment: _Assessment,
    filename: str,
    extension: str,
    had_bidi: bool,
) -> None:
    if had_bidi:
        assessment.flag(
            "HIGH",
            "The file name contained hidden characters that can make "
            "it appear to end in a different extension. PreClear "
            f"removed them; the real extension is {extension or 'missing'}.",
        )

    suffixes = [
        suffix.strip().lower()
        for suffix in Path(filename).suffixes
    ]

    if (
        len(suffixes) >= 2
        and suffixes[-2] in DOCUMENT_LIKE_EXTENSIONS
        and extension in HIGH_RISK_EXTENSIONS
    ):
        assessment.flag(
            "HIGH",
            f"The name looks like a {suffixes[-2]} file, but it "
            f"actually ends in {extension}. Double extensions are a "
            "common way to disguise programs.",
        )

    if re.search(r"\s{5,}\.[^.]+$", filename):
        assessment.flag(
            "MEDIUM",
            "The file name has a long run of spaces before its "
            "extension, which can push the real extension out of view.",
        )


def _check_signature(
    assessment: _Assessment,
    signature: str | None,
    extension: str,
) -> None:
    if signature in EXECUTABLE_SIGNATURES:
        if extension not in HIGH_RISK_EXTENSIONS:
            shown = extension or "no extension"
            assessment.flag(
                "HIGH",
                "The file's contents are "
                f"{EXECUTABLE_SIGNATURES[signature]}, but its name "
                f"ends in {shown}. Programs disguised as other file "
                "types are a common attack.",
            )
        return

    if signature == "shortcut" and extension != ".lnk":
        assessment.flag(
            "HIGH",
            "The file's contents are a Windows shortcut, which can "
            "run commands when opened.",
        )
        return

    if signature == "script" and extension not in HIGH_RISK_EXTENSIONS:
        assessment.flag(
            "MEDIUM",
            "The file's contents are a script that can run commands.",
        )
        return

    if (
        signature in {"html", "svg"}
        and extension not in WEB_CONTENT_EXTENSIONS
    ):
        assessment.flag(
            "MEDIUM",
            "The file's contents are web page code, which does not "
            "match its name. Web page files are commonly used for "
            "fake sign-in pages.",
        )
        return

    if signature == "disk_image" and extension not in DISK_IMAGE_EXTENSIONS:
        assessment.flag(
            "MEDIUM",
            "The file's contents are a disk image, which does not "
            "match its name.",
        )
        return

    expected = EXPECTED_SIGNATURES.get(extension)

    if expected is None or signature in expected:
        return

    if signature == "ole" and extension in ZIP_OFFICE_EXTENSIONS:
        assessment.flag(
            "MEDIUM",
            "This Office file appears to be password-protected or "
            "encrypted, which prevents its contents from being "
            "inspected. Confirm the password with the sender by "
            "another channel, not from the same message.",
        )
        return

    assessment.flag(
        "MEDIUM",
        f"The file's contents do not match its {extension} extension. "
        "A mismatched file may have been renamed to hide what it is.",
    )


def _check_virustotal(
    assessment: _Assessment,
    vt_result: dict,
) -> None:
    if not (vt_result.get("available") and vt_result.get("found")):
        return

    vt_malicious = int(vt_result.get("malicious", 0))
    vt_suspicious = int(vt_result.get("suspicious", 0))

    if vt_malicious > 0:
        assessment.flag(
            "HIGH",
            "VirusTotal threat intelligence reported "
            f"{vt_malicious} malicious detection"
            + ("." if vt_malicious == 1 else "s."),
        )

    elif vt_suspicious > 0:
        assessment.flag(
            "MEDIUM",
            "VirusTotal threat intelligence reported "
            f"{vt_suspicious} suspicious detection"
            + ("." if vt_suspicious == 1 else "s."),
        )

    else:
        assessment.note(
            "VirusTotal recognized this file hash and reported no "
            "malicious or suspicious detections in the latest "
            "available analysis."
        )


def analyze_file(
    filename: str,
    content: bytes,
    content_type: str | None = None,
    check_reputation: bool = True,
) -> dict:
    """
    Inspects an uploaded file. This function is blocking (hashing and a
    VirusTotal request), so async routes must call it through
    run_in_threadpool.
    """
    display_name, had_bidi = clean_filename(filename)

    extension = Path(display_name).suffix.lower()[:MAX_EXTENSION_LENGTH]

    mime_type = clean_mime_type(content_type, display_name)

    file_size = len(content)

    sha256 = hashlib.sha256(content).hexdigest()

    signature = detect_signature(content)

    vt_result = (
        lookup_file_hash(sha256)
        if check_reputation
        else {"available": False, "found": False, "error": "skipped"}
    )

    assessment = _Assessment()

    _check_extension(assessment, extension)
    _check_filename_tricks(assessment, display_name, extension, had_bidi)
    _check_signature(assessment, signature, extension)

    if file_size > LARGE_FILE_BYTES:
        assessment.flag(
            "MEDIUM",
            "The file is unusually large and deserves additional review.",
        )

    _check_virustotal(assessment, vt_result)

    if not assessment.reasons:
        assessment.note(
            "No obvious high-risk file characteristics were identified "
            "by the initial inspection."
        )

    decision = assessment.decision

    if decision == "LOOKS_SAFE":
        explanation = (
            "PreClear did not identify obvious warning signs "
            "in this initial inspection. Continue to use "
            "normal business judgment before opening the file."
        )

    elif decision == "USE_CAUTION":
        explanation = (
            "PreClear identified characteristics that deserve "
            "additional verification before the file is opened "
            "or distributed internally."
        )

    else:
        explanation = (
            "PreClear identified characteristics associated "
            "with higher-risk file types. Do not open the file "
            "unless its source and purpose can be independently verified."
        )

    return {
        "filename": display_name,
        "extension": extension or None,
        "mime_type": mime_type,
        "file_size": file_size,
        "sha256": sha256,
        "detected_type": signature,
        "risk_level": assessment.risk_level,
        "virustotal": vt_result,
        "decision": decision,
        "explanation": explanation,
        "reasons": assessment.reasons,
    }
