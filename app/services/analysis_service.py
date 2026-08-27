from __future__ import annotations

import hashlib
import mimetypes
from pathlib import Path

from app.services.virustotal_service import (
    lookup_file_hash,
)


HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
}

CAUTION_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".dmg",
    ".pkg",
}


def analyze_file(
    filename: str,
    content: bytes,
    content_type: str | None = None,
) -> dict:
    extension = (
        Path(filename).suffix.lower()
        if filename
        else ""
    )

    sha256 = hashlib.sha256(
        content
    ).hexdigest()

    vt_result = lookup_file_hash(
        sha256
    )

    detected_mime, _ = mimetypes.guess_type(
        filename
    )

    mime_type = (
        content_type
        or detected_mime
        or "application/octet-stream"
    )

    file_size = len(content)

    reasons: list[str] = []

    risk_level = "LOW"
    decision = "LOOKS_SAFE"

    if extension in HIGH_RISK_EXTENSIONS:
        risk_level = "HIGH"
        decision = "DO_NOT_OPEN"

        reasons.append(
            "This file type can execute code "
            "or make system changes."
        )

    elif extension in CAUTION_EXTENSIONS:
        risk_level = "MEDIUM"
        decision = "USE_CAUTION"

        reasons.append(
            "Compressed or installable files "
            "deserve additional verification."
        )

    if not extension:
        if decision != "DO_NOT_OPEN":
            risk_level = "MEDIUM"
            decision = "USE_CAUTION"

        reasons.append(
            "The file does not have a recognizable extension."
        )

    if file_size > 25 * 1024 * 1024:
        if decision == "LOOKS_SAFE":
            risk_level = "MEDIUM"
            decision = "USE_CAUTION"

        reasons.append(
            "The file is unusually large and "
            "deserves additional review."
        )

    if (
        vt_result.get("available")
        and vt_result.get("found")
    ):

        vt_malicious = int(
            vt_result.get(
                "malicious",
                0,
            )
        )

        vt_suspicious = int(
            vt_result.get(
                "suspicious",
                0,
            )
        )

        if vt_malicious > 0:

            risk_level = "HIGH"
            decision = "DO_NOT_OPEN"

            reasons.append(
                (
                    "VirusTotal threat intelligence "
                    f"reported {vt_malicious} malicious "
                    "detection"
                    + (
                        "."
                        if vt_malicious == 1
                        else "s."
                    )
                )
            )

        elif vt_suspicious > 0:

            if decision != "DO_NOT_OPEN":
                risk_level = "MEDIUM"
                decision = "USE_CAUTION"

            reasons.append(
                (
                    "VirusTotal threat intelligence "
                    f"reported {vt_suspicious} suspicious "
                    "detection"
                    + (
                        "."
                        if vt_suspicious == 1
                        else "s."
                    )
                )
            )

        else:

            reasons.append(
                (
                    "VirusTotal recognized this file hash "
                    "and reported no malicious or suspicious "
                    "detections in the latest available analysis."
                )
            )

    if not reasons:
        reasons.append(
            "No obvious high-risk file characteristics "
            "were identified by the initial inspection."
        )

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
        "filename": filename,
        "extension": extension or None,
        "mime_type": mime_type,
        "file_size": file_size,
        "sha256": sha256,
        "risk_level": risk_level,
        "virustotal": vt_result,
        "decision": decision,
        "explanation": explanation,
        "reasons": reasons,
    }