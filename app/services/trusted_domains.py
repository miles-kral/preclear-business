"""
Trusted domains: an organization's own domains and its key vendors.

The generic brand list in link_analysis catches imitations of companies
like PayPal or Microsoft. This module catches imitations of the companies
that matter to one particular customer, such as acrne-supply.com posing as
their supplier acme-supply.com. That is the core of invoice fraud, and no
generic list can cover it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.link_analysis import (
    _EXTRACT,
    _decode_host,
    _edit_distance,
    _skeleton,
)


MAX_TRUSTED_DOMAINS = 200

KIND_LABELS = {
    "own": "your organization's own domain",
    "vendor": "a vendor your organization trusts",
}


@dataclass(frozen=True)
class TrustedEntry:
    domain: str
    label: str
    kind: str

    @property
    def name(self) -> str:
        """The part before the ending: "acme-supply" in acme-supply.com."""
        return _EXTRACT(self.domain).domain

    @property
    def description(self) -> str:
        return KIND_LABELS.get(self.kind, KIND_LABELS["vendor"])


@dataclass(frozen=True)
class Lookalike:
    entry: TrustedEntry
    reason: str


class TrustedContext:
    """The trusted domains of one organization, ready for matching."""

    def __init__(self, entries: list[TrustedEntry] | tuple = ()) -> None:
        self.entries = tuple(entries)
        self._by_domain = {entry.domain: entry for entry in self.entries}

    def __bool__(self) -> bool:
        return bool(self.entries)

    def match(self, registered_domain: str) -> TrustedEntry | None:
        return self._by_domain.get((registered_domain or "").lower())

    def lookalike(self, registered_domain: str) -> Lookalike | None:
        """
        Returns the trusted entry a domain imitates, if any. A domain that
        is itself trusted never counts as a lookalike.
        """
        registered = (registered_domain or "").lower()

        if not registered or registered in self._by_domain:
            return None

        extracted = _EXTRACT(registered)
        name = _decode_host(extracted.domain or "")
        suffix = extracted.suffix

        if not name:
            return None

        skeleton = _skeleton(name)

        for entry in self.entries:
            trusted_name = entry.name
            trusted_suffix = _EXTRACT(entry.domain).suffix

            if not trusted_name:
                continue

            trusted_skeleton = _skeleton(trusted_name)

            if name == trusted_name and suffix != trusted_suffix:
                return Lookalike(
                    entry,
                    f"uses the same name with a different ending "
                    f"(.{suffix} instead of .{trusted_suffix})",
                )

            # Very short names match too much by accident.
            if len(trusted_skeleton) < 4:
                continue

            if skeleton == trusted_skeleton:
                return Lookalike(
                    entry,
                    "swaps in look-alike characters or punctuation",
                )

            distance = _edit_distance(skeleton, trusted_skeleton)

            if (len(trusted_skeleton) >= 5 and distance == 1) or (
                len(trusted_skeleton) >= 9 and distance == 2
            ):
                return Lookalike(
                    entry,
                    "differs by only a letter or two",
                )

            if len(trusted_skeleton) >= 5 and trusted_skeleton in skeleton:
                return Lookalike(
                    entry,
                    "adds extra words to the name",
                )

        return None


def normalize_domain(raw: str) -> str | None:
    """
    Turns what someone typed into a registered domain: accepts a domain,
    a web address, or an email address. Returns None if it isn't one.
    """
    text = (raw or "").strip().lower()

    if not text:
        return None

    if "@" in text and "/" not in text:
        text = text.rsplit("@", 1)[-1]

    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = re.split(r"[/?#:]", text, maxsplit=1)[0].strip(".")

    if not text or " " in text:
        return None

    if not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            return None

    if not re.fullmatch(r"[a-z0-9.-]+", text):
        return None

    extracted = _EXTRACT(text)

    if not extracted.domain or not extracted.suffix:
        return None

    return f"{extracted.domain}.{extracted.suffix}"


def load_trusted_context(db, organization_id: int) -> TrustedContext:
    """Loads an organization's trusted domains from the database."""
    from app.models import TrustedDomain

    rows = (
        db.query(TrustedDomain)
        .filter(TrustedDomain.organization_id == organization_id)
        .order_by(TrustedDomain.domain.asc())
        .limit(MAX_TRUSTED_DOMAINS)
        .all()
    )

    return TrustedContext(
        [
            TrustedEntry(domain=row.domain, label=row.label, kind=row.kind)
            for row in rows
        ]
    )
