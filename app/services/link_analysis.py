"""
Static link analysis.

PreClear inspects a link's address without ever visiting it: no HTTP
request, no DNS lookup, no redirect following. That rules out server-side
request forgery and avoids tipping off whoever sent the link. The only
outside call is an optional VirusTotal reputation lookup for the host
name, which reads VirusTotal's stored results and sends only the host,
never the full link.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, unquote, urlsplit

import tldextract

from app.services.analysis_service import (
    CAUTION_EXTENSIONS,
    DISK_IMAGE_EXTENSIONS,
    HIGH_RISK_EXTENSIONS,
    MACRO_EXTENSIONS,
)
from app.services.coverage import (
    DONE,
    NOT_NEEDED,
    check,
    reputation_check,
)
from app.services.virustotal_service import lookup_host


MAX_LINK_LENGTH = 8192

MAX_LABEL_LENGTH = 255

# How many links-inside-links PreClear will unwrap.
MAX_NESTING_DEPTH = 2

# Uses the public suffix list bundled with tldextract. With no URLs and no
# cache directory it never touches the network or the disk.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    include_psl_private_domains=True,
)


RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

DECISION_FOR_RISK = {
    "LOW": "LOOKS_SAFE",
    "MEDIUM": "USE_CAUTION",
    "HIGH": "DO_NOT_OPEN",
}

WEB_SCHEMES = {"http", "https"}

INFO_SCHEMES = {"mailto", "tel", "sms"}

# Schemes that run code or read local files instead of opening a page.
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}

# App-launching schemes that have been abused to run code on Windows.
ABUSED_APP_SCHEMES = {
    "ms-msdt", "search-ms", "search", "ms-officecmd", "ms-word",
    "ms-excel", "ms-powerpoint", "ms-appinstaller", "ms-cxh",
    "ms-cxh-full", "ms-settings", "jar", "smb",
}

URL_SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "tiny.cc", "rb.gy", "s.id", "t.ly", "v.gd", "shorte.st",
    "adf.ly", "bl.ink", "short.io", "tiny.one", "qrco.de", "qr.net",
}

# Services where anyone can publish a page under the service's domain.
SHARED_HOSTING_SUFFIXES = (
    ".web.app", ".firebaseapp.com", ".pages.dev", ".workers.dev",
    ".netlify.app", ".vercel.app", ".github.io", ".glitch.me",
    ".herokuapp.com", ".onrender.com", ".blogspot.com", ".weebly.com",
    ".wixsite.com", ".square.site", ".godaddysites.com", ".webflow.io",
    ".r2.dev", ".ngrok.io", ".ngrok-free.app", ".trycloudflare.com",
    ".azurewebsites.net", ".blob.core.windows.net",
    ".web.core.windows.net", ".s3.amazonaws.com", ".replit.app",
    ".ipfs.dweb.link", ".surge.sh", ".000webhostapp.com",
)

SHARED_HOSTING_HOSTS = {
    "storage.googleapis.com", "sites.google.com", "forms.gle",
    "forms.office.com", "ipfs.io", "dweb.link",
    "s3.amazonaws.com", "notion.site", "canva.site",
}

# Hosts where only some paths let anyone collect information: Google Docs
# documents are ordinary, but Google Forms (docs.google.com/forms) are
# often used to collect passwords.
SHARED_HOSTING_PATHS = {
    "docs.google.com": ("/forms",),
}

# Domain endings that look like file names.
FILE_LIKE_TLDS = {"zip", "mov"}

# Domain endings that turn up often in phishing reports. Legitimate sites
# use them too, so this alone only earns a caution.
OFTEN_ABUSED_TLDS = {
    "top", "xyz", "click", "icu", "cyou", "cfd", "sbs", "rest",
    "quest", "buzz", "tk", "ml", "ga", "cf", "gq", "country",
    "support", "work", "loan", "bond", "lol", "monster", "mom",
}

# Words phishing pages put in a host name to look official.
LURE_WORDS = {
    "login", "signin", "logon", "verify", "verification", "account",
    "accounts", "secure", "security", "update", "password", "wallet",
    "billing", "invoice", "authenticate", "auth", "unlock",
    "suspended", "confirm", "support", "helpdesk", "recovery",
}

# Commonly impersonated brands and the domains they actually use. A host
# whose registered name is exactly the brand (google.de, amazon.co.uk)
# also counts as official.
BRAND_DOMAINS: dict[str, set[str]] = {
    "microsoft": {
        "microsoft.com", "live.com", "office.com", "office365.com",
        "microsoftonline.com", "outlook.com", "sharepoint.com",
        "onedrive.com", "msn.com", "azure.com", "windows.net",
        "bing.com", "skype.com", "microsoft365.com", "1drv.ms",
        "cloud.microsoft", "msft.net", "aka.ms",
    },
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "apple": {"apple.com", "icloud.com", "me.com", "apple.news"},
    "google": {
        "google.com", "gmail.com", "googleusercontent.com", "gstatic.com",
        "youtube.com", "googleapis.com", "withgoogle.com", "goo.gl",
        "googlemail.com",
        "forms.gle", "g.co",
    },
    "amazon": {"amazon.com", "amazonaws.com", "a2z.com", "amzn.to"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com", "db.tt"},
    "adobe": {"adobe.com", "adobesign.com", "adobe.io", "acrobat.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "facebook": {"facebook.com", "fb.com", "facebookmail.com", "fb.me"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "chase": {"chase.com", "jpmorganchase.com", "jpmorgan.com"},
    "wellsfargo": {"wellsfargo.com", "wf.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "citibank": {"citi.com", "citibank.com"},
    "usbank": {"usbank.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com", "binance.us"},
    "intuit": {"intuit.com", "quickbooks.com", "turbotax.com"},
    "quickbooks": {"intuit.com", "quickbooks.com"},
    "irs": {"irs.gov"},
    "usps": {"usps.com", "usps.gov"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},
    "ups": {"ups.com"},
    "zoom": {"zoom.us", "zoom.com", "zoomgov.com"},
    "venmo": {"venmo.com"},
    "zelle": {"zellepay.com", "zelle.com"},
}

# Brand names that are also everyday words or common business names
# (Apple Valley Dental, Chase Ridge Apartments, a Zoom dance studio).
# These count as a brand mention only alongside account words.
EVERYDAY_BRAND_WORDS = {
    "apple", "chase", "outlook", "amazon", "zoom", "ups", "adobe",
}

# Words that turn an everyday brand word into a likely impersonation:
# apple-id-verify, chase-secure-login, outlook-account-update.
ACCOUNT_WORDS = {
    "login", "signin", "logon", "verify", "verification", "account",
    "accounts", "secure", "security", "update", "password", "wallet",
    "billing", "invoice", "authenticate", "auth", "unlock", "suspended",
    "confirm", "support", "helpdesk", "recovery", "id", "pay", "payment",
    "refund", "bank", "banking", "service", "services", "help", "team",
    "care", "online", "alert", "alerts", "mail", "webmail", "portal",
    "delivery", "shipping", "order", "orders", "package", "parcel",
    "track", "tracking", "prime", "gift", "giftcard", "rewards",
    "reward", "claim", "prize", "customer", "meeting", "invite",
}


def brand_mentioned(keyword: str, tokens) -> bool:
    """
    True when a brand keyword among the tokens of a name counts as a brand
    mention. Everyday words need an account word next to them.
    """
    tokens = set(tokens)

    if keyword not in tokens:
        return False

    if keyword in EVERYDAY_BRAND_WORDS:
        return bool(tokens & ACCOUNT_WORDS)

    return True


# Names people use for a brand's products, mapped to the brand.
BRAND_KEYWORDS = {
    **{brand: brand for brand in BRAND_DOMAINS},
    "office365": "microsoft",
    "microsoft365": "microsoft",
    "outlook": "microsoft",
    "onedrive": "microsoft",
    "sharepoint": "microsoft",
    "icloud": "apple",
    "gmail": "google",
    "wells-fargo": "wellsfargo",
}

BRAND_DISPLAY_NAMES = {
    "microsoft": "Microsoft", "paypal": "PayPal", "apple": "Apple",
    "google": "Google", "amazon": "Amazon", "docusign": "DocuSign",
    "dropbox": "Dropbox", "adobe": "Adobe", "netflix": "Netflix",
    "linkedin": "LinkedIn", "facebook": "Facebook",
    "instagram": "Instagram", "whatsapp": "WhatsApp", "chase": "Chase",
    "wellsfargo": "Wells Fargo", "bankofamerica": "Bank of America",
    "citibank": "Citibank", "usbank": "U.S. Bank", "coinbase": "Coinbase",
    "binance": "Binance", "intuit": "Intuit", "quickbooks": "QuickBooks",
    "irs": "the IRS", "usps": "USPS", "fedex": "FedEx", "dhl": "DHL",
    "ups": "UPS", "zoom": "Zoom", "venmo": "Venmo", "zelle": "Zelle",
}

# Character swaps used to make a domain look like a brand.
HOMOGLYPH_SWAPS = (
    ("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"),
    ("3", "e"), ("5", "s"), ("7", "t"), ("4", "a"), ("@", "a"),
    ("$", "s"), ("i", "l"),
)

# Email security services that rewrite links. PreClear unwraps them and
# judges the real destination.
SECURITY_WRAPPERS = {
    "safelinks.protection.outlook.com": "Microsoft Defender Safe Links",
    "urldefense.com": "Proofpoint URL Defense",
    "urldefense.proofpoint.com": "Proofpoint URL Defense",
}

# Letters from other alphabets that look like Latin letters.
CONFUSABLE_LETTERS = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u0501": "d", "\u0261": "g", "\u04cf": "l",
    "\u0455": "s", "\u03bf": "o", "\u03b1": "a", "\u03bd": "v",
    "\u03c1": "p", "\u0432": "b", "\u043a": "k", "\u043c": "m",
    "\u043d": "h", "\u0442": "t",
})

BIDI_AND_INVISIBLE = {
    "\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u2060",
    "\ufeff", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}


class InvalidLinkError(ValueError):
    """The input could not be read as a link."""


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

    def absorb(self, other: "_Assessment", prefix: str) -> None:
        if RISK_ORDER[other.risk_level] > RISK_ORDER[self.risk_level]:
            self.risk_level = other.risk_level
        for reason in other.reasons:
            self.reasons.append(f"{prefix}{reason}")

    @property
    def decision(self) -> str:
        return DECISION_FOR_RISK[self.risk_level]


# ---------------------------------------------------------------- parsing


def normalize_link(raw: str) -> tuple[str, list[str]]:
    """
    Cleans pasted input and undoes common "defanging" such as
    hxxps://example[.]com. Returns the link and notes about what changed.
    """
    notes: list[str] = []

    text = (raw or "").strip().strip("<>\"'").strip()

    had_invisible = any(char in BIDI_AND_INVISIBLE for char in text)

    text = "".join(
        char for char in text
        if char not in BIDI_AND_INVISIBLE
        and unicodedata.category(char) != "Cc"
    )

    # Links copied from emails often wrap across lines.
    text = re.sub(r"\s+", "", text)

    if had_invisible:
        notes.append("invisible")

    refanged = re.sub(r"^hxxp", "http", text, flags=re.IGNORECASE)
    refanged = re.sub(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", ".", refanged,
                      flags=re.IGNORECASE)
    refanged = refanged.replace("[:]", ":").replace("[://]", "://")

    if refanged != text:
        notes.append("defanged")

    if not refanged:
        raise InvalidLinkError("empty")

    if len(refanged) > MAX_LINK_LENGTH:
        raise InvalidLinkError("too_long")

    return refanged, notes


def _scheme_of(link: str) -> str | None:
    match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", link)
    return match.group(1).lower() if match else None


def _parse_obfuscated_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """
    Reads IPv4 addresses written in forms browsers accept but people don't
    recognize, such as 3232235777, 0xC0A80101 or 0300.0250.1.1.
    """
    parts = host.split(".")

    if not 1 <= len(parts) <= 4:
        return None

    values = []

    for part in parts:
        if re.fullmatch(r"0x[0-9a-f]+", part):
            values.append(int(part, 16))
        elif re.fullmatch(r"0[0-7]+", part):
            values.append(int(part, 8))
        elif re.fullmatch(r"[0-9]+", part):
            values.append(int(part))
        else:
            return None

    *head, last = values

    if any(value > 255 for value in head):
        return None

    if last >= 256 ** (4 - len(head)):
        return None

    number = last
    for index, value in enumerate(head):
        number += value << (8 * (3 - index))

    return ipaddress.IPv4Address(number)


def _decode_host(host: str) -> str:
    """Returns the human-readable form of an internationalized host."""
    labels = []

    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
            except (UnicodeError, ValueError):
                labels.append(label)
        else:
            labels.append(label)

    return ".".join(labels)


def _scripts_in(text: str) -> set[str]:
    scripts = set()

    for char in text:
        if char.isalpha():
            try:
                scripts.add(unicodedata.name(char).split()[0])
            except ValueError:
                scripts.add("UNKNOWN")

    return scripts


def _skeleton(text: str) -> str:
    result = text.lower().translate(CONFUSABLE_LETTERS).replace("-", "")
    for fake, real in HOMOGLYPH_SWAPS:
        result = result.replace(fake, real)
    return result


def _edit_distance(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))

    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (char_a != char_b),
            ))
        previous = current

    return previous[-1]


def _host_tokens(host: str) -> list[str]:
    return [token for token in re.split(r"[.\-_]", host) if token]


# ----------------------------------------------------------------- checks


def _check_brand(
    assessment: _Assessment,
    host: str,
    registered_domain: str,
    domain_name: str,
    on_shared_hosting: bool,
    readable_domain_name: str | None = None,
) -> bool:
    """Returns True if the host impersonates a brand."""

    def is_official(brand: str) -> bool:
        return (
            registered_domain in BRAND_DOMAINS[brand]
            or domain_name == brand
        )

    tokens = _host_tokens(host)

    # A brand named in the host, e.g. paypal.account-verify.com.
    for keyword, brand in BRAND_KEYWORDS.items():
        if brand_mentioned(keyword, tokens) and not is_official(brand):
            name = BRAND_DISPLAY_NAMES[brand]
            risk = "HIGH" if on_shared_hosting else "MEDIUM"
            assessment.flag(
                risk,
                f"The address mentions {name}, but {registered_domain} "
                f"is not a {name} domain. The real owner of a link is "
                "the part just before the domain ending.",
            )
            return True

    # A registered name that imitates a brand, e.g. paypa1.com or
    # rnicrosoft.com.
    for brand in BRAND_DOMAINS:
        if is_official(brand) or len(brand) < 4:
            continue

        # Both sides are reduced to a "skeleton" so swapped look-alike
        # characters (1 for l, rn for m, 0 for o) compare as equal.
        skeleton = _skeleton(readable_domain_name or domain_name)
        brand_skeleton = _skeleton(brand)
        name = BRAND_DISPLAY_NAMES[brand]

        imitates = (
            skeleton == brand_skeleton
            or (len(brand) >= 6 and _edit_distance(skeleton, brand_skeleton) == 1)
            or (len(brand) >= 8 and _edit_distance(skeleton, brand_skeleton) == 2)
        )

        if imitates:
            assessment.flag(
                "HIGH",
                f"The domain {registered_domain} closely resembles "
                f"{name}'s name but is not owned by {name}. Lookalike "
                "domains are a common phishing technique.",
            )
            return True

        if len(brand) >= 6 and brand_skeleton in skeleton:
            # Spelled with swapped characters (paypa1-secure) is a
            # deliberate imitation; spelled plainly is only a mention.
            disguised = brand not in domain_name.lower()

            # An everyday word spelled plainly (amazon-rainforest-tours)
            # needs an account word to count.
            if (
                not disguised
                and brand in EVERYDAY_BRAND_WORDS
                and not set(tokens) & ACCOUNT_WORDS
            ):
                continue
            assessment.flag(
                "HIGH" if disguised else "MEDIUM",
                f"The domain {registered_domain} contains "
                + ("a disguised spelling of " if disguised else "")
                + f"{name}'s name but is not a {name} domain.",
            )
            return True

    return False


def _check_trusted(
    assessment: _Assessment,
    registered: str,
    details: dict,
    trusted,
) -> bool:
    """
    Compares a domain with the organization's trusted domains. Returns
    True if the domain is itself trusted.
    """
    if not trusted:
        return False

    entry = trusted.match(registered)

    if entry is not None:
        details["trusted"] = {"label": entry.label, "kind": entry.kind}
        assessment.note(
            f"This link goes to {registered}, which your organization "
            f"lists as trusted ({entry.label})."
        )
        return True

    lookalike = trusted.lookalike(registered)

    if lookalike is not None:
        entry = lookalike.entry
        details["imitates_trusted"] = {
            "label": entry.label,
            "domain": entry.domain,
        }
        assessment.flag(
            "HIGH",
            f"The domain {registered} imitates {entry.label} "
            f"({entry.domain}), {entry.description}. It "
            f"{lookalike.reason}. This is how invoice and payment fraud "
            "usually starts.",
        )

    return False


def _check_host(
    assessment: _Assessment,
    host: str,
    details: dict,
    trusted=None,
    path: str = "",
) -> None:
    # IP addresses instead of names.
    try:
        ip = ipaddress.ip_address(host)
        obfuscated = False
    except ValueError:
        ip = _parse_obfuscated_ipv4(host)
        obfuscated = ip is not None

    if ip is not None:
        details["ip_address"] = str(ip)

        if obfuscated:
            assessment.flag(
                "HIGH",
                f"The address hides a numeric IP address ({ip}) in a "
                "disguised format. Legitimate links almost never do this.",
            )
        else:
            assessment.flag(
                "MEDIUM",
                "The link points to a numeric IP address instead of a "
                "named website, which legitimate businesses rarely use.",
            )

        if ip.is_private or ip.is_loopback or ip.is_link_local:
            assessment.flag(
                "MEDIUM",
                "The IP address belongs to a private or internal "
                "network, so the link would reach a device inside a "
                "network rather than a public website.",
            )
        return

    # Internationalized names that can imitate familiar letters. Browsers
    # accept them either as Unicode or in xn-- (punycode) form.
    if not host.isascii():
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise InvalidLinkError("bad_host") from error
        decoded, host = host, ascii_host
        details["host"] = host
    else:
        decoded = _decode_host(host)

    if decoded != host:
        details["decoded_host"] = decoded

        scripts = _scripts_in(decoded)

        if len(scripts) > 1:
            assessment.flag(
                "HIGH",
                f"The domain mixes letters from different alphabets "
                f"({', '.join(sorted(s.title() for s in scripts))}). "
                f"It displays as {decoded} but is really {host}. This is "
                "a common way to imitate a familiar name.",
            )
        else:
            assessment.flag(
                "MEDIUM",
                f"The domain uses international characters. It displays "
                f"as {decoded}; check that it is the site you expect.",
            )

    extracted = _EXTRACT(host)

    if not extracted.suffix:
        assessment.flag(
            "MEDIUM",
            "The address does not end in a recognized domain ending.",
        )
        details["registered_domain"] = host
        return

    registered = f"{extracted.domain}.{extracted.suffix}"
    details["registered_domain"] = registered

    tld = extracted.suffix.split(".")[-1]

    on_shared_hosting = (
        host in SHARED_HOSTING_HOSTS
        or host.endswith(SHARED_HOSTING_SUFFIXES)
        or (path or "").lower().startswith(SHARED_HOSTING_PATHS.get(host, ("\0",)))
    )

    # URL shorteners hide the destination, and PreClear won't follow them.
    if registered in URL_SHORTENERS or host in URL_SHORTENERS:
        assessment.flag(
            "MEDIUM",
            f"This is a shortened link ({host}), which hides its real "
            "destination. PreClear does not follow links, so the final "
            "address can't be checked. Ask the sender for the full link.",
        )
        details["shortener"] = True

    if on_shared_hosting:
        assessment.flag(
            "MEDIUM",
            "This page is hosted on a service "
            f"({host if host in SHARED_HOSTING_HOSTS else registered}) where "
            "anyone can publish a page. Fake sign-in pages are often "
            "hosted on services like this.",
        )
        details["shared_hosting"] = True

    readable_name = _decode_host(extracted.domain)

    # A domain the organization explicitly trusts skips the generic brand
    # and wording checks; the structural checks above still apply.
    if _check_trusted(assessment, registered, details, trusted):
        return

    impersonates = _check_brand(
        assessment,
        host,
        registered,
        extracted.domain,
        on_shared_hosting,
        readable_name,
    )

    lure_words = sorted(
        {token for token in _host_tokens(host) if token in LURE_WORDS}
    )

    known_brand_domain = any(
        registered in domains for domains in BRAND_DOMAINS.values()
    )

    if lure_words and not known_brand_domain:
        words = ", ".join(f'"{word}"' for word in lure_words)
        assessment.flag(
            "HIGH" if impersonates else "MEDIUM",
            f"The address uses words like {words}, which phishing "
            "pages use to look official.",
        )

    if tld in FILE_LIKE_TLDS:
        assessment.flag(
            "MEDIUM",
            f"The domain ends in .{tld}, which looks like a file name "
            "and can be mistaken for an attachment.",
        )
    elif tld in OFTEN_ABUSED_TLDS:
        assessment.flag(
            "HIGH" if impersonates else "MEDIUM",
            f"This domain ending (.{tld}) is often seen in phishing and "
            "scam links, though legitimate sites use it too.",
        )

    subdomain_labels = [
        label for label in extracted.subdomain.split(".") if label
    ]

    if len(subdomain_labels) >= 4 or len(host) > 70:
        assessment.flag(
            "MEDIUM",
            "The address has an unusually long chain of subdomains, "
            "which can push the real domain out of view.",
        )


def _check_path(
    assessment: _Assessment,
    path: str,
) -> None:
    name = unquote(path).rstrip("/").split("/")[-1].lower()
    extension = PurePosixPath(name).suffix

    # ".com" is also a domain ending, so it is too ambiguous in a path.
    if not extension or extension == ".com" or "@" in name:
        return

    if extension in HIGH_RISK_EXTENSIONS:
        assessment.flag(
            "HIGH",
            f"The link appears to download a program ({extension} file).",
        )
    elif extension in (
        CAUTION_EXTENSIONS | DISK_IMAGE_EXTENSIONS | MACRO_EXTENSIONS
    ):
        assessment.flag(
            "MEDIUM",
            f"The link appears to download a {extension} file, which "
            "deserves verification before opening.",
        )


def _unwrap_security_link(
    host: str,
    path: str,
    query: str,
) -> tuple[str, str] | None:
    """Returns (service name, real link) for rewritten security links."""
    params = dict(parse_qsl(query, keep_blank_values=True))

    if host.endswith("safelinks.protection.outlook.com"):
        target = params.get("url")
        if target:
            return SECURITY_WRAPPERS["safelinks.protection.outlook.com"], target

    if host == "urldefense.com":
        match = re.match(r"^/v3/__(.+?)__;", path)
        if match:
            return SECURITY_WRAPPERS["urldefense.com"], match.group(1)

    if host == "urldefense.proofpoint.com":
        encoded = params.get("u")
        if encoded:
            target = unquote(encoded.replace("-", "%").replace("_", "/"))
            return SECURITY_WRAPPERS["urldefense.proofpoint.com"], target

    return None


def _embedded_links(query: str, fragment: str) -> list[str]:
    """Finds full web addresses hidden in query parameters."""
    found = []

    for _, value in parse_qsl(query, keep_blank_values=True):
        candidate = unquote(value).strip()
        if re.match(r"^https?://", candidate, re.IGNORECASE):
            found.append(candidate)

    fragment_value = unquote(fragment)
    match = re.search(r"https?://\S+", fragment_value, re.IGNORECASE)
    if match:
        found.append(match.group(0))

    return found


# --------------------------------------------------------------- analysis


def _assess(
    link: str,
    details: dict,
    depth: int,
    trusted=None,
) -> _Assessment:
    assessment = _Assessment()

    scheme = _scheme_of(link)

    if scheme is None:
        link = f"http://{link}"
        scheme = "http"
        details["scheme_assumed"] = True

    details["scheme"] = scheme
    details["link"] = link

    if scheme in DANGEROUS_SCHEMES:
        assessment.flag(
            "HIGH",
            f"This is a {scheme}: link, which can run code or open local "
            "files instead of opening a web page.",
        )
        return assessment

    if scheme in INFO_SCHEMES:
        target = link.split(":", 1)[1].split("?")[0]
        action = {
            "mailto": "starts a new email to",
            "tel": "starts a phone call to",
            "sms": "starts a text message to",
        }[scheme]
        assessment.note(
            f"This link {action} {unquote(target)}. It does not open a "
            "web page."
        )
        details["contact"] = unquote(target)
        return assessment

    if scheme not in WEB_SCHEMES:
        risk = "HIGH" if scheme in ABUSED_APP_SCHEMES else "MEDIUM"
        assessment.flag(
            risk,
            f"This {scheme}: link opens a program on your computer "
            "instead of a web page. Links like this have been used to "
            "run malicious code.",
        )
        return assessment

    if "\\" in link:
        assessment.flag(
            "MEDIUM",
            "The address contains backslashes, which browsers treat as "
            "slashes. This is sometimes used to confuse link checkers.",
        )
        link = link.replace("\\", "/")
        details["link"] = link

    try:
        parts = urlsplit(link)
        host = (parts.hostname or "").rstrip(".")
        port = parts.port
    except ValueError as error:
        raise InvalidLinkError("unparseable") from error

    if not host or not re.fullmatch(r"[^\s/?#@]+", host):
        raise InvalidLinkError("no_host")

    if "%" in parts.netloc.split("@")[-1]:
        assessment.flag(
            "HIGH",
            "The domain name contains encoded characters, which hides "
            "what site the link really points to.",
        )
        host = unquote(host).lower()

    details["host"] = host

    if scheme == "http":
        assessment.note(
            "The link does not use an encrypted connection (https). "
            "Never enter a password on a page that isn't https."
        )

    if parts.username is not None:
        assessment.flag(
            "HIGH",
            f'The address contains an "@" trick: the text before "@" '
            f"({unquote(parts.username)}) is ignored, and the link really "
            f"goes to {host}.",
        )

    if port is not None and port not in {80, 443}:
        assessment.flag(
            "MEDIUM",
            f"The link uses an unusual network port ({port}), which "
            "ordinary business websites rarely need.",
        )

    wrapped = _unwrap_security_link(host, parts.path, parts.query)

    if wrapped is not None and depth < MAX_NESTING_DEPTH:
        service, inner = wrapped
        details["unwrapped_from"] = service
        inner_details: dict = {}

        try:
            inner_link, _ = normalize_link(inner)
            inner_assessment = _assess(
                inner_link, inner_details, depth + 1, trusted
            )
        except InvalidLinkError:
            assessment.flag(
                "MEDIUM",
                f"The link was rewritten by {service}, but the original "
                "address inside it could not be read.",
            )
            return assessment

        details["inner"] = {"link": inner_link, **inner_details}
        assessment.note(
            f"This link was rewritten by {service}. PreClear checked "
            f"the original destination: {inner_details.get('host', inner_link)}."
        )
        assessment.absorb(inner_assessment, "")
        return assessment

    _check_host(assessment, host, details, trusted, parts.path)
    _check_path(assessment, parts.path)

    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", parts.path))
    if encoded_count >= 10 and encoded_count * 3 > len(parts.path) * 0.3:
        assessment.flag(
            "MEDIUM",
            "Much of the address is encoded, which can hide where it leads.",
        )

    if depth < MAX_NESTING_DEPTH:
        for inner in _embedded_links(parts.query, parts.fragment)[:3]:
            inner_details = {}
            try:
                inner_link, _ = normalize_link(inner)
                inner_assessment = _assess(
                    inner_link, inner_details, depth + 1, trusted
                )
            except InvalidLinkError:
                continue

            inner_host = inner_details.get("host", inner_link)
            details.setdefault("embedded", []).append(
                {"link": inner_link, **inner_details}
            )
            assessment.flag(
                "MEDIUM",
                f"The link carries a second address ({inner_host}) and may "
                "redirect you there.",
            )
            assessment.absorb(inner_assessment, f"Second address: ")

    return assessment


def _display_label(link: str, details: dict) -> str:
    inner = details.get("inner")
    host = (inner or details).get("host")

    if host:
        source = (inner or details).get("link", link)
        try:
            path = urlsplit(source).path
        except ValueError:
            path = ""
        label = host + (path if path not in {"", "/"} else "")
    else:
        label = link

    if len(label) > MAX_LABEL_LENGTH:
        label = label[: MAX_LABEL_LENGTH - 3] + "..."

    return label


def _check_reputation(
    assessment: _Assessment,
    details: dict,
) -> dict:
    target = details.get("inner") or details
    host = target.get("ip_address") or target.get("host")

    if not host:
        return {"available": False, "found": False, "error": "no_host"}

    result = lookup_host(host)

    if not (result.get("available") and result.get("found")):
        return result

    malicious = int(result.get("malicious", 0))
    suspicious = int(result.get("suspicious", 0))

    # Large, legitimate domains sometimes carry a single stray detection,
    # so one vendor alone earns a caution rather than a block.
    if malicious >= 2:
        assessment.flag(
            "HIGH",
            f"VirusTotal reports {malicious} security vendors flag "
            f"{host} as malicious.",
        )
    elif malicious == 1 or suspicious > 0:
        count = malicious + suspicious
        assessment.flag(
            "MEDIUM",
            f"VirusTotal reports {count} security vendor"
            f"{'' if count == 1 else 's'} flag {host} as malicious or "
            "suspicious.",
        )
    else:
        assessment.note(
            f"VirusTotal has a record of {host} with no malicious or "
            "suspicious detections. A clean reputation does not prove a "
            "specific page is safe."
        )

    return result


def analyze_link(
    raw_link: str,
    check_reputation: bool = True,
    trusted=None,
) -> dict:
    """
    Analyzes a link without visiting it. Blocking (VirusTotal lookup), so
    async routes must call it through run_in_threadpool.

    Raises InvalidLinkError if the input can't be read as a link.
    """
    link, input_notes = normalize_link(raw_link)

    details: dict = {}

    assessment = _assess(link, details, depth=0, trusted=trusted)

    if "invisible" in input_notes:
        assessment.flag(
            "HIGH",
            "The link contained invisible characters, which can make an "
            "address look different from where it really goes. PreClear "
            "removed them before checking.",
        )

    if "defanged" in input_notes:
        details["refanged"] = True
        assessment.note(
            "The link was pasted in a safety format (such as hxxp or "
            "[.]). PreClear restored the real address before checking."
        )

    vt_result = (
        _check_reputation(assessment, details)
        if check_reputation
        else {"available": False, "found": False, "error": "skipped"}
    )

    if not assessment.reasons:
        assessment.note(
            "No warning signs were found in the address itself."
        )

    decision = assessment.decision

    if decision == "LOOKS_SAFE":
        explanation = (
            "PreClear did not find warning signs in this address. "
            "PreClear checks the address without visiting it, so it "
            "cannot see the page itself. If you weren't expecting this "
            "link, go to the site by typing its address yourself."
        )
    elif decision == "USE_CAUTION":
        explanation = (
            "This address has characteristics that deserve verification "
            "before you visit it. If the link claims to come from a "
            "company you know, go to that company's site by typing its "
            "address yourself instead of clicking."
        )
    else:
        explanation = (
            "This address shows strong signs of a deceptive or dangerous "
            "link. Do not visit it unless the sender confirms it through "
            "a channel you already trust."
        )

    link = details.get("link", link)

    checks = [
        check(
            "Address",
            DONE,
            "Checked how the address is built, including hidden "
            "destinations and tricks.",
        ),
        check(
            "Brands and lookalikes",
            DONE,
            "Compared the domain with commonly imitated brands.",
        ),
        (
            check(
                "Your trusted domains",
                DONE,
                "Compared the domain with your organization's trusted "
                "domains.",
            )
            if trusted
            else check(
                "Your trusted domains",
                NOT_NEEDED,
                "Your organization hasn't listed trusted domains yet.",
            )
        ),
        check(
            "Destination page",
            NOT_NEEDED,
            "Never visited, by design.",
        ),
        reputation_check(vt_result, "domain"),
    ]

    return {
        "checks": checks,
        "filename": _display_label(link, details),
        "extension": None,
        "mime_type": None,
        "file_size": len(link.encode("utf-8")),
        "sha256": hashlib.sha256(link.encode("utf-8")).hexdigest(),
        "target": link,
        "details": details,
        "details_json": json.dumps(details),
        "risk_level": assessment.risk_level,
        "virustotal": vt_result,
        "decision": decision,
        "explanation": explanation,
        "reasons": assessment.reasons,
    }
