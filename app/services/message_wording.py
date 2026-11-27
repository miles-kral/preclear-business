"""
Scam wording shared by the text message and email checks.

Each category is a few phrase patterns matched on lower-cased text. A
match is ignored when a negation such as "never" or "don't" comes shortly
before it, so advice like "Never share this code with anyone", which
appears in every genuine sign-in code message, isn't mistaken for a
request.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class WordingSignal:
    key: str
    serious: bool
    reason: str


# How far back (in characters) a negation can cancel a match.
NEGATION_WINDOW = 60

NEGATION = re.compile(
    r"\b(?:never|don'?t|do not|doesn'?t|does not|not|won'?t|will not|"
    r"no one|nobody|cannot|can'?t|shouldn'?t|should not)\b"
)

# Message text beyond this is ignored (texts are short; this bounds the
# work for long emails).
MAX_TEXT = 200_000


# (key, serious on its own, patterns, reason)
CATEGORIES: list[tuple[str, bool, list[str], str]] = [
    (
        "codes",
        True,
        [
            r"(?:send|share|tell|read|give|forward|text)\s+(?:me|us|it|them)?\s*"
            r"(?:back\s+)?(?:the|your|that|this)?\s*(?:\d+[- ]digit\s+)?"
            r"(?:verification\s+|security\s+|login\s+|one[- ]time\s+|"
            r"authentication\s+|confirmation\s+)?(?:code|passcode|pin)\b",
            r"(?:approve|accept|confirm)\s+(?:the\s+|my\s+|this\s+)?"
            r"(?:sign[- ]?in|login|log[- ]in|mfa|push)\s*(?:request|prompt|"
            r"notification)?",
            r"(?:what|which)\s+(?:is\s+)?(?:the\s+)?code\s+(?:you|did you)",
        ],
        "The message asks for a sign-in code or to approve a sign-in. No "
        "legitimate company, colleague or IT team needs your code; sharing "
        "it hands over your account.",
    ),
    (
        "remote_access",
        True,
        [
            r"quick\s*assist|anydesk|teamviewer|ultraviewer|rustdesk|"
            r"screenconnect|connectwise",
            r"remote\s+(?:access|support|session|desktop)",
            r"(?:install|download)\s+(?:this|the|our)\s+(?:app|software|tool)"
            r"\s+(?:so|to)\s+(?:we|i)\s+can",
        ],
        "The message asks for remote access to a computer. Legitimate IT "
        "support rarely asks for this unprompted.",
    ),
    (
        "payment_change",
        False,
        [
            r"(?:new|updated?|chang(?:e|ed|ing)|different)\s+(?:\w+\s+){0,3}"
            r"(?:bank(?:ing)?|account|payment|wire|ach|remittance|routing)"
            r"\s*(?:details|information|info|number|instructions)?",
            r"(?:bank(?:ing)?|account|payment|wire|remittance)\s+(?:details|"
            r"information|instructions)\s+(?:\w+\s+){0,3}(?:changed|updated|"
            r"new)",
        ],
        "The message asks to change payment or bank details. Confirm any "
        "change by calling the sender at a phone number you already have.",
    ),
    (
        "gift_cards",
        False,
        [r"gift\s*cards?", r"(?:apple|google play|itunes|steam|amazon)\s+cards?"],
        "The message mentions gift cards, a payment method scammers favor "
        "because it can't be traced or reversed.",
    ),
    (
        "boss_favor",
        False,
        [
            r"(?:are you|r u)\s+(?:available|free|around|at your desk)",
            r"(?:quick|small|urgent)\s+(?:favor|favour|task|errand)",
            r"(?:i'?m|i am)\s+(?:in a meeting|in meetings|tied up|"
            r"traveling|on a call)",
            r"(?:can'?t|cannot|unable to)\s+(?:talk|call|take calls)",
            r"keep (?:this|it) (?:between us|confidential|quiet)",
        ],
        "The message reads like an executive or manager asking for a quick, "
        "private favor, a common opening for gift-card and payment scams. "
        "Confirm in person or by calling a number you already have.",
    ),
    (
        "account_threat",
        False,
        [
            r"(?:account|mailbox|card|service)\s+(?:has\s+been\s+|will\s+be\s+|"
            r"is\s+)?(?:suspended|locked|disabled|closed|deactivated|"
            r"restricted|on hold)",
            r"unusual\s+(?:sign[- ]?in|activity|login)",
            r"password\s+(?:expires|expired|will expire)",
        ],
        "The message warns that an account is locked, suspended or at risk. "
        "Check by going to the company's site yourself, not through the "
        "message.",
    ),
    (
        "verify_account",
        False,
        [
            r"(?:verify|confirm|validate|update|re-?activate)\s+(?:your\s+)?"
            r"(?:account|identity|details|information|credentials|login|"
            r"payment method|billing)",
        ],
        "The message asks you to sign in or confirm account details. Go to "
        "the site by typing its address yourself instead.",
    ),
    (
        "payment_pressure",
        False,
        [
            r"(?:overdue|past due|outstanding)\s+(?:invoice|balance|payment|"
            r"amount)",
            r"(?:final|last)\s+(?:notice|warning|reminder)",
            r"(?:pay|payment)\s+(?:immediately|today|now|within)",
            r"avoid\s+(?:late fees|penalties|suspension|disconnection|legal)",
        ],
        "The message pressures you to pay quickly. Check any bill through "
        "your own records or the company's usual contact details.",
    ),
    (
        "delivery",
        False,
        [
            r"(?:package|parcel|shipment|delivery)\s+(?:\w+\s+){0,3}"
            r"(?:held|on hold|failed|unsuccessful|undeliverable|pending|"
            r"returned|could not be delivered)",
            r"(?:redelivery|reschedule (?:your )?delivery|update (?:your )?"
            r"(?:delivery|shipping) address)",
            r"(?:usps|ups|fedex|dhl)\b.*\b(?:address|fee|redeliver)",
        ],
        "The message claims a delivery problem. Track packages through the "
        "carrier's own app or site, not a link in a message.",
    ),
    (
        "toll_fine",
        False,
        [
            r"(?:unpaid|outstanding|overdue)\s+(?:toll|tolls|parking|fine|"
            r"ticket|citation)",
            r"(?:toll|parking)\s+(?:balance|violation|notice|fee)",
            r"(?:e-?zpass|fastrak|sunpass|toll\s*tag)",
        ],
        "The message claims an unpaid toll or fine. Toll agencies and "
        "courts rarely text payment links; check through their official "
        "site.",
    ),
    (
        "tax_refund",
        False,
        [
            r"(?:tax|irs)\s+(?:refund|rebate|return)",
            r"(?:irs|internal revenue)",
        ],
        "The message mentions a tax refund or the IRS. The IRS doesn't "
        "contact people by text message.",
    ),
    (
        "prize",
        False,
        [
            r"(?:you'?ve|you have)\s+(?:won|been selected)",
            r"(?:claim|collect)\s+(?:your\s+)?(?:prize|reward|winnings|gift)",
            r"(?:congratulations|congrats)[,!]",
        ],
        "The message says you've won something. Real prizes don't require "
        "a link, a fee or your details by text.",
    ),
    (
        "tech_support",
        False,
        [
            r"(?:subscription|membership|license|antivirus|norton|mcafee|"
            r"geek squad)\s+(?:\w+\s+){0,3}(?:renew|renewed|charged|expired|"
            r"auto-?renew)",
            r"(?:virus|malware|hacked|compromised)\s+(?:detected|found|on your)",
            r"call\s+(?:our|the)\s+(?:support|help|billing)\s+(?:team|desk|line)",
        ],
        "The message looks like a fake renewal or tech-support alert. Check "
        "subscriptions in your own account, and don't call numbers from the "
        "message.",
    ),
    (
        "crypto",
        False,
        [r"bitcoin|crypto(?:currency)?|usdt|ethereum|wallet address|btc\b"],
        "The message involves cryptocurrency. Crypto payments can't be "
        "reversed, and scammers favor them.",
    ),
    (
        "family_emergency",
        False,
        [
            r"(?:mom|dad|grandma|grandpa)[,!]?\s+(?:it'?s me|i'?m in trouble)",
            r"(?:new|changed)\s+(?:my\s+)?(?:phone\s+)?number",
            r"(?:i'?m|i am)\s+in\s+(?:jail|the hospital|trouble)",
        ],
        "The message reads like someone you know in urgent trouble from a "
        "new number. Call them on the number you already have.",
    ),
]

_COMPILED = [
    (key, serious, [re.compile(p) for p in patterns], reason)
    for key, serious, patterns, reason in CATEGORIES
]

URGENCY = re.compile(
    r"\burgent(?:ly)?\b|\bimmediately\b|\basap\b|within\s+\d+\s+hours|"
    r"\bfinal\s+(?:notice|warning)\b|\btoday\b|right\s+away|"
    r"before\s+end\s+of\s+day"
)


def _negated(text: str, start: int) -> bool:
    window = text[max(0, start - NEGATION_WINDOW):start]
    # Only look within the same sentence.
    window = re.split(r"[.!?\n]", window)[-1]
    return bool(NEGATION.search(window))


def find_signals(text: str) -> list[WordingSignal]:
    """Returns the scam categories found in a message, in list order."""
    lowered = (text or "")[:MAX_TEXT].lower()
    found = []

    for key, serious, patterns, reason in _COMPILED:
        for pattern in patterns:
            if any(
                not _negated(lowered, match.start())
                for match in pattern.finditer(lowered)
            ):
                found.append(WordingSignal(key, serious, reason))
                break

    return found


def is_urgent(text: str) -> bool:
    return bool(URGENCY.search((text or "")[:MAX_TEXT].lower()))
