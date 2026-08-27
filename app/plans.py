from datetime import datetime, timedelta, timezone

PLAN_CONFIG = {
    "small_business": {
        "name": "Small Business",
        "monthly_price": 99,
        "annual_price": 990,
        "analysis_limit": 250,
        "team_member_limit": 10,
        "environment_limit": 10,
        "evidence_retention_months": 12,
        "advanced_reporting": False,
        "advanced_governance": False,
        "integrations": False,
        "priority_support": False,
    },

    "enterprise": {
        "name": "Enterprise",
        "monthly_price": 499,
        "annual_price": 4990,
        "analysis_limit": 2500,
        "team_member_limit": 50,
        "environment_limit": 50,
        "evidence_retention_months": 36,
        "advanced_reporting": True,
        "advanced_governance": True,
        "integrations": True,
        "priority_support": True,
    },
}


DEFAULT_PLAN = "small_business"

SUBSCRIPTION_ACCESS_STATUSES = {
    "active",
    "trialing",
    "past_due",
}


def has_subscription_access(
    subscription_status: str | None,
) -> bool:
    return (
        subscription_status
        in SUBSCRIPTION_ACCESS_STATUSES
    )

def get_plan_config(
    plan_key: str | None,
) -> dict:

    return PLAN_CONFIG.get(
        plan_key or DEFAULT_PLAN,
        PLAN_CONFIG[DEFAULT_PLAN],
    )

def get_evidence_retention_cutoff(
    plan_key: str | None,
) -> datetime | None:

    plan_config = get_plan_config(
        plan_key
    )

    retention_months = (
        plan_config[
            "evidence_retention_months"
        ]
    )

    if retention_months is None:
        return None

    retention_days = (
        retention_months * 30
    )

    return (
        datetime.now(timezone.utc)
        - timedelta(
            days=retention_days
        )
    )