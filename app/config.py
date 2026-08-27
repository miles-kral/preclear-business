import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

load_dotenv(PROJECT_ROOT / ".env")


APP_ENV = os.getenv(
    "APP_ENV",
    "development",
).strip().lower()

IS_PRODUCTION = (
    APP_ENV == "production"
)


DATA_DIR = Path(
    os.getenv(
        "DATA_DIR",
        str(PROJECT_ROOT / "data"),
    )
)

DATABASE_PATH = Path(
    os.getenv(
        "DATABASE_PATH",
        str(DATA_DIR / "preclear_business.db"),
    )
)


SESSION_SECRET_KEY = os.getenv(
    "SESSION_SECRET_KEY",
    "",
)

if (
    IS_PRODUCTION
    and not SESSION_SECRET_KEY
):
    raise RuntimeError(
        "SESSION_SECRET_KEY must be configured "
        "in production."
    )

if not SESSION_SECRET_KEY:
    SESSION_SECRET_KEY = (
        "preclear-business-development-secret"
    )


APP_BASE_URL = os.getenv(
    "APP_BASE_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY",
    "",
)

STRIPE_SECRET_KEY = os.getenv(
    "STRIPE_SECRET_KEY",
    "",
)

STRIPE_WEBHOOK_SECRET = os.getenv(
    "STRIPE_WEBHOOK_SECRET",
    "",
)


STRIPE_SMALL_BUSINESS_MONTHLY_PRICE_ID = os.getenv(
    "STRIPE_SMALL_BUSINESS_MONTHLY_PRICE_ID",
    "",
)

STRIPE_SMALL_BUSINESS_ANNUAL_PRICE_ID = os.getenv(
    "STRIPE_SMALL_BUSINESS_ANNUAL_PRICE_ID",
    "",
)


STRIPE_ENTERPRISE_MONTHLY_PRICE_ID = os.getenv(
    "STRIPE_ENTERPRISE_MONTHLY_PRICE_ID",
    "",
)

STRIPE_ENTERPRISE_ANNUAL_PRICE_ID = os.getenv(
    "STRIPE_ENTERPRISE_ANNUAL_PRICE_ID",
    "",
)

STRIPE_BUSINESS_PORTAL_CONFIGURATION_ID = os.getenv(
    "STRIPE_BUSINESS_PORTAL_CONFIGURATION_ID",
    "",
)
