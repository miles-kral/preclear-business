"""
Shared setup for PreClear's tests. Import this before anything from app.

Every test run uses a throwaway SQLite database in a temporary folder,
built from the Alembic migrations, and never touches the real database,
Stripe or VirusTotal: their keys are blanked or replaced with dummies
before the app loads, and Stripe is pointed at an address that can't be
reached, so an accidental call fails instead of going out.
"""
import atexit
import io
import warnings
import os
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMP_DIR = tempfile.mkdtemp(prefix="preclear-tests-")
atexit.register(shutil.rmtree, TEMP_DIR, ignore_errors=True)

# These must be set before app.config runs. load_dotenv() never overrides
# variables that already exist, so .env can't switch the tests to a real
# database or real keys.
os.environ.update({
    "APP_ENV": "development",
    "DATA_DIR": TEMP_DIR,
    "DATABASE_PATH": str(Path(TEMP_DIR) / "test.db"),
    "DATABASE_URL": "",
    "SESSION_SECRET_KEY": "test-session-secret",
    "VIRUSTOTAL_API_KEY": "",
    "STRIPE_SECRET_KEY": "sk_test_dummy",
    "STRIPE_WEBHOOK_SECRET": "whsec_dummy",
    "STRIPE_BUSINESS_PORTAL_CONFIGURATION_ID": "bpc_dummy",
    "STRIPE_SMALL_BUSINESS_MONTHLY_PRICE_ID": "price_sb_monthly",
    "STRIPE_SMALL_BUSINESS_ANNUAL_PRICE_ID": "price_sb_annual",
    "STRIPE_ENTERPRISE_MONTHLY_PRICE_ID": "price_ent_monthly",
    "STRIPE_ENTERPRISE_ANNUAL_PRICE_ID": "price_ent_annual",
    "TURNSTILE_SITE_KEY": "",
    "TURNSTILE_SECRET_KEY": "",
})

import stripe  # noqa: E402

stripe.api_base = "http://127.0.0.1:9"

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402

from app.database import SessionLocal, engine  # noqa: E402

# Refuse to run against anything but the temporary database.
if engine.url.get_backend_name() != "sqlite" or TEMP_DIR not in str(engine.url):
    raise RuntimeError(f"Tests refused to run against {engine.url}")


def _migrate() -> None:
    # No ini file: alembic.ini only adds logging setup, which would print
    # every migration during the tests.
    config = Config()
    config.set_main_option("script_location", str(ROOT / "alembic"))
    command.upgrade(config, "head")


_migrate()

# Keep test output readable: the app logs expected warnings (a missing
# webhook secret, Stripe being unreachable) that the tests trigger on
# purpose, and Alembic logs every migration.
import logging  # noqa: E402
import warnings  # noqa: E402

for name in ("alembic", "uvicorn.error"):
    logging.getLogger(name).setLevel(logging.CRITICAL)

warnings.filterwarnings("ignore", message=".*httpx.*", category=DeprecationWarning)

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient  # noqa: E402

import app.main as main  # noqa: E402
from app import dependencies, models  # noqa: E402

ORIGIN = {"origin": "http://testserver"}

_state = {}


def make(db, cls, **fields):
    row = cls(**{key: value for key, value in fields.items() if hasattr(cls, key)})
    db.add(row)
    db.flush()
    return row


def account():
    """One signed-in owner with an active Small Business organization."""
    if "account" in _state:
        return _state["account"]

    db = SessionLocal()
    user = make(db, models.User, name="Test Owner", email="owner@example.com", password_hash="x")
    org = make(
        db, models.Organization,
        name="Acme Testing", slug="acme-testing", plan="small_business",
        subscription_status="active", stripe_customer_id="cus_test",
        stripe_subscription_id="sub_test", stripe_price_id="price_sb_monthly",
    )
    membership = make(
        db, models.Membership,
        user_id=user.id, organization_id=org.id, role="owner", is_active=True,
    )
    environment = make(
        db, models.Environment,
        organization_id=org.id, name="Accounting", is_active=True,
    )
    db.commit()

    _state["account"] = {
        "db": db,
        "user_id": user.id,
        "org_id": org.id,
        "membership_id": membership.id,
        "environment_id": environment.id,
    }
    return _state["account"]


def signed_in_client() -> TestClient:
    info = account()
    db = info["db"]
    main.app.dependency_overrides[dependencies.get_current_user] = (
        lambda: db.get(models.User, info["user_id"])
    )
    main.app.dependency_overrides[dependencies.get_current_organization] = (
        lambda: db.get(models.Organization, info["org_id"])
    )
    main.app.dependency_overrides[dependencies.get_current_membership] = (
        lambda: db.get(models.Membership, info["membership_id"])
    )
    return TestClient(main.app, follow_redirects=False)


def signed_out_client() -> TestClient:
    main.app.dependency_overrides.clear()
    return TestClient(main.app, follow_redirects=False)


def organization():
    info = account()
    info["db"].expire_all()
    return info["db"].get(models.Organization, info["org_id"])


# ------------------------------------------------------------ samples
# Harmless test content built in memory, so the tests need no files.

def qr_png(text: str, scale: int = 6) -> bytes:
    import zxingcpp
    from PIL import Image

    image = zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode).to_image(scale=scale)
    view = memoryview(image)
    height, width = view.shape[:2]
    picture = Image.frombytes("L", (width, height), view.tobytes())
    canvas = Image.new("L", (width + 40, height + 40), 255)
    canvas.paste(picture, (20, 20))
    buffer = io.BytesIO()
    canvas.save(buffer, "PNG")
    return buffer.getvalue()


def pdf_with_qr(text: str, pages: int = 2, qr_page: int = 2) -> bytes:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    for number in range(1, pages + 1):
        pdf.drawString(72, 720, f"Invoice page {number}")
        if number == qr_page:
            pdf.drawImage(ImageReader(io.BytesIO(qr_png(text))), 72, 300, 150, 150)
        pdf.showPage()
    pdf.save()
    return buffer.getvalue()


def email_bytes(
    sender="Billing <billing@example.com>",
    subject="Invoice",
    body="Please find your invoice attached.",
    html=None,
    auth="mx.example.net; spf=pass; dkim=pass; dmarc=pass header.from=example.com",
    reply_to=None,
    attachments=(),
    received=True,
) -> bytes:
    from email.message import EmailMessage

    message = EmailMessage()
    if auth:
        message["Authentication-Results"] = auth
    if received:
        message["Received"] = "from mail.example.com by mx.example.net"
    message["From"] = sender
    message["To"] = "ap@acme-testing.com"
    message["Subject"] = subject
    message["Message-ID"] = "<test@example.com>"
    if reply_to:
        message["Reply-To"] = reply_to
    message.set_content(body)
    if html:
        message.add_alternative(html, subtype="html")
    for name, data, maintype, subtype in attachments:
        message.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return bytes(message)
