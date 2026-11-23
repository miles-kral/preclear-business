from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.routes import (
    pages,
    dashboard,
    auth,
    analysis,
    ledger,
    team,
    environments,
    activity,
    governance,
    reports,
    settings,
    contact,
    billing,
    account,
    admin_evaluations,
    trusted_domains,
)

from app import config

from app.evaluation_middleware import (
    EvaluationAccessMiddleware,
)

from app.csrf import (
    CSRFMiddleware,
)

from app.security_headers import (
    SecurityHeadersMiddleware,
)

from app.upload_limit import (
    UploadSizeLimitMiddleware,
)

from app.services.analysis_service import (
    MAX_UPLOAD_BYTES,
)


# The database schema is managed only by Alembic migrations. Run
# "alembic upgrade head" after pulling changes; Render runs it before each
# deploy. (The app used to create missing tables at startup, which could
# collide with migrations.)

app = FastAPI(
    title="PreClear Business",
    docs_url=(
        None
        if config.IS_PRODUCTION
        else "/docs"
    ),
    redoc_url=(
        None
        if config.IS_PRODUCTION
        else "/redoc"
    ),
    openapi_url=(
        None
        if config.IS_PRODUCTION
        else "/openapi.json"
    ),
)

app.add_middleware(
    EvaluationAccessMiddleware,
)

app.add_middleware(
    CSRFMiddleware,
)

app.add_middleware(
    SecurityHeadersMiddleware,
)

app.add_middleware(
    SessionMiddleware,
    secret_key=config.SESSION_SECRET_KEY,
    same_site="lax",
    https_only=config.IS_PRODUCTION,
    max_age=60 * 60 * 8,
)

# Added last so it runs first and rejects oversized uploads before any
# other middleware or route reads them. The extra 1 MB allows for the
# form fields and multipart overhead that travel with the file.
app.add_middleware(
    UploadSizeLimitMiddleware,
    max_body_bytes=MAX_UPLOAD_BYTES + 1024 * 1024,
)

app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static",
)

app.include_router(
    pages.router,
)

app.include_router(
    dashboard.router,
)

app.include_router(
    auth.router,
)

app.include_router(
    analysis.router,
)

app.include_router(
    ledger.router,
)

app.include_router(
    team.router,
)

app.include_router(
    environments.router,
)

app.include_router(
    activity.router,
)

app.include_router(
    governance.router,
)

app.include_router(
    reports.router,
)

app.include_router(
    settings.router,
)

app.include_router(
    contact.router,
)

app.include_router(
    billing.router,
)

app.include_router(
    account.router,
)

app.include_router(
    admin_evaluations.router,
)

app.include_router(
    trusted_domains.router,
)