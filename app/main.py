from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.database import Base, engine
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
)

from app import config


Base.metadata.create_all(bind=engine)

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
    SessionMiddleware,
    secret_key=config.SESSION_SECRET_KEY,
    same_site="lax",
    https_only=config.IS_PRODUCTION,
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