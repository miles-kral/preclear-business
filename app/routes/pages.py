from fastapi import APIRouter, Request
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    Response,
)
from fastapi.templating import Jinja2Templates
from app.plans import get_plan_config
from app.config import APP_BASE_URL


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates",
)


@router.get(
    "/",
    response_class=HTMLResponse,
)
def home_page(
    request: Request,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "active_page": "home",
            "page_title": (
                "PreClear Business | Know Before You Trust"
            ),
            "meta_description": (
                "PreClear Business helps organizations inspect "
                "external files before internal access and maintain "
                "clear, auditable evidence behind every trust decision."
            ),
            "canonical_url": f"{APP_BASE_URL}/",
        },
    )

@router.get(
    "/pricing",
    response_class=HTMLResponse,
)
def pricing_page(
    request: Request,
):
    small_business_plan = get_plan_config(
        "small_business"
    )

    enterprise_plan = get_plan_config(
        "enterprise"
    )

    return templates.TemplateResponse(
        request=request,
        name="pricing.html",
        context={
            "small_business_plan": (
                small_business_plan
            ),
            "enterprise_plan": (
                enterprise_plan
            ),
            "page_title": (
                "Pricing | PreClear Business"
            ),
            "meta_description": (
                "Compare PreClear Business plans for proactive "
                "file protection, security evidence, reporting, "
                "team controls, and governance."
            ),
            "canonical_url": f"{APP_BASE_URL}/pricing",
        },
    )

@router.get(
    "/about",
    response_class=HTMLResponse,
)
def about_page(
    request: Request,
):
    return templates.TemplateResponse(
        request=request,
        name="about.html",
        context={
            "page_title": (
                "About PreClear | PreClear Business"
            ),
            "meta_description": (
                "Learn why PreClear is building proactive "
                "pre-ingress security infrastructure to help "
                "organizations make informed trust decisions "
                "before external files reach internal environments."
            ),
            "canonical_url": f"{APP_BASE_URL}/about",
        },
    )

@router.get(
    "/security",
    response_class=HTMLResponse,
)
def security_page(
    request: Request,
):
    return templates.TemplateResponse(
        request=request,
        name="security.html",
        context={
            "page_title": (
                "Security | PreClear Business"
            ),
            "meta_description": (
                "Learn how PreClear Business approaches "
                "organizational isolation, access control, "
                "auditability, threat intelligence, and "
                "pre-ingress security."
            ),
            "canonical_url": f"{APP_BASE_URL}/security",
        },
    )

@router.get(
    "/privacy",
    response_class=HTMLResponse,
)
def privacy_page(
    request: Request,
):
    return templates.TemplateResponse(
        request=request,
        name="privacy.html",
        context={
            "page_title": (
                "Privacy Policy | PreClear Business"
            ),
            "meta_description": (
                "Learn how PreClear Cybersecurity, Inc. "
                "collects, uses, protects, and handles "
                "information associated with PreClear Business."
            ),
            "canonical_url": f"{APP_BASE_URL}/privacy",
        },
    )

@router.get(
    "/terms",
    response_class=HTMLResponse,
)
def terms_page(
    request: Request,
):
    return templates.TemplateResponse(
        request=request,
        name="terms.html",
        context={
            "page_title": (
                "Terms of Service | PreClear Business"
            ),
            "meta_description": (
                "Review the terms governing access to and use "
                "of PreClear Business and related services."
            ),
            "canonical_url": f"{APP_BASE_URL}/terms",
        },
    )

@router.get(
    "/sitemap.xml",
    response_class=Response,
    include_in_schema=False,
)
def sitemap():
    urls = [
        "",
        "/pricing",
        "/about",
        "/security",
        "/privacy",
        "/terms",
        "/contact",
    ]

    entries = "\n".join(
        (
            "    <url>\n"
            f"        <loc>{APP_BASE_URL}{path}</loc>\n"
            "    </url>"
        )
        for path in urls
    )

    content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/'
        'schemas/sitemap/0.9">\n'
        f"{entries}\n"
        "</urlset>"
    )

    return Response(
        content=content,
        media_type="application/xml",
    )

@router.get(
    "/robots.txt",
    response_class=PlainTextResponse,
    include_in_schema=False,
)
def robots():
    content = (
        "User-agent: *\n"
        "Allow: /\n"
        "\n"
        "Disallow: /dashboard\n"
        "Disallow: /analyze\n"
        "Disallow: /analysis/\n"
        "Disallow: /ledger\n"
        "Disallow: /team\n"
        "Disallow: /environments\n"
        "Disallow: /activity\n"
        "Disallow: /governance\n"
        "Disallow: /reports\n"
        "Disallow: /settings\n"
        "Disallow: /account\n"
        "Disallow: /invite/\n"
        "Disallow: /purchase/\n"
        "Disallow: /billing/\n"
        "Disallow: /docs\n"
        "Disallow: /redoc\n"
        "Disallow: /openapi.json\n"
        "\n"
        f"Sitemap: {APP_BASE_URL}/sitemap.xml\n"
    )

    return PlainTextResponse(
        content=content,
    )