"""CyberMap AI backend — FastAPI application factory.

Run locally (from ``backend/`` with the venv active)::

    uvicorn app.main:app --reload --port 8000

API docs (when running): http://localhost:8000/docs
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.v1 import (
    ai,
    auth,
    dashboard,
    graph,
    health,
    ingestion,
    intelligence,
    learning,
    research,
    vulnerabilities,
)
from app.core.config import settings

# SECURITY: response headers every backend reply carries. This is the
# API, so no CSP here — a JSON API has nothing to frame or run inline,
# and a strict CSP would break the dev-only Swagger UI. The four headers
# below are the ones that matter for an API: no framing (clickjacking),
# no MIME sniffing, a strict referrer, and no browser features.
SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Set the security headers on every response, including errors."""

    async def dispatch(self, request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response


def create_app() -> FastAPI:
    # SECURITY (R4): the interactive API docs and the raw OpenAPI schema
    # are dev-only. In production they are disabled entirely — a public
    # /docs page hands an attacker the full endpoint map (the same
    # exposure Curion shipped with). Local dev keeps them on.
    docs_enabled = settings.environment != "production"
    app = FastAPI(
        title="CyberMap AI",
        description=(
            "AI-powered vulnerability intelligence platform. "
            "Phases 1–10 complete: database models and migrations, "
            "Argon2id auth, live ingestion (NVD/KEV/EPSS/MITRE), "
            "dashboard, vulnerability explorer, AI analyst and "
            "assistant with non-AI fallback, knowledge graph, "
            "research workspace and learning center."
        ),
        version=settings.app_version,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Added after CORS so it wraps every response, including the
    # preflight replies CORS itself returns early.
    app.add_middleware(SecurityHeadersMiddleware)

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(ingestion.router)
    app.include_router(ai.router)
    app.include_router(graph.router)
    app.include_router(research.router)
    app.include_router(learning.router)
    app.include_router(dashboard.router)
    app.include_router(vulnerabilities.router)
    app.include_router(intelligence.router)

    @app.get("/", tags=["root"])
    def root() -> dict:
        """Service root — identifies the API and where the docs live."""
        return {
            "service": "cybermap-ai",
            "version": settings.app_version,
            "environment": settings.environment,
            "docs": "/docs" if docs_enabled else None,
            "health": "/health",
        }

    return app


app = create_app()
