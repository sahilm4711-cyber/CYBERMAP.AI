"""CyberMap AI backend — FastAPI application factory.

Run locally (from ``backend/`` with the venv active)::

    uvicorn app.main:app --reload --port 8000

API docs (when running): http://localhost:8000/docs
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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


def create_app() -> FastAPI:
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
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

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
            "docs": "/docs",
            "health": "/health",
        }

    return app


app = create_app()
