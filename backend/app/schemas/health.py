"""Response schemas for the health endpoints."""

from datetime import datetime

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """What ``/health`` and ``/api/v1/health`` return."""

    status: str = Field(description="'ok' when the service is up")
    service: str = Field(description="Service name, e.g. 'cybermap-ai'")
    version: str = Field(description="Application version")
    environment: str = Field(description="development | staging | production")
    timestamp: datetime = Field(description="UTC time the check ran")
    database: str = Field(
        description="'ok' when a SELECT 1 against the database "
        "answers, 'error' when it does not (Phase 9 real check; "
        "Phase 2 reported the placeholder 'not_configured')"
    )
    ai_mode: str = Field(
        description="'provider' when an AI provider is configured, "
        "otherwise 'fallback' (non-AI mode)"
    )
