"""Application settings.

All configuration comes from environment variables. No secrets are
hardcoded anywhere in this codebase — copy ``.env.example`` to ``.env``
and fill in your own values. See ``docs/ARCHITECTURE.md`` for the full
list of variables.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, loaded from the environment / ``.env``."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # App
    app_name: str = "CyberMap AI"
    app_version: str = "0.1.0"
    environment: str = "development"  # development | staging | production
    debug: bool = False

    # Database (PostgreSQL + pgvector in Docker; SQLite fallback for
    # local development without a database server — Phase 3 replaces
    # this with real models and Alembic migrations).
    database_url: str = "sqlite:///./cybermap.db"

    # Redis (caching + job coordination). Empty = Redis disabled.
    redis_url: str = ""

    # CORS — comma-separated list of allowed origins.
    cors_origins: str = "http://localhost:3000"

    # AI provider adapters (Phase 6). Empty = non-AI fallback mode.
    # Supported values are provider names, e.g. "openai", "groq",
    # "google-gemini". The actual key lives in the matching
    # ``<PROVIDER>_API_KEY`` variable and is never committed.
    ai_provider: str = ""
    ai_model: str = ""

    # Sessions / auth (Phase 3). No secrets here — the cookie carries a
    # random token; only its SHA-256 hash is stored in the database.
    # Set SESSION_COOKIE_SECURE=true in production (HTTPS only).
    session_cookie_name: str = "cybermap_session"
    session_expire_days: int = 7
    session_cookie_secure: bool = False
    session_cookie_samesite: str = "lax"
    password_min_length: int = 8

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
