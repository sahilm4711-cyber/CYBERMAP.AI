"""Request/response schemas for the auth API (Phase 3).

Passwords travel only in request bodies, are never returned, and are
never logged. Validation (min length 8) happens here in Pydantic so a
weak password is rejected with 422 before any service code runs.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.core.config import settings


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=8)

    @field_validator("password")
    @classmethod
    def password_min_length(cls, value: str) -> str:
        minimum = max(8, settings.password_min_length)
        if len(value) < minimum:
            raise ValueError(
                f"Password must be at least {minimum} characters"
            )
        return value


class LoginRequest(BaseModel):
    """``username`` accepts a username or an email address."""

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8)

    @field_validator("new_password")
    @classmethod
    def new_password_min_length(cls, value: str) -> str:
        minimum = max(8, settings.password_min_length)
        if len(value) < minimum:
            raise ValueError(
                f"Password must be at least {minimum} characters"
            )
        return value


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None

    model_config = {"from_attributes": True}


class MessageResponse(BaseModel):
    detail: str


class PasswordChangeResponse(BaseModel):
    detail: str
    sessions_revoked: int
