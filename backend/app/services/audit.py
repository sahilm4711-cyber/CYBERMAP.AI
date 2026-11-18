"""Audit logging (DATABASE.md §2.21).

Append-only. ``details`` must never contain passwords, tokens or
other secrets — callers pass only safe metadata (usernames, ids,
counts). The helper deliberately has no parameter that could carry a
secret.
"""

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog


def write_audit_log(
    db: Session,
    action: str,
    user_id: uuid.UUID | None = None,
    entity_type: str | None = None,
    entity_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    """Insert one audit row. Callers must not put secrets in ``details``."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details,
        ip_address=ip_address,
    )
    db.add(entry)
    return entry
