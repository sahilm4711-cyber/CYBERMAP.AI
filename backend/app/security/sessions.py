"""Session tokens.

A session is a random token (``secrets.token_urlsafe``). The raw token
goes to the client in an HTTP-only cookie; the database stores only
its SHA-256 hash, so a leaked database dump cannot be used to hijack
sessions. Tokens are never logged.
"""

import hashlib
import secrets


def new_token() -> str:
    """Generate a fresh random session token (returned to the client)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 hash of a token — the only form ever stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
