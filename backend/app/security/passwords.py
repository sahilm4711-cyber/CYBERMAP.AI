"""Password hashing with Argon2id.

Argon2id is the DATABASE.md / ARCHITECTURE.md choice (Phase 3).
Plaintext passwords are never stored or logged — only the hash
returned here ever reaches the database.
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# OWASP-recommended Argon2id parameters for interactive login.
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Hash a plaintext password. The plaintext is never retained."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Check a plaintext password against a stored hash.

    Returns False (never raises) for a wrong password or a malformed
    hash, so callers can treat both as "login failed".
    """
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when a stored hash was made with weaker parameters."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except Exception:
        return True
