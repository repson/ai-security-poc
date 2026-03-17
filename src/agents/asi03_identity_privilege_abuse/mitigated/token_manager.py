"""ASI03 — Identity & Privilege Abuse: JWT token manager."""

from __future__ import annotations

import secrets, time
from typing import Optional
import jwt  # pip install PyJWT

_SECRET = secrets.token_hex(32)
ALGORITHM = "HS256"


def issue_token(
    subject: str, resources: list[str], actions: list[str], ttl: int = 300
) -> str:
    payload = {
        "sub": subject,
        "resources": resources,
        "actions": actions,
        "iat": time.time(),
        "exp": time.time() + ttl,
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, _SECRET, algorithm=ALGORITHM)


def verify_token(token: str) -> dict:
    """Decode and validate a token. Raises jwt.ExpiredSignatureError / DecodeError."""
    return jwt.decode(token, _SECRET, algorithms=[ALGORITHM])


def check_permission(token: str, resource: str, action: str) -> bool:
    """Return True if the token grants (resource, action). Raises on invalid token."""
    claims = verify_token(token)
    return resource in claims.get("resources", []) and action in claims.get(
        "actions", []
    )
