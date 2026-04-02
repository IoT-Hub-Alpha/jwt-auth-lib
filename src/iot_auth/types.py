"""Type definitions for JWT authentication."""

from typing import TypedDict


class JWTPayload(TypedDict):
    """JWT token payload structure."""

    sub: str
    username: str
    email: str
    groups: list[str]
    permissions: list[str]
    is_staff: bool
    is_superuser: bool
    exp: int
    iat: int
    type: str
