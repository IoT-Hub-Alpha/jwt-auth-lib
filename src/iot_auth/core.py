"""Core JWT validation logic shared by Django and FastAPI integrations."""

import os
from typing import Optional

import jwt

from .types import JWTPayload

# Configuration from environment
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
INTERNAL_SERVICE_HEADER = os.getenv("INTERNAL_SERVICE_HEADER", "X-Internal-Service")


class InvalidTokenError(Exception):
    """Raised when JWT token is invalid, expired, or malformed."""

    pass


def get_jwt_secret_key() -> str:
    """Get the JWT secret key from environment or Django settings."""
    if JWT_SECRET_KEY:
        return JWT_SECRET_KEY

    # Try Django settings as fallback
    try:
        from django.conf import settings

        return getattr(settings, "JWT_SECRET_KEY", "")
    except ImportError:
        pass

    return ""


def decode_jwt(token: str, secret_key: Optional[str] = None) -> JWTPayload:
    """
    Decode and validate a JWT token.

    Args:
        token: The JWT token string to decode
        secret_key: Optional secret key override. If not provided,
                   uses JWT_SECRET_KEY from environment or Django settings.

    Returns:
        JWTPayload: The decoded token payload

    Raises:
        InvalidTokenError: If token is invalid, expired, or malformed
    """
    if not secret_key:
        secret_key = get_jwt_secret_key()

    if not secret_key:
        raise InvalidTokenError("JWT secret key not configured")

    try:
        payload = jwt.decode(token, secret_key, algorithms=[JWT_ALGORITHM])
        return payload  # type: ignore
    except jwt.ExpiredSignatureError:
        raise InvalidTokenError("Token has expired")
    except jwt.InvalidTokenError:
        raise InvalidTokenError("Invalid token")


def extract_token_from_header(auth_header: Optional[str]) -> Optional[str]:
    """
    Extract JWT token from Authorization header.

    Args:
        auth_header: The Authorization header value (e.g., "Bearer <token>")

    Returns:
        The token string if valid Bearer format, None otherwise
    """
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    return parts[1]


def is_internal_request(headers: dict) -> bool:
    """
    Check if a request is from an internal service (container-to-container).

    Internal requests bypass JWT authentication. A request is considered internal
    if it has the X-Internal-Service header (or custom header name from env).

    Args:
        headers: Request headers dictionary (case-insensitive lookup)

    Returns:
        True if the request is from an internal service
    """
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    internal_header = INTERNAL_SERVICE_HEADER.lower()
    return internal_header in normalized_headers


def has_permissions(payload: JWTPayload, required_permissions: list[str]) -> bool:
    """
    Check if the JWT payload has all required permissions.

    Superusers automatically have all permissions.

    Args:
        payload: The decoded JWT payload
        required_permissions: List of permission strings to check

    Returns:
        True if user has all required permissions (or is superuser)
    """
    if payload.get("is_superuser", False):
        return True

    permissions = payload.get("permissions", [])
    return all(perm in permissions for perm in required_permissions)
