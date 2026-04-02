"""
iot_auth - Shared JWT authentication library for Django and FastAPI microservices.

This library provides middleware, decorators, and dependencies for consistent
token validation and permission checks across microservices.

Quick Start (Django):
    # settings.py
    MIDDLEWARE = [
        ...
        'iot_auth.django.JWTAuthMiddleware',
    ]

    # views.py
    from iot_auth.django import check_permissions
    from iot_auth.types import JWTPayload

    @check_permissions('devices.view')
    def list_devices(request) -> JsonResponse:
        auth: JWTPayload = request.auth
        user_id = auth['sub']
        ...

Quick Start (FastAPI):
    from fastapi import Depends
    from iot_auth.fastapi import get_current_user, require_permissions
    from iot_auth.types import JWTPayload

    @app.get("/devices")
    def list_devices(auth: JWTPayload = Depends(get_current_user)):
        user_id = auth['sub']
        ...
"""

from .core import (
    InvalidTokenError,
    decode_jwt,
    extract_token_from_header,
    has_permissions,
    is_internal_request,
)
from .types import JWTPayload

__version__ = "0.1.0"

__all__ = [
    # Core functions
    "decode_jwt",
    "extract_token_from_header",
    "is_internal_request",
    "has_permissions",
    "InvalidTokenError",
    # Types
    "JWTPayload",
]
