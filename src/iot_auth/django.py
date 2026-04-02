"""Django integration for JWT authentication."""

import functools
from typing import Callable, Optional

from django.http import HttpRequest, JsonResponse

from .core import (
    InvalidTokenError,
    decode_jwt,
    extract_token_from_header,
    has_permissions,
    is_internal_request,
)
from .types import JWTPayload


def invalid_token_response() -> JsonResponse:
    """Return standard 400 response for invalid/missing token."""
    return JsonResponse({"error": "invalid token"}, status=400)


def not_authorized_response() -> JsonResponse:
    """Return standard 401 response for missing permissions."""
    return JsonResponse({"error": "Not authorized"}, status=401)


class JWTAuthMiddleware:
    """
    Django middleware for JWT authentication.

    Extracts JWT from Authorization header, validates it, and attaches
    the decoded payload to request.auth.

    Returns 400 {"error": "invalid token"} for bad/missing tokens.
    Skips authentication for internal service requests.

    Usage in settings.py:
        MIDDLEWARE = [
            ...
            'iot_auth.django.JWTAuthMiddleware',
        ]
    """

    def __init__(self, get_response: Callable):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        # Get headers as dict for is_internal_request
        headers = {
            key[5:].replace("_", "-"): value
            for key, value in request.META.items()
            if key.startswith("HTTP_")
        }

        # Skip auth for internal service requests
        if is_internal_request(headers):
            request.auth = None  # type: ignore
            request._is_internal_request = True  # type: ignore
            return self.get_response(request)

        request._is_internal_request = False  # type: ignore

        # Extract token from Authorization header
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        token = extract_token_from_header(auth_header)

        if not token:
            return invalid_token_response()

        # Decode and validate token
        try:
            payload = decode_jwt(token)
            request.auth = payload  # type: ignore
        except InvalidTokenError:
            return invalid_token_response()

        return self.get_response(request)


def check_permissions(*permissions: str) -> Callable:
    """
    Decorator to check if the authenticated user has required permissions.

    Returns 401 {"error": "Not authorized"} if permissions are missing.

    Args:
        *permissions: One or more permission strings to check (user must have all)

    Usage:
        @check_permissions('notification.view')
        def my_view(request: AuthenticatedRequest) -> JsonResponse:
            ...

        @check_permissions('devices.view', 'devices.edit')
        def edit_device(request: AuthenticatedRequest) -> JsonResponse:
            ...
    """

    def decorator(view_func: Callable) -> Callable:
        @functools.wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs):
            # Allow internal requests to bypass permission checks
            if getattr(request, "_is_internal_request", False):
                return view_func(request, *args, **kwargs)

            # Check if request has auth payload
            auth: Optional[JWTPayload] = getattr(request, "auth", None)
            if not auth:
                return not_authorized_response()

            # Check permissions
            if not has_permissions(auth, list(permissions)):
                return not_authorized_response()

            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def require_auth(view_func: Callable) -> Callable:
    """
    Decorator to require authentication without checking specific permissions.

    Returns 401 {"error": "Not authorized"} if not authenticated.

    Usage:
        @require_auth
        def my_view(request: AuthenticatedRequest) -> JsonResponse:
            ...
    """

    @functools.wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs):
        # Allow internal requests
        if getattr(request, "_is_internal_request", False):
            return view_func(request, *args, **kwargs)

        # Check if request has auth payload
        auth = getattr(request, "auth", None)
        if not auth:
            return not_authorized_response()

        return view_func(request, *args, **kwargs)

    return wrapper


class CheckPermissionsMixin:
    """
    Mixin for class-based views to check permissions.

    Usage:
        class MyView(CheckPermissionsMixin, View):
            required_permissions = ['notification.view']

            def get(self, request: AuthenticatedRequest) -> JsonResponse:
                ...
    """

    required_permissions: list[str] = []

    def dispatch(self, request: HttpRequest, *args, **kwargs):
        # Allow internal requests
        if getattr(request, "_is_internal_request", False):
            return super().dispatch(request, *args, **kwargs)  # type: ignore

        auth: Optional[JWTPayload] = getattr(request, "auth", None)
        if not auth:
            return not_authorized_response()

        if self.required_permissions:
            if not has_permissions(auth, self.required_permissions):
                return not_authorized_response()

        return super().dispatch(request, *args, **kwargs)  # type: ignore
