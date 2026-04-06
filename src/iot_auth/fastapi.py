"""FastAPI integration for JWT authentication."""

from typing import Callable, Optional

from fastapi import HTTPException, Request, status

from .core import (
    InvalidTokenError,
    decode_jwt,
    extract_token_from_header,
    has_permissions,
    is_internal_request,
)
from .types import JWTPayload


async def get_current_user(request: Request) -> JWTPayload:
    """
    FastAPI dependency to extract and validate JWT from request.

    Returns the decoded JWT payload.
    Raises HTTPException 400 for invalid/missing token.

    Usage:
        @app.get("/items")
        async def get_items(auth: JWTPayload = Depends(get_current_user)):
            user_id = auth['sub']
            ...
    """
    # Check for internal service request
    headers = dict(request.headers)

    if is_internal_request(headers):
        # For internal requests, return a minimal payload
        # The actual auth is handled by the calling service
        request.state.is_internal_request = True
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid token"},
        )

    request.state.is_internal_request = False

    # Extract token from Authorization header
    auth_header = request.headers.get("authorization")
    token = extract_token_from_header(auth_header)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid token"},
        )

    try:
        payload = decode_jwt(token)
        request.state.auth = payload
        return payload
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid token"},
        )


async def get_optional_user(request: Request) -> Optional[JWTPayload]:
    """
    FastAPI dependency to optionally extract JWT from request.

    Returns the decoded JWT payload if present and valid, None otherwise.
    Does not raise exceptions for missing/invalid tokens.

    Usage:
        @app.get("/items")
        async def get_items(auth: Optional[JWTPayload] = Depends(get_optional_user)):
            if auth:
                user_id = auth['sub']
            ...
    """
    # Check for internal service request
    headers = dict(request.headers)

    if is_internal_request(headers):
        request.state.is_internal_request = True
        return None

    request.state.is_internal_request = False

    # Extract token from Authorization header
    auth_header = request.headers.get("authorization")
    token = extract_token_from_header(auth_header)

    if not token:
        return None

    try:
        payload = decode_jwt(token)
        request.state.auth = payload
        return payload
    except InvalidTokenError:
        return None


def require_permissions(*permissions: str) -> Callable:
    """
    FastAPI dependency factory for permission checks.

    Returns 401 {"error": "Not authorized"} if permissions are missing.

    Args:
        *permissions: One or more permission strings to check (user must have all)

    Usage:
        @app.get("/admin")
        async def admin_only(
            auth: JWTPayload = Depends(require_permissions("admin.view"))
        ):
            ...

        @app.get("/devices")
        async def edit_device(
            auth: JWTPayload =
            Depends(require_permissions("devices.view", "devices.edit"))
        ):
            ...
    """

    async def dependency(request: Request) -> JWTPayload:
        # Check for internal service request (bypass permission check)
        headers = dict(request.headers)

        if is_internal_request(headers):
            request.state.is_internal_request = True
            # Return empty payload for internal requests
            # The calling service is responsible for proper authorization
            return {}  # type: ignore

        # Get the authenticated user first
        auth = await get_current_user(request)

        # Check permissions
        if not has_permissions(auth, list(permissions)):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "Not authorized"},
            )

        return auth

    return dependency


class JWTAuthMiddleware:
    """
    FastAPI/Starlette middleware for JWT authentication.

    Alternative to using dependencies - processes all requests.

    Usage:
        from fastapi import FastAPI
        from iot_auth.fastapi import JWTAuthMiddleware

        app = FastAPI()
        app.add_middleware(JWTAuthMiddleware)
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        # Check for internal service request
        headers = dict(request.headers)

        if is_internal_request(headers):
            scope["state"] = scope.get("state", {})
            scope["state"]["is_internal_request"] = True
            scope["state"]["auth"] = None
            await self.app(scope, receive, send)
            return

        # Extract and validate token
        auth_header = request.headers.get("authorization")
        token = extract_token_from_header(auth_header)

        if not token:
            response = JSONResponse(
                {"error": "invalid token"},
                status_code=400,
            )
            await response(scope, receive, send)
            return

        try:
            payload = decode_jwt(token)
            scope["state"] = scope.get("state", {})
            scope["state"]["auth"] = payload
            scope["state"]["is_internal_request"] = False
        except InvalidTokenError:
            response = JSONResponse(
                {"error": "invalid token"},
                status_code=400,
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


# Import JSONResponse only when needed to avoid import errors
try:
    from starlette.responses import JSONResponse
except ImportError:
    JSONResponse = None  # type: ignore
