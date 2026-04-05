"""Tests for iot_auth.django module."""

import json

import pytest
from django.http import HttpRequest, JsonResponse
from django.test import RequestFactory

from iot_auth.django import (
    CheckPermissionsMixin,
    JWTAuthMiddleware,
    check_permissions,
    invalid_token_response,
    not_authorized_response,
    require_auth,
)


@pytest.fixture
def rf():
    """Return a Django RequestFactory."""
    return RequestFactory()


@pytest.fixture
def mock_get_response():
    """Return a mock get_response callable."""

    def get_response(request):
        return JsonResponse({"success": True})

    return get_response


class TestResponses:
    """Tests for response helper functions."""

    def test_invalid_token_response(self):
        """Test invalid_token_response returns correct format."""
        response = invalid_token_response()
        assert response.status_code == 400
        assert json.loads(response.content) == {"error": "invalid token"}

    def test_not_authorized_response(self):
        """Test not_authorized_response returns correct format."""
        response = not_authorized_response()
        assert response.status_code == 401
        assert json.loads(response.content) == {"error": "Not authorized"}


class TestJWTAuthMiddleware:
    """Tests for JWTAuthMiddleware."""

    def test_valid_token_attaches_auth(self, rf, mock_get_response, valid_token):
        """Test valid token attaches auth payload to request."""
        middleware = JWTAuthMiddleware(mock_get_response)
        request = rf.get("/", HTTP_AUTHORIZATION=f"Bearer {valid_token}")

        response = middleware(request)

        assert response.status_code == 200
        assert hasattr(request, "auth")
        assert request.auth["username"] == "testuser"
        assert request.auth["sub"] == "user-123"

    def test_missing_token_returns_400(self, rf, mock_get_response):
        """Test missing token returns 400 error."""
        middleware = JWTAuthMiddleware(mock_get_response)
        request = rf.get("/")

        response = middleware(request)

        assert response.status_code == 400
        assert json.loads(response.content) == {"error": "invalid token"}

    def test_invalid_token_returns_400(self, rf, mock_get_response):
        """Test invalid token returns 400 error."""
        middleware = JWTAuthMiddleware(mock_get_response)
        request = rf.get("/", HTTP_AUTHORIZATION="Bearer invalid-token")

        response = middleware(request)

        assert response.status_code == 400
        assert json.loads(response.content) == {"error": "invalid token"}

    def test_expired_token_returns_400(self, rf, mock_get_response, expired_token):
        """Test expired token returns 400 error."""
        middleware = JWTAuthMiddleware(mock_get_response)
        request = rf.get("/", HTTP_AUTHORIZATION=f"Bearer {expired_token}")

        response = middleware(request)

        assert response.status_code == 400
        assert json.loads(response.content) == {"error": "invalid token"}

    def test_internal_request_bypasses_auth(self, rf, mock_get_response):
        """Test internal service request bypasses authentication."""
        middleware = JWTAuthMiddleware(mock_get_response)
        request = rf.get(
            "/",
            HTTP_X_INTERNAL_SERVICE="notification-service",
        )

        response = middleware(request)

        assert response.status_code == 200
        assert request._is_internal_request is True
        assert request.auth is None

    def test_malformed_authorization_header(self, rf, mock_get_response):
        """Test malformed Authorization header returns 400."""
        middleware = JWTAuthMiddleware(mock_get_response)

        # Missing Bearer prefix
        request = rf.get("/", HTTP_AUTHORIZATION="token-without-bearer")
        response = middleware(request)
        assert response.status_code == 400

        # Basic auth instead of Bearer
        request = rf.get("/", HTTP_AUTHORIZATION="Basic dXNlcjpwYXNz")
        response = middleware(request)
        assert response.status_code == 400


class TestCheckPermissionsDecorator:
    """Tests for check_permissions decorator."""

    def test_allows_with_permission(self, rf, valid_token):
        """Test decorator allows request with required permission."""

        @check_permissions("devices.view")
        def view(request):
            return JsonResponse({"user": request.auth["username"]})

        request = rf.get("/")
        request.auth = {
            "sub": "user-123",
            "username": "testuser",
            "permissions": ["devices.view", "devices.add"],
            "is_superuser": False,
        }
        request._is_internal_request = False

        response = view(request)

        assert response.status_code == 200
        assert json.loads(response.content) == {"user": "testuser"}

    def test_rejects_without_permission(self, rf):
        """Test decorator rejects request without required permission."""

        @check_permissions("admin.delete")
        def view(request):
            return JsonResponse({"success": True})

        request = rf.get("/")
        request.auth = {
            "sub": "user-123",
            "permissions": ["devices.view"],
            "is_superuser": False,
        }
        request._is_internal_request = False

        response = view(request)

        assert response.status_code == 401
        assert json.loads(response.content) == {"error": "Not authorized"}

    def test_rejects_without_auth(self, rf):
        """Test decorator rejects request without auth payload."""

        @check_permissions("devices.view")
        def view(request):
            return JsonResponse({"success": True})

        request = rf.get("/")
        request._is_internal_request = False
        # No auth attribute

        response = view(request)

        assert response.status_code == 401

    def test_superuser_allowed(self, rf):
        """Test superuser is allowed regardless of specific permissions."""

        @check_permissions("admin.superspecial")
        def view(request):
            return JsonResponse({"success": True})

        request = rf.get("/")
        request.auth = {
            "sub": "user-123",
            "permissions": [],
            "is_superuser": True,
        }
        request._is_internal_request = False

        response = view(request)

        assert response.status_code == 200

    def test_internal_request_allowed(self, rf):
        """Test internal request bypasses permission check."""

        @check_permissions("admin.delete")
        def view(request):
            return JsonResponse({"success": True})

        request = rf.get("/")
        request._is_internal_request = True
        # No auth needed for internal requests

        response = view(request)

        assert response.status_code == 200

    def test_multiple_permissions(self, rf):
        """Test decorator requires all listed permissions."""

        @check_permissions("devices.view", "devices.add")
        def view(request):
            return JsonResponse({"success": True})

        request = rf.get("/")
        request._is_internal_request = False

        # Has only one permission - should fail
        request.auth = {
            "permissions": ["devices.view"],
            "is_superuser": False,
        }
        response = view(request)
        assert response.status_code == 401

        # Has both permissions - should succeed
        request.auth = {
            "permissions": ["devices.view", "devices.add"],
            "is_superuser": False,
        }
        response = view(request)
        assert response.status_code == 200


class TestRequireAuthDecorator:
    """Tests for require_auth decorator."""

    def test_allows_authenticated(self, rf):
        """Test decorator allows authenticated request."""

        @require_auth
        def view(request):
            return JsonResponse({"user": request.auth["username"]})

        request = rf.get("/")
        request.auth = {"username": "testuser"}
        request._is_internal_request = False

        response = view(request)

        assert response.status_code == 200

    def test_rejects_unauthenticated(self, rf):
        """Test decorator rejects unauthenticated request."""

        @require_auth
        def view(request):
            return JsonResponse({"success": True})

        request = rf.get("/")
        request._is_internal_request = False
        # No auth attribute

        response = view(request)

        assert response.status_code == 401

    def test_allows_internal_request(self, rf):
        """Test decorator allows internal request."""

        @require_auth
        def view(request):
            return JsonResponse({"success": True})

        request = rf.get("/")
        request._is_internal_request = True

        response = view(request)

        assert response.status_code == 200


class TestCheckPermissionsMixin:
    """Tests for CheckPermissionsMixin class-based view mixin."""

    def test_required_permissions_allows_with_permission(self, rf):
        """Test mixin allows request with required permission."""
        from django.views import View

        class TestView(CheckPermissionsMixin, View):
            required_permissions = ["devices.view"]

            def get(self, request):
                return JsonResponse({"success": True})

        request = rf.get("/")
        request.auth = {
            "sub": "user-123",
            "permissions": ["devices.view"],
            "is_superuser": False,
        }
        request._is_internal_request = False

        view = TestView.as_view()
        response = view(request)

        assert response.status_code == 200

    def test_required_permissions_rejects_without_permission(self, rf):
        """Test mixin rejects request without required permission."""
        from django.views import View

        class TestView(CheckPermissionsMixin, View):
            required_permissions = ["admin.delete"]

            def get(self, request):
                return JsonResponse({"success": True})

        request = rf.get("/")
        request.auth = {
            "sub": "user-123",
            "permissions": ["devices.view"],
            "is_superuser": False,
        }
        request._is_internal_request = False

        view = TestView.as_view()
        response = view(request)

        assert response.status_code == 401

    def test_permission_map_different_methods(self, rf):
        """Test permission_map applies different permissions per HTTP method."""
        from django.views import View

        class TestView(CheckPermissionsMixin, View):
            permission_map = {
                "get": ["devices.view"],
                "post": ["devices.add"],
                "delete": ["devices.delete"],
            }

            def get(self, request):
                return JsonResponse({"action": "list"})

            def post(self, request):
                return JsonResponse({"action": "create"})

            def delete(self, request):
                return JsonResponse({"action": "delete"})

        view = TestView.as_view()

        # User with only devices.view permission
        request = rf.get("/")
        request.auth = {
            "permissions": ["devices.view"],
            "is_superuser": False,
        }
        request._is_internal_request = False
        response = view(request)
        assert response.status_code == 200  # GET allowed

        request = rf.post("/")
        request.auth = {
            "permissions": ["devices.view"],
            "is_superuser": False,
        }
        request._is_internal_request = False
        response = view(request)
        assert response.status_code == 401  # POST denied

        # User with devices.add permission
        request = rf.post("/")
        request.auth = {
            "permissions": ["devices.add"],
            "is_superuser": False,
        }
        request._is_internal_request = False
        response = view(request)
        assert response.status_code == 200  # POST allowed

    def test_permission_map_takes_precedence(self, rf):
        """Test permission_map takes precedence over required_permissions."""
        from django.views import View

        class TestView(CheckPermissionsMixin, View):
            required_permissions = ["fallback.permission"]
            permission_map = {
                "get": ["specific.view"],
            }

            def get(self, request):
                return JsonResponse({"success": True})

        request = rf.get("/")
        request.auth = {
            "permissions": ["specific.view"],
            "is_superuser": False,
        }
        request._is_internal_request = False

        view = TestView.as_view()
        response = view(request)

        # Should use permission_map, not required_permissions
        assert response.status_code == 200

    def test_permission_map_fallback_to_required(self, rf):
        """Test methods not in permission_map fall back to required_permissions."""
        from django.views import View

        class TestView(CheckPermissionsMixin, View):
            required_permissions = ["fallback.permission"]
            permission_map = {
                "get": ["specific.view"],
            }

            def get(self, request):
                return JsonResponse({"success": True})

            def post(self, request):
                return JsonResponse({"success": True})

        view = TestView.as_view()

        # POST is not in permission_map, should use required_permissions
        request = rf.post("/")
        request.auth = {
            "permissions": ["specific.view"],  # Has GET permission, not fallback
            "is_superuser": False,
        }
        request._is_internal_request = False
        response = view(request)
        assert response.status_code == 401  # POST denied - needs fallback.permission

        request = rf.post("/")
        request.auth = {
            "permissions": ["fallback.permission"],
            "is_superuser": False,
        }
        request._is_internal_request = False
        response = view(request)
        assert response.status_code == 200  # POST allowed with fallback permission

    def test_internal_request_bypasses_permission_map(self, rf):
        """Test internal request bypasses permission_map checks."""
        from django.views import View

        class TestView(CheckPermissionsMixin, View):
            permission_map = {
                "delete": ["admin.delete"],
            }

            def delete(self, request):
                return JsonResponse({"success": True})

        request = rf.delete("/")
        request._is_internal_request = True
        # No auth needed for internal requests

        view = TestView.as_view()
        response = view(request)

        assert response.status_code == 200

    def test_superuser_bypasses_permission_map(self, rf):
        """Test superuser bypasses all permission_map checks."""
        from django.views import View

        class TestView(CheckPermissionsMixin, View):
            permission_map = {
                "delete": ["admin.superspecial"],
            }

            def delete(self, request):
                return JsonResponse({"success": True})

        request = rf.delete("/")
        request.auth = {
            "permissions": [],  # No permissions
            "is_superuser": True,
        }
        request._is_internal_request = False

        view = TestView.as_view()
        response = view(request)

        assert response.status_code == 200

    def test_no_auth_returns_401(self, rf):
        """Test request without auth returns 401."""
        from django.views import View

        class TestView(CheckPermissionsMixin, View):
            required_permissions = ["devices.view"]

            def get(self, request):
                return JsonResponse({"success": True})

        request = rf.get("/")
        request._is_internal_request = False
        # No auth attribute

        view = TestView.as_view()
        response = view(request)

        assert response.status_code == 401
