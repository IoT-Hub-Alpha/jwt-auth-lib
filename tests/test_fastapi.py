"""Tests for iot_auth.fastapi module."""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from iot_auth.fastapi import (
    get_current_user,
    get_optional_user,
    require_permissions,
)
from iot_auth.types import JWTPayload


@pytest.fixture
def app():
    """Create a FastAPI test app."""
    app = FastAPI()

    @app.get("/protected")
    async def protected_route(auth: JWTPayload = Depends(get_current_user)):
        return {"user": auth["username"], "sub": auth["sub"]}

    @app.get("/optional")
    async def optional_route(auth: JWTPayload = Depends(get_optional_user)):
        if auth:
            return {"user": auth["username"]}
        return {"user": "guest"}

    @app.get("/devices")
    async def devices_route(
        auth: JWTPayload = Depends(require_permissions("devices.view")),
    ):
        return {"devices": [], "user": auth.get("username")}

    @app.get("/admin")
    async def admin_route(
        auth: JWTPayload = Depends(require_permissions("admin.view", "admin.edit"))
    ):
        return {"admin": "panel"}

    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return TestClient(app)


class TestGetCurrentUser:
    """Tests for get_current_user dependency."""

    def test_valid_token(self, client, valid_token):
        """Test valid token returns user info."""
        response = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {valid_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user"] == "testuser"
        assert data["sub"] == "user-123"

    def test_missing_token(self, client):
        """Test missing token returns 400."""
        response = client.get("/protected")

        assert response.status_code == 400
        assert response.json() == {"detail": {"error": "invalid token"}}

    def test_invalid_token(self, client):
        """Test invalid token returns 400."""
        response = client.get(
            "/protected",
            headers={"Authorization": "Bearer invalid-token"},
        )

        assert response.status_code == 400
        assert response.json() == {"detail": {"error": "invalid token"}}

    def test_expired_token(self, client, expired_token):
        """Test expired token returns 400."""
        response = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {expired_token}"},
        )

        assert response.status_code == 400
        assert response.json() == {"detail": {"error": "invalid token"}}

    def test_malformed_header(self, client):
        """Test malformed Authorization header returns 400."""
        response = client.get(
            "/protected",
            headers={"Authorization": "NotBearer token"},
        )

        assert response.status_code == 400


class TestGetOptionalUser:
    """Tests for get_optional_user dependency."""

    def test_valid_token(self, client, valid_token):
        """Test valid token returns user info."""
        response = client.get(
            "/optional",
            headers={"Authorization": f"Bearer {valid_token}"},
        )

        assert response.status_code == 200
        assert response.json() == {"user": "testuser"}

    def test_missing_token(self, client):
        """Test missing token returns guest."""
        response = client.get("/optional")

        assert response.status_code == 200
        assert response.json() == {"user": "guest"}

    def test_invalid_token(self, client):
        """Test invalid token returns guest (no error)."""
        response = client.get(
            "/optional",
            headers={"Authorization": "Bearer invalid-token"},
        )

        assert response.status_code == 200
        assert response.json() == {"user": "guest"}


class TestRequirePermissions:
    """Tests for require_permissions dependency."""

    def test_has_permission(self, client, valid_token):
        """Test user with permission can access."""
        response = client.get(
            "/devices",
            headers={"Authorization": f"Bearer {valid_token}"},
        )

        assert response.status_code == 200
        assert response.json()["user"] == "testuser"

    def test_missing_permission(self, client, valid_token):
        """Test user without permission gets 401."""
        # valid_token has devices.view but not admin.view + admin.edit
        response = client.get(
            "/admin",
            headers={"Authorization": f"Bearer {valid_token}"},
        )

        assert response.status_code == 401
        assert response.json() == {"detail": {"error": "Not authorized"}}

    def test_superuser_has_all_permissions(self, client, superuser_token):
        """Test superuser can access any endpoint."""
        response = client.get(
            "/admin",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )

        assert response.status_code == 200
        assert response.json() == {"admin": "panel"}

    def test_internal_request_bypasses_auth(self, client):
        """Test internal service request bypasses permission check."""
        response = client.get(
            "/devices",
            headers={"X-Internal-Service": "notification-service"},
        )

        assert response.status_code == 200

    def test_missing_token(self, client):
        """Test missing token returns 400."""
        response = client.get("/devices")

        assert response.status_code == 400
