"""Pytest fixtures for iot_auth tests."""

import os
from datetime import datetime, timedelta, timezone

import jwt
import pytest

# Set test secret key before importing iot_auth (32+ chars for SHA256)
SECRET_KEY = "test-secret-key-for-testing-1234567890"
os.environ["JWT_SECRET_KEY"] = SECRET_KEY


@pytest.fixture
def secret_key():
    """Return the test secret key."""
    return SECRET_KEY


@pytest.fixture
def valid_payload():
    """Return a valid JWT payload."""
    now = datetime.now(timezone.utc)
    return {
        "sub": "user-123",
        "username": "testuser",
        "email": "test@example.com",
        "groups": ["operators", "viewers"],
        "permissions": ["devices.view", "devices.add", "notification.view"],
        "is_staff": False,
        "is_superuser": False,
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "type": "access",
    }


@pytest.fixture
def superuser_payload(valid_payload):
    """Return a payload for a superuser."""
    return {**valid_payload, "is_superuser": True}


@pytest.fixture
def valid_token(valid_payload, secret_key):
    """Return a valid JWT token."""
    return jwt.encode(valid_payload, secret_key, algorithm="HS256")


@pytest.fixture
def superuser_token(superuser_payload, secret_key):
    """Return a valid JWT token for a superuser."""
    return jwt.encode(superuser_payload, secret_key, algorithm="HS256")


@pytest.fixture
def expired_token(valid_payload, secret_key):
    """Return an expired JWT token."""
    now = datetime.now(timezone.utc)
    expired_payload = {
        **valid_payload,
        "exp": int((now - timedelta(hours=1)).timestamp()),
    }
    return jwt.encode(expired_payload, secret_key, algorithm="HS256")


@pytest.fixture
def invalid_signature_token(valid_payload):
    """Return a token signed with wrong key."""
    return jwt.encode(
        valid_payload, "wrong-secret-key-that-is-long-enough", algorithm="HS256"
    )
