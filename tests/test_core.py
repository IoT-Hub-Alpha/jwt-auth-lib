"""Tests for iot_auth.core module."""

import pytest

from iot_auth.core import (
    InvalidTokenError,
    decode_jwt,
    extract_token_from_header,
    has_permissions,
    is_internal_request,
)


class TestDecodeJWT:
    """Tests for decode_jwt function."""

    def test_decode_valid_token(self, valid_token, secret_key, valid_payload):
        """Test decoding a valid token returns the payload."""
        payload = decode_jwt(valid_token, secret_key)

        assert payload["sub"] == valid_payload["sub"]
        assert payload["username"] == valid_payload["username"]
        assert payload["email"] == valid_payload["email"]
        assert payload["permissions"] == valid_payload["permissions"]

    def test_decode_expired_token_raises(self, expired_token, secret_key):
        """Test decoding an expired token raises InvalidTokenError."""
        with pytest.raises(InvalidTokenError, match="expired"):
            decode_jwt(expired_token, secret_key)

    def test_decode_invalid_signature_raises(self, invalid_signature_token, secret_key):
        """Test decoding a token with invalid signature raises InvalidTokenError."""
        with pytest.raises(InvalidTokenError, match="Invalid token"):
            decode_jwt(invalid_signature_token, secret_key)

    def test_decode_malformed_token_raises(self, secret_key):
        """Test decoding a malformed token raises InvalidTokenError."""
        with pytest.raises(InvalidTokenError, match="Invalid token"):
            decode_jwt("not-a-valid-token", secret_key)

    def test_decode_empty_token_raises(self, secret_key):
        """Test decoding an empty token raises InvalidTokenError."""
        with pytest.raises(InvalidTokenError, match="Invalid token"):
            decode_jwt("", secret_key)


class TestExtractTokenFromHeader:
    """Tests for extract_token_from_header function."""

    def test_extract_valid_bearer_token(self):
        """Test extracting token from valid Bearer header."""
        token = extract_token_from_header("Bearer my-token-here")
        assert token == "my-token-here"

    def test_extract_bearer_case_insensitive(self):
        """Test Bearer prefix is case insensitive."""
        token = extract_token_from_header("bearer my-token-here")
        assert token == "my-token-here"

        token = extract_token_from_header("BEARER my-token-here")
        assert token == "my-token-here"

    def test_extract_returns_none_for_missing_header(self):
        """Test returns None when header is missing."""
        assert extract_token_from_header(None) is None
        assert extract_token_from_header("") is None

    def test_extract_returns_none_for_invalid_format(self):
        """Test returns None for invalid header format."""
        assert extract_token_from_header("Basic my-token") is None
        assert extract_token_from_header("Bearer") is None
        assert extract_token_from_header("my-token") is None
        assert extract_token_from_header("Bearer token extra") is None


class TestIsInternalRequest:
    """Tests for is_internal_request function."""

    def test_internal_request_with_header(self):
        """Test request with internal service header is detected."""
        headers = {"X-Internal-Service": "notification-service"}
        assert is_internal_request(headers) is True

    def test_internal_request_header_case_insensitive(self):
        """Test internal service header is case insensitive."""
        headers = {"x-internal-service": "notification-service"}
        assert is_internal_request(headers) is True

    def test_request_without_header_not_internal(self):
        """Test request without internal header is not internal."""
        headers = {"Authorization": "Bearer token"}
        assert is_internal_request(headers) is False

    def test_empty_headers(self):
        """Test empty headers dict is not internal."""
        assert is_internal_request({}) is False


class TestPermissions:
    """Tests for has_permissions function."""

    def test_single_permission(self, valid_payload):
        """Test checking single permission."""
        assert has_permissions(valid_payload, ["devices.view"]) is True
        assert has_permissions(valid_payload, ["admin.delete"]) is False

    def test_multiple_permissions(self, valid_payload):
        """Test checking multiple permissions (user must have all)."""
        assert has_permissions(valid_payload, ["devices.view", "devices.add"]) is True
        assert has_permissions(valid_payload, ["devices.view", "admin.delete"]) is False

    def test_superuser_has_all_permissions(self, superuser_payload):
        """Test superuser has all permissions."""
        assert has_permissions(superuser_payload, ["admin.delete"]) is True
        assert has_permissions(superuser_payload, ["any.perm", "other.perm"]) is True

    def test_empty_permissions_list(self, valid_payload):
        """Test empty permissions list returns True."""
        assert has_permissions(valid_payload, []) is True
