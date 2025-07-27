"""Unit tests for exception handling."""

import pytest
from fastapi import HTTPException

from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    UserNotFoundError,
    UserDisabledError,
    UserLockedError,
    ServiceClientNotFoundError,
    ServiceClientDisabledError,
    InvalidTokenError,
    ExpiredTokenError,
    RevokedTokenError,
    InsufficientScopeError,
    PasswordPolicyError,
    RateLimitExceededError,
    ValidationError,
)


class TestAuthenticationExceptions:
    """Test authentication-related exceptions."""

    @pytest.mark.unit
    def test_authentication_error_creation(self):
        """Test AuthenticationError creation and properties."""
        message = "Invalid credentials"
        error = AuthenticationError(message)
        
        assert str(error) == message
        assert error.message == message
        assert error.error_code == "authentication_failed"
        assert error.status_code == 401

    @pytest.mark.unit
    def test_authentication_error_with_details(self):
        """Test AuthenticationError with additional details."""
        message = "Login failed"
        details = {"attempts": 3, "locked_until": "2024-01-01T10:00:00Z"}
        error = AuthenticationError(message, details=details)
        
        assert error.details == details
        error_dict = error.to_dict()
        assert error_dict["error"] == "authentication_failed"
        assert error_dict["error_description"] == message
        assert error_dict["details"] == details

    @pytest.mark.unit
    def test_authentication_error_http_exception(self):
        """Test conversion to HTTPException."""
        error = AuthenticationError("Invalid token")
        http_exc = error.to_http_exception()
        
        assert isinstance(http_exc, HTTPException)
        assert http_exc.status_code == 401
        assert "authentication_failed" in str(http_exc.detail)


class TestAuthorizationExceptions:
    """Test authorization-related exceptions."""

    @pytest.mark.unit
    def test_authorization_error_creation(self):
        """Test AuthorizationError creation."""
        message = "Insufficient permissions"
        error = AuthorizationError(message)
        
        assert str(error) == message
        assert error.error_code == "authorization_failed"
        assert error.status_code == 403

    @pytest.mark.unit
    def test_insufficient_scope_error(self):
        """Test InsufficientScopeError with required scopes."""
        message = "Missing required scopes"
        required_scopes = ["read:admin", "write:users"]
        error = InsufficientScopeError(message, required_scopes=required_scopes)
        
        assert error.required_scopes == required_scopes
        assert error.error_code == "insufficient_scope"
        assert error.status_code == 403
        
        error_dict = error.to_dict()
        assert error_dict["required_scopes"] == required_scopes


class TestUserExceptions:
    """Test user-related exceptions."""

    @pytest.mark.unit
    def test_user_not_found_error(self):
        """Test UserNotFoundError."""
        user_id = "123e4567-e89b-12d3-a456-426614174000"
        error = UserNotFoundError(f"User {user_id} not found")
        
        assert error.error_code == "user_not_found"
        assert error.status_code == 404
        assert user_id in str(error)

    @pytest.mark.unit
    def test_user_disabled_error(self):
        """Test UserDisabledError."""
        error = UserDisabledError("User account is disabled")
        
        assert error.error_code == "user_disabled"
        assert error.status_code == 403

    @pytest.mark.unit
    def test_user_locked_error(self):
        """Test UserLockedError with lockout details."""
        locked_until = "2024-01-01T10:00:00Z"
        error = UserLockedError("Account locked", locked_until=locked_until)
        
        assert error.error_code == "user_locked"
        assert error.status_code == 423
        assert error.locked_until == locked_until
        
        error_dict = error.to_dict()
        assert error_dict["locked_until"] == locked_until


class TestServiceClientExceptions:
    """Test service client-related exceptions."""

    @pytest.mark.unit
    def test_service_client_not_found_error(self):
        """Test ServiceClientNotFoundError."""
        client_id = "my-service"
        error = ServiceClientNotFoundError(f"Client {client_id} not found")
        
        assert error.error_code == "client_not_found"
        assert error.status_code == 404
        assert client_id in str(error)

    @pytest.mark.unit
    def test_service_client_disabled_error(self):
        """Test ServiceClientDisabledError."""
        error = ServiceClientDisabledError("Service client is disabled")
        
        assert error.error_code == "client_disabled"
        assert error.status_code == 403


class TestTokenExceptions:
    """Test token-related exceptions."""

    @pytest.mark.unit
    def test_invalid_token_error(self):
        """Test InvalidTokenError."""
        error = InvalidTokenError("Token signature is invalid")
        
        assert error.error_code == "invalid_token"
        assert error.status_code == 401

    @pytest.mark.unit
    def test_expired_token_error(self):
        """Test ExpiredTokenError with expiration time."""
        expired_at = "2024-01-01T10:00:00Z"
        error = ExpiredTokenError("Token has expired", expired_at=expired_at)
        
        assert error.error_code == "token_expired"
        assert error.status_code == 401
        assert error.expired_at == expired_at

    @pytest.mark.unit
    def test_revoked_token_error(self):
        """Test RevokedTokenError."""
        jti = "unique-token-id"
        error = RevokedTokenError("Token has been revoked", jti=jti)
        
        assert error.error_code == "token_revoked"
        assert error.status_code == 401
        assert error.jti == jti


class TestValidationExceptions:
    """Test validation-related exceptions."""

    @pytest.mark.unit
    def test_password_policy_error(self):
        """Test PasswordPolicyError with validation errors."""
        validation_errors = [
            "Password must be at least 8 characters",
            "Password must contain uppercase letters"
        ]
        error = PasswordPolicyError("Password policy violation", errors=validation_errors)
        
        assert error.error_code == "password_policy_violation"
        assert error.status_code == 422
        assert error.validation_errors == validation_errors

    @pytest.mark.unit
    def test_validation_error(self):
        """Test general ValidationError."""
        field_errors = {
            "username": ["Username is required"],
            "email": ["Invalid email format"]
        }
        error = ValidationError("Validation failed", field_errors=field_errors)
        
        assert error.error_code == "validation_failed"
        assert error.status_code == 422
        assert error.field_errors == field_errors


class TestRateLimitExceptions:
    """Test rate limiting exceptions."""

    @pytest.mark.unit
    def test_rate_limit_exceeded_error(self):
        """Test RateLimitExceededError with retry information."""
        retry_after = 60
        limit = "5/minute"
        error = RateLimitExceededError(
            "Rate limit exceeded", 
            retry_after=retry_after,
            limit=limit
        )
        
        assert error.error_code == "rate_limit_exceeded"
        assert error.status_code == 429
        assert error.retry_after == retry_after
        assert error.limit == limit
        
        error_dict = error.to_dict()
        assert error_dict["retry_after"] == retry_after
        assert error_dict["limit"] == limit


class TestExceptionChaining:
    """Test exception chaining and context."""

    @pytest.mark.unit
    def test_exception_chaining(self):
        """Test exception chaining with original cause."""
        original_error = ValueError("Original error")
        
        try:
            raise original_error
        except ValueError as e:
            auth_error = AuthenticationError("Authentication failed", original_error=e)
            
            assert auth_error.original_error == original_error
            assert "Original error" in str(auth_error.original_error)

    @pytest.mark.unit
    def test_exception_context_preservation(self):
        """Test that exception context is preserved."""
        context = {
            "user_id": "123",
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0"
        }
        
        error = AuthenticationError("Login failed", context=context)
        
        assert error.context == context
        error_dict = error.to_dict()
        assert error_dict["context"] == context


class TestExceptionSerialization:
    """Test exception serialization and deserialization."""

    @pytest.mark.unit
    def test_exception_to_dict(self):
        """Test exception serialization to dictionary."""
        error = AuthenticationError(
            "Login failed",
            details={"attempts": 3},
            context={"ip": "192.168.1.1"}
        )
        
        error_dict = error.to_dict()
        
        expected_keys = [
            "error", "error_description", "error_code", 
            "status_code", "details", "context"
        ]
        for key in expected_keys:
            assert key in error_dict

    @pytest.mark.unit
    def test_exception_json_serialization(self):
        """Test exception JSON serialization."""
        import json
        
        error = AuthorizationError("Access denied", details={"role": "user"})
        error_dict = error.to_dict()
        
        # Should be JSON serializable
        json_str = json.dumps(error_dict)
        assert isinstance(json_str, str)
        
        # Should be deserializable
        deserialized = json.loads(json_str)
        assert deserialized["error"] == "authorization_failed"
        assert deserialized["details"]["role"] == "user"


class TestExceptionLogging:
    """Test exception logging integration."""

    @pytest.mark.unit
    def test_exception_logging_data(self):
        """Test exception provides proper logging data."""
        error = AuthenticationError(
            "Login failed",
            details={"user_id": "123", "attempts": 3},
            context={"ip": "192.168.1.1"}
        )
        
        log_data = error.get_log_data()
        
        assert log_data["error_type"] == "AuthenticationError"
        assert log_data["error_code"] == "authentication_failed"
        assert log_data["message"] == "Login failed"
        assert log_data["details"] == {"user_id": "123", "attempts": 3}
        assert log_data["context"] == {"ip": "192.168.1.1"}

    @pytest.mark.unit
    def test_exception_security_logging(self):
        """Test security-related exception logging."""
        error = InsufficientScopeError(
            "Missing admin scope",
            required_scopes=["admin:users"],
            context={"user_id": "123", "endpoint": "/admin/users"}
        )
        
        log_data = error.get_security_log_data()
        
        assert log_data["security_event"] == "authorization_failure"
        assert log_data["required_scopes"] == ["admin:users"]
        assert log_data["user_id"] == "123"
        assert log_data["endpoint"] == "/admin/users"


class TestExceptionHandlerIntegration:
    """Test exception handler integration."""

    @pytest.mark.unit
    def test_exception_handler_response_format(self):
        """Test exception handler response format."""
        error = AuthenticationError("Invalid credentials")
        response_data = error.to_response_dict()
        
        # Should match OAuth2 error response format
        assert "error" in response_data
        assert "error_description" in response_data
        assert response_data["error"] == "authentication_failed"
        assert response_data["error_description"] == "Invalid credentials"

    @pytest.mark.unit
    def test_exception_handler_headers(self):
        """Test exception handler headers."""
        error = AuthenticationError("Token required")
        headers = error.get_response_headers()
        
        assert "WWW-Authenticate" in headers
        assert headers["WWW-Authenticate"] == "Bearer"

    @pytest.mark.unit
    def test_rate_limit_exception_headers(self):
        """Test rate limit exception headers."""
        error = RateLimitExceededError("Too many requests", retry_after=60)
        headers = error.get_response_headers()
        
        assert "Retry-After" in headers
        assert headers["Retry-After"] == "60"