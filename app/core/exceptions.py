"""Custom exceptions for Keystone authentication system."""

from typing import Any, Dict, Optional


class KeystoneException(Exception):
    """Base exception for Keystone authentication system."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.error_code = error_code or self.__class__.__name__.lower()
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses."""
        return {
            "error": self.error_code,
            "error_description": self.message,
            "details": self.details,
        }


class AuthenticationError(KeystoneException):
    """Raised when authentication fails."""

    def __init__(
        self,
        message: str = "Authentication failed",
        error_code: str = "authentication_failed",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class AuthorizationError(KeystoneException):
    """Raised when authorization fails."""

    def __init__(
        self,
        message: str = "Authorization failed",
        error_code: str = "authorization_failed",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class ValidationError(KeystoneException):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str = "Validation failed",
        error_code: str = "validation_failed",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class TokenError(AuthenticationError):
    """Raised when token operations fail."""

    def __init__(
        self,
        message: str = "Token error",
        error_code: str = "token_error",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class ExpiredTokenError(TokenError):
    """Raised when token has expired."""

    def __init__(
        self,
        message: str = "Token has expired",
        error_code: str = "token_expired",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class InvalidTokenError(TokenError):
    """Raised when token is invalid."""

    def __init__(
        self,
        message: str = "Invalid token",
        error_code: str = "invalid_token",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class RevokedTokenError(TokenError):
    """Raised when token has been revoked."""

    def __init__(
        self,
        message: str = "Token has been revoked",
        error_code: str = "token_revoked",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class UserNotFoundError(AuthenticationError):
    """Raised when user is not found."""

    def __init__(
        self,
        message: str = "User not found",
        error_code: str = "user_not_found",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class UserDisabledError(AuthenticationError):
    """Raised when user account is disabled."""

    def __init__(
        self,
        message: str = "User account is disabled",
        error_code: str = "user_disabled",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class UserLockedError(AuthenticationError):
    """Raised when user account is locked."""

    def __init__(
        self,
        message: str = "User account is locked",
        error_code: str = "user_locked",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid."""

    def __init__(
        self,
        message: str = "Invalid credentials",
        error_code: str = "invalid_credentials",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class PasswordPolicyError(ValidationError):
    """Raised when password doesn't meet policy requirements."""

    def __init__(
        self,
        message: str = "Password does not meet policy requirements",
        error_code: str = "password_policy_violation",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class RateLimitError(KeystoneException):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        error_code: str = "rate_limit_exceeded",
        details: Optional[Dict[str, Any]] = None,
        retry_after: Optional[int] = None,
    ):
        super().__init__(message, error_code, details)
        self.retry_after = retry_after

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary with retry_after."""
        result = super().to_dict()
        if self.retry_after:
            result["retry_after"] = self.retry_after
        return result


class ServiceClientError(AuthenticationError):
    """Raised when service client operations fail."""

    def __init__(
        self,
        message: str = "Service client error",
        error_code: str = "service_client_error",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class ServiceClientNotFoundError(ServiceClientError):
    """Raised when service client is not found."""

    def __init__(
        self,
        message: str = "Service client not found",
        error_code: str = "service_client_not_found",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class ServiceClientDisabledError(ServiceClientError):
    """Raised when service client is disabled."""

    def __init__(
        self,
        message: str = "Service client is disabled",
        error_code: str = "service_client_disabled",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class InsufficientScopeError(AuthorizationError):
    """Raised when token lacks required scopes."""

    def __init__(
        self,
        message: str = "Insufficient scope",
        error_code: str = "insufficient_scope",
        details: Optional[Dict[str, Any]] = None,
        required_scopes: Optional[list] = None,
    ):
        super().__init__(message, error_code, details)
        self.required_scopes = required_scopes or []

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary with required scopes."""
        result = super().to_dict()
        if self.required_scopes:
            result["required_scopes"] = self.required_scopes
        return result


class DatabaseError(KeystoneException):
    """Raised when database operations fail."""

    def __init__(
        self,
        message: str = "Database error",
        error_code: str = "database_error",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class CacheError(KeystoneException):
    """Raised when cache operations fail."""

    def __init__(
        self,
        message: str = "Cache error",
        error_code: str = "cache_error",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class ConfigurationError(KeystoneException):
    """Raised when configuration is invalid."""

    def __init__(
        self,
        message: str = "Configuration error",
        error_code: str = "configuration_error",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class DuplicateResourceError(ValidationError):
    """Raised when trying to create duplicate resource."""

    def __init__(
        self,
        message: str = "Resource already exists",
        error_code: str = "duplicate_resource",
        details: Optional[Dict[str, Any]] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
    ):
        super().__init__(message, error_code, details)
        self.resource_type = resource_type
        self.resource_id = resource_id

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary with resource information."""
        result = super().to_dict()
        if self.resource_type:
            result["resource_type"] = self.resource_type
        if self.resource_id:
            result["resource_id"] = self.resource_id
        return result


class ResourceNotFoundError(KeystoneException):
    """Raised when resource is not found."""

    def __init__(
        self,
        message: str = "Resource not found",
        error_code: str = "resource_not_found",
        details: Optional[Dict[str, Any]] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
    ):
        super().__init__(message, error_code, details)
        self.resource_type = resource_type
        self.resource_id = resource_id

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary with resource information."""
        result = super().to_dict()
        if self.resource_type:
            result["resource_type"] = self.resource_type
        if self.resource_id:
            result["resource_id"] = self.resource_id
        return result