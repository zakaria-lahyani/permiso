"""Custom exceptions for Keystone authentication system."""

from typing import Any, Dict, Optional
from fastapi import HTTPException


class KeystoneException(Exception):
    """Base exception for Keystone authentication system."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        status_code: int = 500,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        self.message = message
        self.error_code = error_code or self.__class__.__name__.lower()
        self.details = details or {}
        self.status_code = status_code
        self.context = context or {}
        self.original_error = original_error
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses."""
        result = {
            "error": self.error_code,
            "error_description": self.message,
            "error_code": self.error_code,
            "status_code": self.status_code,
            "details": self.details,
        }
        if self.context:
            result["context"] = self.context
        return result

    def to_http_exception(self) -> HTTPException:
        """Convert to FastAPI HTTPException."""
        return HTTPException(
            status_code=self.status_code,
            detail=self.to_dict()
        )

    def to_response_dict(self) -> Dict[str, Any]:
        """Convert to response dictionary format."""
        return {
            "error": self.error_code,
            "error_description": self.message,
        }

    def get_response_headers(self) -> Dict[str, str]:
        """Get response headers for this exception."""
        return {}

    def get_log_data(self) -> Dict[str, Any]:
        """Get data for logging."""
        return {
            "error_type": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
            "context": self.context,
        }

    def get_security_log_data(self) -> Dict[str, Any]:
        """Get security-specific log data."""
        log_data = self.get_log_data()
        log_data["security_event"] = "security_exception"
        return log_data


class AuthenticationError(KeystoneException):
    """Raised when authentication fails."""

    def __init__(
        self,
        message: str = "Authentication failed",
        error_code: str = "authentication_failed",
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, 401, context, original_error)

    def get_response_headers(self) -> Dict[str, str]:
        """Get response headers for authentication errors."""
        return {"WWW-Authenticate": "Bearer"}


class AuthorizationError(KeystoneException):
    """Raised when authorization fails."""

    def __init__(
        self,
        message: str = "Authorization failed",
        error_code: str = "authorization_failed",
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, 403, context, original_error)


class ValidationError(KeystoneException):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str = "Validation failed",
        error_code: str = "validation_failed",
        details: Optional[Dict[str, Any]] = None,
        field_errors: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, 422, context, original_error)
        self.field_errors = field_errors or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary with field errors."""
        result = super().to_dict()
        if self.field_errors:
            result["field_errors"] = self.field_errors
        return result


class TokenError(AuthenticationError):
    """Raised when token operations fail."""

    def __init__(
        self,
        message: str = "Token error",
        error_code: str = "token_error",
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
        status_code: Optional[int] = None,
    ):
        super().__init__(message, error_code, details, context, original_error)
        if status_code is not None:
            self.status_code = status_code


class ExpiredTokenError(TokenError):
    """Raised when token has expired."""

    def __init__(
        self,
        message: str = "Token has expired",
        error_code: str = "token_expired",
        details: Optional[Dict[str, Any]] = None,
        expired_at: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, context, original_error)
        self.expired_at = expired_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary with expired_at."""
        result = super().to_dict()
        if self.expired_at:
            result["expired_at"] = self.expired_at
        return result


class InvalidTokenError(TokenError):
    """Raised when token is invalid."""

    def __init__(
        self,
        message: str = "Invalid token",
        error_code: str = "invalid_token",
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, context, original_error)


class RevokedTokenError(TokenError):
    """Raised when token has been revoked."""

    def __init__(
        self,
        message: str = "Token has been revoked",
        error_code: str = "token_revoked",
        details: Optional[Dict[str, Any]] = None,
        jti: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, context, original_error)
        self.jti = jti

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary with jti."""
        result = super().to_dict()
        if self.jti:
            result["jti"] = self.jti
        return result


class UserNotFoundError(AuthenticationError):
    """Raised when user is not found."""

    def __init__(
        self,
        message: str = "User not found",
        error_code: str = "user_not_found",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)
        self.status_code = 404  # Override to 404 for not found


class UserDisabledError(AuthenticationError):
    """Raised when user account is disabled."""

    def __init__(
        self,
        message: str = "User account is disabled",
        error_code: str = "user_disabled",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)
        self.status_code = 403  # Override to 403 for disabled account


class UserLockedError(AuthenticationError):
    """Raised when user account is locked."""

    def __init__(
        self,
        message: str = "User account is locked",
        error_code: str = "user_locked",
        details: Optional[Dict[str, Any]] = None,
        locked_until: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, context, original_error)
        self.locked_until = locked_until
        self.status_code = 423

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary with locked_until."""
        result = super().to_dict()
        if self.locked_until:
            result["locked_until"] = self.locked_until
        return result


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
        errors: Optional[list] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, None, context, original_error)
        self.validation_errors = errors or []

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary with validation errors."""
        result = super().to_dict()
        if self.validation_errors:
            result["validation_errors"] = self.validation_errors
        return result


class RateLimitError(KeystoneException):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        error_code: str = "rate_limit_exceeded",
        details: Optional[Dict[str, Any]] = None,
        retry_after: Optional[int] = None,
        limit: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, 429, context, original_error)
        self.retry_after = retry_after
        self.limit = limit

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary with retry_after."""
        result = super().to_dict()
        if self.retry_after:
            result["retry_after"] = self.retry_after
        if self.limit:
            result["limit"] = self.limit
        return result

    def get_response_headers(self) -> Dict[str, str]:
        """Get response headers for rate limit errors."""
        headers = {}
        if self.retry_after:
            headers["Retry-After"] = str(self.retry_after)
        return headers


class ServiceClientError(AuthenticationError):
    """Raised when service client operations fail."""

    def __init__(
        self,
        message: str = "Service client error",
        error_code: str = "service_client_error",
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
        status_code: Optional[int] = None,
    ):
        super().__init__(message, error_code, details, context, original_error)
        if status_code is not None:
            self.status_code = status_code


class ServiceClientNotFoundError(ServiceClientError):
    """Raised when service client is not found."""

    def __init__(
        self,
        message: str = "Service client not found",
        error_code: str = "client_not_found",
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, context, original_error)
        self.status_code = 404


class ServiceClientDisabledError(ServiceClientError):
    """Raised when service client is disabled."""

    def __init__(
        self,
        message: str = "Service client is disabled",
        error_code: str = "client_disabled",
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, context, original_error)
        self.status_code = 403


class InsufficientScopeError(AuthorizationError):
    """Raised when token lacks required scopes."""

    def __init__(
        self,
        message: str = "Insufficient scope",
        error_code: str = "insufficient_scope",
        details: Optional[Dict[str, Any]] = None,
        required_scopes: Optional[list] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, context, original_error)
        self.required_scopes = required_scopes or []

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary with required scopes."""
        result = super().to_dict()
        if self.required_scopes:
            result["required_scopes"] = self.required_scopes
        return result

    def get_security_log_data(self) -> Dict[str, Any]:
        """Get security-specific log data."""
        log_data = self.get_log_data()
        log_data["security_event"] = "authorization_failure"
        log_data["required_scopes"] = self.required_scopes
        if self.context:
            log_data.update({
                "user_id": self.context.get("user_id"),
                "endpoint": self.context.get("endpoint"),
            })
        return log_data


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


class NotFoundError(KeystoneException):
    """Raised when a resource is not found."""

    def __init__(
        self,
        message: str = "Resource not found",
        error_code: str = "not_found",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)


class RateLimitExceededError(RateLimitError):
    """Raised when rate limit is exceeded (alias for RateLimitError)."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        error_code: str = "rate_limit_exceeded",
        details: Optional[Dict[str, Any]] = None,
        retry_after: Optional[int] = None,
        limit: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, details, retry_after, limit, context, original_error)


class ConflictError(ValidationError):
    """Raised when there's a conflict with existing data."""

    def __init__(
        self,
        message: str = "Conflict with existing data",
        error_code: str = "conflict",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, error_code, details)