"""Unit tests for security utilities."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta

from app.core.security import (
    SecurityUtils,
    get_current_token_payload,
    get_current_user,
    get_current_service_client,
    require_scopes,
    require_roles,
    require_admin,
    require_any_scope,
    get_optional_current_user,
)
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    UserNotFoundError,
    UserDisabledError,
    UserLockedError,
    ServiceClientNotFoundError,
    ServiceClientDisabledError,
    RevokedTokenError,
    InsufficientScopeError,
)
from app.core.jwt import JWTClaims, TokenType
from app.models.user import User
from app.models.service_client import ServiceClient


class TestSecurityUtils:
    """Test SecurityUtils class methods."""

    @pytest.mark.unit
    def test_extract_bearer_token_valid(self):
        """Test extracting valid bearer token."""
        from fastapi.security import HTTPAuthorizationCredentials
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid.jwt.token"
        )
        
        token = SecurityUtils.extract_bearer_token(credentials)
        assert token == "valid.jwt.token"

    @pytest.mark.unit
    def test_extract_bearer_token_none_credentials(self):
        """Test extracting token with None credentials."""
        with pytest.raises(AuthenticationError) as exc_info:
            SecurityUtils.extract_bearer_token(None)
        
        assert "No authentication token provided" in str(exc_info.value)

    @pytest.mark.unit
    def test_extract_bearer_token_empty_credentials(self):
        """Test extracting token with empty credentials."""
        from fastapi.security import HTTPAuthorizationCredentials
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=""
        )
        
        with pytest.raises(AuthenticationError) as exc_info:
            SecurityUtils.extract_bearer_token(credentials)
        
        assert "No authentication token provided" in str(exc_info.value)

    @pytest.mark.unit
    async def test_is_token_revoked_true(self):
        """Test checking revoked token."""
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = True
        
        jti = "revoked-token-id"
        is_revoked = await SecurityUtils.is_token_revoked(jti, mock_redis)
        
        assert is_revoked is True
        mock_redis.exists.assert_called_once_with(f"revoked_token:{jti}")

    @pytest.mark.unit
    async def test_is_token_revoked_false(self):
        """Test checking non-revoked token."""
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = False
        
        jti = "valid-token-id"
        is_revoked = await SecurityUtils.is_token_revoked(jti, mock_redis)
        
        assert is_revoked is False
        mock_redis.exists.assert_called_once_with(f"revoked_token:{jti}")

    @pytest.mark.unit
    async def test_is_token_revoked_redis_error(self):
        """Test token revocation check with Redis error."""
        mock_redis = AsyncMock()
        mock_redis.exists.side_effect = Exception("Redis connection failed")
        
        jti = "token-id"
        is_revoked = await SecurityUtils.is_token_revoked(jti, mock_redis)
        
        # Should return False on Redis error (fail open)
        assert is_revoked is False

    @pytest.mark.unit
    async def test_revoke_token_success(self):
        """Test successful token revocation."""
        mock_redis = AsyncMock()
        
        jti = "token-to-revoke"
        ttl = 3600
        
        await SecurityUtils.revoke_token(jti, mock_redis, ttl)
        
        mock_redis.set.assert_called_once_with(
            f"revoked_token:{jti}", 
            "1", 
            expire=ttl
        )

    @pytest.mark.unit
    async def test_revoke_token_redis_error(self):
        """Test token revocation with Redis error."""
        mock_redis = AsyncMock()
        mock_redis.set.side_effect = Exception("Redis connection failed")
        
        jti = "token-to-revoke"
        
        # Should not raise exception on Redis error
        await SecurityUtils.revoke_token(jti, mock_redis)

    @pytest.mark.unit
    async def test_get_user_by_id_success(self):
        """Test successful user retrieval by ID."""
        mock_db = AsyncMock()
        mock_result = Mock()
        mock_user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            is_active=True
        )
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db.execute.return_value = mock_result
        
        user_id = "123e4567-e89b-12d3-a456-426614174000"
        user = await SecurityUtils.get_user_by_id(user_id, mock_db)
        
        assert user == mock_user
        mock_db.execute.assert_called_once()

    @pytest.mark.unit
    async def test_get_user_by_id_not_found(self):
        """Test user retrieval with non-existent ID."""
        mock_db = AsyncMock()
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        user_id = "nonexistent-id"
        
        with pytest.raises(UserNotFoundError) as exc_info:
            await SecurityUtils.get_user_by_id(user_id, mock_db)
        
        assert user_id in str(exc_info.value)

    @pytest.mark.unit
    async def test_get_user_by_id_disabled(self):
        """Test user retrieval with disabled user."""
        mock_db = AsyncMock()
        mock_result = Mock()
        mock_user = User(
            username="disabled",
            email="disabled@example.com",
            password_hash="hash",
            is_active=False
        )
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db.execute.return_value = mock_result
        
        user_id = "disabled-user-id"
        
        with pytest.raises(UserDisabledError):
            await SecurityUtils.get_user_by_id(user_id, mock_db)

    @pytest.mark.unit
    async def test_get_user_by_id_locked(self):
        """Test user retrieval with locked user."""
        mock_db = AsyncMock()
        mock_result = Mock()
        mock_user = User(
            username="locked",
            email="locked@example.com",
            password_hash="hash",
            is_active=True,
            locked_until=datetime.utcnow() + timedelta(hours=1)
        )
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db.execute.return_value = mock_result
        
        user_id = "locked-user-id"
        
        with pytest.raises(UserLockedError):
            await SecurityUtils.get_user_by_id(user_id, mock_db)

    @pytest.mark.unit
    async def test_get_service_client_by_id_success(self):
        """Test successful service client retrieval."""
        mock_db = AsyncMock()
        mock_result = Mock()
        mock_client = ServiceClient(
            client_id="test-service",
            client_secret_hash="hash",
            name="Test Service",
            is_active=True
        )
        mock_result.scalar_one_or_none.return_value = mock_client
        mock_db.execute.return_value = mock_result
        
        client_id = "test-service"
        client = await SecurityUtils.get_service_client_by_id(client_id, mock_db)
        
        assert client == mock_client

    @pytest.mark.unit
    async def test_get_service_client_by_id_not_found(self):
        """Test service client retrieval with non-existent ID."""
        mock_db = AsyncMock()
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        client_id = "nonexistent-service"
        
        with pytest.raises(ServiceClientNotFoundError) as exc_info:
            await SecurityUtils.get_service_client_by_id(client_id, mock_db)
        
        assert client_id in str(exc_info.value)

    @pytest.mark.unit
    async def test_get_service_client_by_id_disabled(self):
        """Test service client retrieval with disabled client."""
        mock_db = AsyncMock()
        mock_result = Mock()
        mock_client = ServiceClient(
            client_id="disabled-service",
            client_secret_hash="hash",
            name="Disabled Service",
            is_active=False
        )
        mock_result.scalar_one_or_none.return_value = mock_client
        mock_db.execute.return_value = mock_result
        
        client_id = "disabled-service"
        
        with pytest.raises(ServiceClientDisabledError):
            await SecurityUtils.get_service_client_by_id(client_id, mock_db)


class TestTokenPayloadDependency:
    """Test get_current_token_payload dependency."""

    @pytest.mark.unit
    @patch('app.core.security.jwt_service')
    async def test_get_current_token_payload_valid(self, mock_jwt_service):
        """Test valid token payload extraction."""
        from fastapi.security import HTTPAuthorizationCredentials
        
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = False
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid.jwt.token"
        )
        
        expected_payload = {
            JWTClaims.SUBJECT: "user-123",
            JWTClaims.JWT_ID: "token-id",
            JWTClaims.TOKEN_TYPE: TokenType.ACCESS
        }
        mock_jwt_service.validate_token.return_value = expected_payload
        
        payload = await get_current_token_payload(credentials, mock_redis)
        
        assert payload == expected_payload
        mock_jwt_service.validate_token.assert_called_once_with("valid.jwt.token")

    @pytest.mark.unit
    @patch('app.core.security.jwt_service')
    async def test_get_current_token_payload_revoked(self, mock_jwt_service):
        """Test revoked token payload extraction."""
        from fastapi.security import HTTPAuthorizationCredentials
        from fastapi import HTTPException
        
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = True  # Token is revoked
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="revoked.jwt.token"
        )
        
        payload = {
            JWTClaims.SUBJECT: "user-123",
            JWTClaims.JWT_ID: "revoked-token-id",
            JWTClaims.TOKEN_TYPE: TokenType.ACCESS
        }
        mock_jwt_service.validate_token.return_value = payload
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_token_payload(credentials, mock_redis)
        
        assert exc_info.value.status_code == 401

    @pytest.mark.unit
    async def test_get_current_token_payload_no_credentials(self):
        """Test token payload extraction with no credentials."""
        from fastapi import HTTPException
        
        mock_redis = AsyncMock()
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_token_payload(None, mock_redis)
        
        assert exc_info.value.status_code == 401


class TestCurrentUserDependency:
    """Test get_current_user dependency."""

    @pytest.mark.unit
    @patch('app.core.security.SecurityUtils.get_user_by_id')
    async def test_get_current_user_success(self, mock_get_user):
        """Test successful current user retrieval."""
        mock_db = AsyncMock()
        mock_user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            is_active=True
        )
        mock_get_user.return_value = mock_user
        
        payload = {
            JWTClaims.SUBJECT: "user-123",
            JWTClaims.TOKEN_TYPE: TokenType.ACCESS
        }
        
        user = await get_current_user(payload, mock_db)
        
        assert user == mock_user
        mock_get_user.assert_called_once_with("user-123", mock_db)

    @pytest.mark.unit
    async def test_get_current_user_service_token(self):
        """Test current user retrieval with service token."""
        from fastapi import HTTPException
        
        mock_db = AsyncMock()
        payload = {
            JWTClaims.SUBJECT: "service-client",
            JWTClaims.TOKEN_TYPE: TokenType.SERVICE
        }
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(payload, mock_db)
        
        assert exc_info.value.status_code == 401

    @pytest.mark.unit
    async def test_get_current_user_missing_subject(self):
        """Test current user retrieval with missing subject."""
        from fastapi import HTTPException
        
        mock_db = AsyncMock()
        payload = {
            JWTClaims.TOKEN_TYPE: TokenType.ACCESS
            # Missing SUBJECT
        }
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(payload, mock_db)
        
        assert exc_info.value.status_code == 401


class TestCurrentServiceClientDependency:
    """Test get_current_service_client dependency."""

    @pytest.mark.unit
    @patch('app.core.security.SecurityUtils.get_service_client_by_id')
    async def test_get_current_service_client_success(self, mock_get_client):
        """Test successful service client retrieval."""
        mock_db = AsyncMock()
        mock_client = ServiceClient(
            client_id="test-service",
            client_secret_hash="hash",
            name="Test Service",
            is_active=True
        )
        mock_get_client.return_value = mock_client
        
        payload = {
            JWTClaims.CLIENT_ID: "test-service",
            JWTClaims.TOKEN_TYPE: TokenType.SERVICE
        }
        
        client = await get_current_service_client(payload, mock_db)
        
        assert client == mock_client
        mock_get_client.assert_called_once_with("test-service", mock_db)

    @pytest.mark.unit
    async def test_get_current_service_client_user_token(self):
        """Test service client retrieval with user token."""
        from fastapi import HTTPException
        
        mock_db = AsyncMock()
        payload = {
            JWTClaims.SUBJECT: "user-123",
            JWTClaims.TOKEN_TYPE: TokenType.ACCESS
        }
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_service_client(payload, mock_db)
        
        assert exc_info.value.status_code == 401


class TestScopeRequirements:
    """Test scope-based authorization dependencies."""

    @pytest.mark.unit
    def test_require_scopes_success(self):
        """Test successful scope requirement check."""
        required_scopes = ["read:profile", "write:profile"]
        check_scopes = require_scopes(required_scopes)
        
        payload = {
            JWTClaims.SCOPES: ["read:profile", "write:profile", "admin:users"]
        }
        
        # Should not raise exception
        result = check_scopes.__wrapped__(payload)
        assert result == payload

    @pytest.mark.unit
    def test_require_scopes_insufficient(self):
        """Test insufficient scope requirement check."""
        from fastapi import HTTPException
        
        required_scopes = ["read:profile", "write:profile", "admin:users"]
        check_scopes = require_scopes(required_scopes)
        
        payload = {
            JWTClaims.SCOPES: ["read:profile"]  # Missing scopes
        }
        
        with pytest.raises(HTTPException) as exc_info:
            check_scopes.__wrapped__(payload)
        
        assert exc_info.value.status_code == 403

    @pytest.mark.unit
    def test_require_any_scope_success(self):
        """Test successful any scope requirement check."""
        allowed_scopes = ["read:profile", "read:admin"]
        check_any_scope = require_any_scope(allowed_scopes)
        
        payload = {
            JWTClaims.SCOPES: ["read:profile", "write:profile"]
        }
        
        # Should not raise exception (has read:profile)
        result = check_any_scope.__wrapped__(payload)
        assert result == payload

    @pytest.mark.unit
    def test_require_any_scope_insufficient(self):
        """Test insufficient any scope requirement check."""
        from fastapi import HTTPException
        
        allowed_scopes = ["read:admin", "write:admin"]
        check_any_scope = require_any_scope(allowed_scopes)
        
        payload = {
            JWTClaims.SCOPES: ["read:profile", "write:profile"]
        }
        
        with pytest.raises(HTTPException) as exc_info:
            check_any_scope.__wrapped__(payload)
        
        assert exc_info.value.status_code == 403


class TestRoleRequirements:
    """Test role-based authorization dependencies."""

    @pytest.mark.unit
    async def test_require_roles_success(self):
        """Test successful role requirement check."""
        required_roles = ["admin", "user"]
        check_roles = require_roles(required_roles)
        
        mock_user = Mock()
        mock_user.get_role_names = AsyncMock(return_value=["admin", "moderator"])
        
        # Should not raise exception
        result = await check_roles.__wrapped__(mock_user)
        assert result == mock_user

    @pytest.mark.unit
    async def test_require_roles_insufficient(self):
        """Test insufficient role requirement check."""
        from fastapi import HTTPException
        
        required_roles = ["admin", "superuser"]
        check_roles = require_roles(required_roles)
        
        mock_user = Mock()
        mock_user.get_role_names = AsyncMock(return_value=["user", "moderator"])
        
        with pytest.raises(HTTPException) as exc_info:
            await check_roles.__wrapped__(mock_user)
        
        assert exc_info.value.status_code == 403

    @pytest.mark.unit
    def test_require_admin(self):
        """Test admin requirement dependency."""
        admin_check = require_admin()
        roles_check = require_roles(["admin"])
        
        # Should be functionally equivalent to require_roles(["admin"])
        # Both should have the same wrapped function behavior
        assert hasattr(admin_check, '__wrapped__')
        assert hasattr(roles_check, '__wrapped__')
        
        # Test that both functions exist and are callable
        assert callable(admin_check)
        assert callable(roles_check)


class TestOptionalAuthentication:
    """Test optional authentication dependency."""

    @pytest.mark.unit
    @patch('app.core.security.jwt_service')
    @patch('app.core.security.SecurityUtils.get_user_by_id')
    async def test_get_optional_current_user_with_token(self, mock_get_user, mock_jwt_service):
        """Test optional user retrieval with valid token."""
        from fastapi.security import HTTPAuthorizationCredentials
        
        mock_db = AsyncMock()
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = False
        
        mock_user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            is_active=True
        )
        mock_get_user.return_value = mock_user
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="valid.jwt.token"
        )
        
        payload = {
            JWTClaims.SUBJECT: "user-123",
            JWTClaims.JWT_ID: "token-id",
            JWTClaims.TOKEN_TYPE: TokenType.ACCESS
        }
        mock_jwt_service.validate_token.return_value = payload
        
        user = await get_optional_current_user(credentials, mock_db, mock_redis)
        
        assert user == mock_user

    @pytest.mark.unit
    async def test_get_optional_current_user_no_token(self):
        """Test optional user retrieval without token."""
        mock_db = AsyncMock()
        mock_redis = AsyncMock()
        
        user = await get_optional_current_user(None, mock_db, mock_redis)
        
        assert user is None

    @pytest.mark.unit
    @patch('app.core.security.jwt_service')
    async def test_get_optional_current_user_invalid_token(self, mock_jwt_service):
        """Test optional user retrieval with invalid token."""
        from fastapi.security import HTTPAuthorizationCredentials
        
        mock_db = AsyncMock()
        mock_redis = AsyncMock()
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="invalid.jwt.token"
        )
        
        mock_jwt_service.validate_token.side_effect = Exception("Invalid token")
        
        user = await get_optional_current_user(credentials, mock_db, mock_redis)
        
        # Should return None on any error
        assert user is None

    @pytest.mark.unit
    @patch('app.core.security.jwt_service')
    async def test_get_optional_current_user_service_token(self, mock_jwt_service):
        """Test optional user retrieval with service token."""
        from fastapi.security import HTTPAuthorizationCredentials
        
        mock_db = AsyncMock()
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = False
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="service.jwt.token"
        )
        
        payload = {
            JWTClaims.CLIENT_ID: "service-client",
            JWTClaims.TOKEN_TYPE: TokenType.SERVICE
        }
        mock_jwt_service.validate_token.return_value = payload
        
        user = await get_optional_current_user(credentials, mock_db, mock_redis)
        
        # Should return None for service tokens
        assert user is None


class TestSecurityIntegration:
    """Test security component integration."""

    @pytest.mark.unit
    def test_convenience_dependencies_exist(self):
        """Test that convenience dependencies are properly defined."""
        from app.core.security import CurrentUser, CurrentServiceClient, OptionalCurrentUser, AdminUser
        
        # These should be Depends() instances
        assert CurrentUser is not None
        assert CurrentServiceClient is not None
        assert OptionalCurrentUser is not None
        assert AdminUser is not None

    @pytest.mark.unit
    def test_security_scheme_configuration(self):
        """Test HTTP Bearer security scheme configuration."""
        from app.core.security import security
        from fastapi.security import HTTPBearer
        
        assert isinstance(security, HTTPBearer)
        assert security.auto_error is False  # Should not auto-error for optional auth