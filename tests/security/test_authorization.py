"""Security tests for authorization functionality."""

import pytest
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from httpx import AsyncClient

from app.core.security import (
    get_current_user,
    get_current_service_client,
    require_scopes,
    require_roles,
    require_admin,
    SecurityUtils,
)
from app.core.jwt import jwt_service, JWTClaims, TokenType
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    InsufficientScopeError,
    UserNotFoundError,
    UserDisabledError,
    UserLockedError,
)
from app.models.user import User
from app.models.service_client import ServiceClient


class TestSecurityDependencies:
    """Test FastAPI security dependencies."""

    @pytest.mark.security
    async def test_get_current_user_valid_token(self, test_user: User, test_access_token: str, db_session):
        """Test getting current user with valid token."""
        # Mock the database dependency
        with patch('app.core.security.get_db', return_value=AsyncMock(return_value=db_session)):
            with patch('app.core.security.get_redis', return_value=AsyncMock()):
                # Mock SecurityUtils.get_user_by_id to return our test user
                with patch.object(SecurityUtils, 'get_user_by_id', return_value=test_user):
                    # Mock token payload
                    payload = {
                        JWTClaims.SUBJECT: str(test_user.id),
                        JWTClaims.TOKEN_TYPE: TokenType.ACCESS,
                        JWTClaims.JWT_ID: "test-jti",
                    }
                    
                    user = await get_current_user(payload, db_session)
                    assert user == test_user

    @pytest.mark.security
    async def test_get_current_user_service_token_rejected(self, db_session):
        """Test that service tokens are rejected for user authentication."""
        payload = {
            JWTClaims.SUBJECT: "service-client-id",
            JWTClaims.TOKEN_TYPE: TokenType.SERVICE,
            JWTClaims.JWT_ID: "test-jti",
        }
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(payload, db_session)
        
        assert exc_info.value.status_code == 401
        assert "Service tokens cannot be used" in str(exc_info.value.detail)

    @pytest.mark.security
    async def test_get_current_user_missing_subject(self, db_session):
        """Test error when token has no subject."""
        payload = {
            JWTClaims.TOKEN_TYPE: TokenType.ACCESS,
            JWTClaims.JWT_ID: "test-jti",
        }
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(payload, db_session)
        
        assert exc_info.value.status_code == 401
        assert "missing user ID" in str(exc_info.value.detail)

    @pytest.mark.security
    async def test_get_current_service_client_valid_token(self, test_service_client: ServiceClient, test_service_token: str, db_session):
        """Test getting current service client with valid token."""
        with patch.object(SecurityUtils, 'get_service_client_by_id', return_value=test_service_client):
            payload = {
                JWTClaims.CLIENT_ID: test_service_client.client_id,
                JWTClaims.TOKEN_TYPE: TokenType.SERVICE,
                JWTClaims.JWT_ID: "test-jti",
            }
            
            client = await get_current_service_client(payload, db_session)
            assert client == test_service_client

    @pytest.mark.security
    async def test_get_current_service_client_user_token_rejected(self, db_session):
        """Test that user tokens are rejected for service authentication."""
        payload = {
            JWTClaims.SUBJECT: "user-id",
            JWTClaims.TOKEN_TYPE: TokenType.ACCESS,
            JWTClaims.JWT_ID: "test-jti",
        }
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_service_client(payload, db_session)
        
        assert exc_info.value.status_code == 401
        assert "Only service tokens" in str(exc_info.value.detail)


class TestScopeBasedAuthorization:
    """Test scope-based authorization."""

    @pytest.mark.security
    async def test_require_scopes_valid(self):
        """Test scope requirement with valid scopes."""
        required_scopes = ["read:profile", "write:profile"]
        check_scopes = require_scopes(required_scopes)
        
        payload = {
            JWTClaims.SCOPES: ["read:profile", "write:profile", "admin:users"],
            JWTClaims.JWT_ID: "test-jti",
        }
        
        result = await check_scopes(payload)
        assert result == payload

    @pytest.mark.security
    async def test_require_scopes_insufficient(self):
        """Test scope requirement with insufficient scopes."""
        required_scopes = ["read:profile", "write:profile", "admin:users"]
        check_scopes = require_scopes(required_scopes)
        
        payload = {
            JWTClaims.SCOPES: ["read:profile"],  # Missing write:profile and admin:users
            JWTClaims.JWT_ID: "test-jti",
        }
        
        with pytest.raises(HTTPException) as exc_info:
            await check_scopes(payload)
        
        assert exc_info.value.status_code == 403
        assert "Insufficient permissions" in str(exc_info.value.detail)

    @pytest.mark.security
    async def test_require_scopes_empty_token_scopes(self):
        """Test scope requirement with empty token scopes."""
        required_scopes = ["read:profile"]
        check_scopes = require_scopes(required_scopes)
        
        payload = {
            JWTClaims.SCOPES: [],  # No scopes
            JWTClaims.JWT_ID: "test-jti",
        }
        
        with pytest.raises(HTTPException) as exc_info:
            await check_scopes(payload)
        
        assert exc_info.value.status_code == 403

    @pytest.mark.security
    async def test_require_scopes_missing_scopes_claim(self):
        """Test scope requirement with missing scopes claim."""
        required_scopes = ["read:profile"]
        check_scopes = require_scopes(required_scopes)
        
        payload = {
            JWTClaims.JWT_ID: "test-jti",
            # No scopes claim
        }
        
        with pytest.raises(HTTPException) as exc_info:
            await check_scopes(payload)
        
        assert exc_info.value.status_code == 403


class TestRoleBasedAuthorization:
    """Test role-based authorization."""

    @pytest.mark.security
    async def test_require_roles_valid(self, test_user: User):
        """Test role requirement with valid roles."""
        # Add admin role to user
        from app.models.role import Role
        admin_role = Role(name="admin", description="Admin role")
        test_user.roles.append(admin_role)
        
        required_roles = ["admin"]
        check_roles = require_roles(required_roles)
        
        result = await check_roles(test_user)
        assert result == test_user

    @pytest.mark.security
    async def test_require_roles_insufficient(self, test_user: User):
        """Test role requirement with insufficient roles."""
        # User has no admin role
        required_roles = ["admin"]
        check_roles = require_roles(required_roles)
        
        with pytest.raises(HTTPException) as exc_info:
            await check_roles(test_user)
        
        assert exc_info.value.status_code == 403
        assert "Insufficient permissions" in str(exc_info.value.detail)

    @pytest.mark.security
    async def test_require_roles_multiple_valid(self, test_user: User):
        """Test role requirement with multiple valid roles."""
        from app.models.role import Role
        user_role = Role(name="user", description="User role")
        admin_role = Role(name="admin", description="Admin role")
        test_user.roles.extend([user_role, admin_role])
        
        # User needs either user OR admin role
        required_roles = ["user", "admin"]
        check_roles = require_roles(required_roles)
        
        result = await check_roles(test_user)
        assert result == test_user

    @pytest.mark.security
    async def test_require_admin_valid(self, admin_user: User):
        """Test admin requirement with admin user."""
        check_admin = require_admin()
        
        result = await check_admin(admin_user)
        assert result == admin_user

    @pytest.mark.security
    async def test_require_admin_invalid(self, test_user: User):
        """Test admin requirement with non-admin user."""
        check_admin = require_admin()
        
        with pytest.raises(HTTPException) as exc_info:
            await check_admin(test_user)
        
        assert exc_info.value.status_code == 403


class TestSecurityUtils:
    """Test SecurityUtils helper methods."""

    @pytest.mark.security
    async def test_is_token_revoked_true(self, test_redis_client):
        """Test checking revoked token."""
        jti = "revoked-token-id"
        
        # Mock Redis to return True for revoked token
        with patch.object(test_redis_client, 'exists', return_value=True):
            result = await SecurityUtils.is_token_revoked(jti, test_redis_client)
            assert result is True

    @pytest.mark.security
    async def test_is_token_revoked_false(self, test_redis_client):
        """Test checking non-revoked token."""
        jti = "valid-token-id"
        
        # Mock Redis to return False for valid token
        with patch.object(test_redis_client, 'exists', return_value=False):
            result = await SecurityUtils.is_token_revoked(jti, test_redis_client)
            assert result is False

    @pytest.mark.security
    async def test_is_token_revoked_redis_error(self, test_redis_client):
        """Test token revocation check with Redis error."""
        jti = "token-id"
        
        # Mock Redis to raise exception
        with patch.object(test_redis_client, 'exists', side_effect=Exception("Redis error")):
            result = await SecurityUtils.is_token_revoked(jti, test_redis_client)
            # Should return False on Redis error (fail open)
            assert result is False

    @pytest.mark.security
    async def test_revoke_token(self, test_redis_client):
        """Test token revocation."""
        jti = "token-to-revoke"
        ttl = 3600
        
        # Mock Redis set method
        with patch.object(test_redis_client, 'set', return_value=True) as mock_set:
            await SecurityUtils.revoke_token(jti, test_redis_client, ttl)
            
            mock_set.assert_called_once_with(f"revoked_token:{jti}", "1", expire=ttl)

    @pytest.mark.security
    async def test_get_user_by_id_valid(self, test_user: User, db_session):
        """Test getting user by ID."""
        with patch('sqlalchemy.ext.asyncio.AsyncSession.execute') as mock_execute:
            from unittest.mock import MagicMock
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = test_user
            mock_execute.return_value = mock_result
            
            result = await SecurityUtils.get_user_by_id(str(test_user.id), db_session)
            assert result == test_user

    @pytest.mark.security
    async def test_get_user_by_id_not_found(self, db_session):
        """Test getting non-existent user."""
        with patch('sqlalchemy.ext.asyncio.AsyncSession.execute') as mock_execute:
            from unittest.mock import MagicMock
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_execute.return_value = mock_result
            
            with pytest.raises(UserNotFoundError):
                await SecurityUtils.get_user_by_id("non-existent-id", db_session)

    @pytest.mark.security
    async def test_get_user_by_id_disabled(self, disabled_user: User, db_session):
        """Test getting disabled user."""
        with patch('sqlalchemy.ext.asyncio.AsyncSession.execute') as mock_execute:
            from unittest.mock import MagicMock
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = disabled_user
            mock_execute.return_value = mock_result
            
            with pytest.raises(UserDisabledError):
                await SecurityUtils.get_user_by_id(str(disabled_user.id), db_session)

    @pytest.mark.security
    async def test_get_user_by_id_locked(self, test_user: User, db_session):
        """Test getting locked user."""
        from datetime import datetime, timedelta
        
        # Lock the user
        test_user.locked_until = datetime.utcnow() + timedelta(hours=1)
        
        with patch('sqlalchemy.ext.asyncio.AsyncSession.execute') as mock_execute:
            from unittest.mock import MagicMock
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = test_user
            mock_execute.return_value = mock_result
            
            with pytest.raises(UserLockedError):
                await SecurityUtils.get_user_by_id(str(test_user.id), db_session)


class TestTokenSecurity:
    """Test token security measures."""

    @pytest.mark.security
    def test_jwt_token_tampering(self):
        """Test that tampered tokens are rejected."""
        # Create valid token
        token = jwt_service.create_access_token(
            subject="user-123",
            scopes=["read:profile"],
            audience=["api-server"],
        )
        
        # Tamper with token by changing a character
        tampered_token = token[:-5] + "XXXXX"
        
        with pytest.raises(AuthenticationError):
            jwt_service.validate_token(tampered_token)

    @pytest.mark.security
    def test_jwt_token_signature_verification(self):
        """Test that tokens with wrong signature are rejected."""
        import jwt
        
        # Create token with different secret
        payload = {
            "sub": "user-123",
            "scopes": ["read:profile"],
            "aud": ["api-server"],
            "iss": "keystone-auth",
            "type": "access",
        }
        
        wrong_secret_token = jwt.encode(payload, "wrong-secret", algorithm="HS256")
        
        with pytest.raises(AuthenticationError):
            jwt_service.validate_token(wrong_secret_token)

    @pytest.mark.security
    def test_jwt_token_algorithm_confusion(self):
        """Test protection against algorithm confusion attacks."""
        import jwt
        
        # Try to create token with 'none' algorithm
        payload = {
            "sub": "user-123",
            "scopes": ["admin:all"],
            "aud": ["api-server"],
            "iss": "keystone-auth",
            "type": "access",
        }
        
        none_token = jwt.encode(payload, "", algorithm="none")
        
        with pytest.raises(AuthenticationError):
            jwt_service.validate_token(none_token)

    @pytest.mark.security
    def test_jwt_token_replay_protection(self):
        """Test that JTI provides replay protection."""
        token1 = jwt_service.create_access_token(
            subject="user-123",
            scopes=["read:profile"],
            audience=["api-server"],
        )
        
        token2 = jwt_service.create_access_token(
            subject="user-123",
            scopes=["read:profile"],
            audience=["api-server"],
        )
        
        payload1 = jwt_service.decode_token(token1, verify_signature=False)
        payload2 = jwt_service.decode_token(token2, verify_signature=False)
        
        # JTI should be different for each token
        assert payload1[JWTClaims.JWT_ID] != payload2[JWTClaims.JWT_ID]

    @pytest.mark.security
    def test_token_expiration_enforcement(self):
        """Test that expired tokens are properly rejected."""
        from datetime import timedelta
        
        # Create token that expires immediately
        expired_token = jwt_service.create_access_token(
            subject="user-123",
            scopes=["read:profile"],
            audience=["api-server"],
            expires_delta=timedelta(seconds=-1),  # Already expired
        )
        
        with pytest.raises(AuthenticationError) as exc_info:
            jwt_service.validate_token(expired_token)
        
        assert "expired" in str(exc_info.value).lower()

    @pytest.mark.security
    def test_audience_validation_enforcement(self):
        """Test that audience validation is enforced."""
        token = jwt_service.create_access_token(
            subject="user-123",
            scopes=["read:profile"],
            audience=["api-server"],
        )
        
        # Try to validate with wrong audience
        with pytest.raises(AuthenticationError) as exc_info:
            jwt_service.validate_token(token, expected_audience="wrong-audience")
        
        assert "Invalid audience" in str(exc_info.value)

    @pytest.mark.security
    def test_scope_privilege_escalation_prevention(self):
        """Test that scope privilege escalation is prevented."""
        token = jwt_service.create_access_token(
            subject="user-123",
            scopes=["read:profile"],  # Only read access
            audience=["api-server"],
        )
        
        # Try to require admin scope
        with pytest.raises(AuthorizationError) as exc_info:
            jwt_service.validate_token(token, required_scopes=["admin:users"])
        
        assert "Insufficient permissions" in str(exc_info.value)


class TestPasswordSecurity:
    """Test password security measures."""

    @pytest.mark.security
    def test_password_timing_attack_resistance(self):
        """Test that password verification is resistant to timing attacks."""
        from app.core.password import verify_password
        import time
        
        correct_password = "CorrectPassword123!"
        wrong_password = "WrongPassword123!"
        password_hash = "fake_hash_for_timing_test"
        
        # Measure time for correct password (should fail due to fake hash)
        start_time = time.time()
        verify_password(correct_password, password_hash)
        correct_time = time.time() - start_time
        
        # Measure time for wrong password
        start_time = time.time()
        verify_password(wrong_password, password_hash)
        wrong_time = time.time() - start_time
        
        # Times should be similar (within reasonable bounds)
        # This is a basic test - in practice, timing attacks are more sophisticated
        time_diff = abs(correct_time - wrong_time)
        assert time_diff < 0.1  # Should complete within similar timeframes

    @pytest.mark.security
    def test_password_hash_uniqueness(self):
        """Test that password hashes are unique even for same password."""
        from app.core.password import hash_password
        
        password = "SamePassword123!"
        
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        # Hashes should be different due to salt
        assert hash1 != hash2

    @pytest.mark.security
    def test_password_policy_bypass_prevention(self):
        """Test that password policy cannot be bypassed."""
        from app.core.password import validate_password
        
        # Try various ways to bypass password policy
        bypass_attempts = [
            "",  # Empty password
            None,  # None password
            "short",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoDigitsHere!",  # No digits
            "NoSpecialChars123",  # No special chars
        ]
        
        for password in bypass_attempts:
            errors = validate_password(password)
            assert len(errors) > 0, f"Password '{password}' should have failed validation"


class TestSessionSecurity:
    """Test session security measures."""

    @pytest.mark.security
    async def test_concurrent_session_handling(self, test_user: User, db_session):
        """Test handling of concurrent sessions."""
        # Create multiple refresh tokens for same user
        from app.models.refresh_token import RefreshToken
        
        token1 = RefreshToken.create_for_user(user=test_user, client_id="client1")
        token2 = RefreshToken.create_for_user(user=test_user, client_id="client2")
        token3 = RefreshToken.create_for_user(user=test_user, client_id="client3")
        
        db_session.add_all([token1, token2, token3])
        await db_session.commit()
        
        # All tokens should have unique JTIs
        jtis = [token1.jti, token2.jti, token3.jti]
        assert len(set(jtis)) == 3  # All unique

    @pytest.mark.security
    async def test_session_fixation_prevention(self):
        """Test that session fixation is prevented."""
        # Create initial token
        token1 = jwt_service.create_refresh_token(
            subject="user-123",
            username="testuser",
        )
        
        # Refresh the token (should create new token)
        tokens = jwt_service.refresh_access_token(
            refresh_token=token1,
            new_scopes=["read:profile"],
            new_audience=["api-server"],
        )
        
        # New refresh token should be different
        assert tokens["refresh_token"] != token1
        
        # JTIs should be different
        payload1 = jwt_service.decode_token(token1, verify_signature=False)
        payload2 = jwt_service.decode_token(tokens["refresh_token"], verify_signature=False)
        
        assert payload1[JWTClaims.JWT_ID] != payload2[JWTClaims.JWT_ID]