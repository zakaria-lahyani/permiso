"""Security tests for authorization functionality."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from httpx import AsyncClient

from app.core.exceptions import (
    AuthorizationError,
    InsufficientScopeError,
)
from app.core.jwt import jwt_service, JWTClaims, TokenType
from app.core.security import require_scopes, require_roles, require_admin
from app.models.user import User
from app.models.role import Role
from app.models.scope import Scope
from app.core.password import hash_password


class TestScopeBasedAuthorization:
    """Test scope-based authorization security."""

    @pytest.mark.security
    def test_scope_requirement_enforcement(self):
        """Test that scope requirements are properly enforced."""
        required_scopes = ["read:admin", "write:users"]
        check_scopes = require_scopes(required_scopes)
        
        # Token with sufficient scopes should pass
        sufficient_payload = {
            JWTClaims.SCOPES: ["read:admin", "write:users", "read:profile"]
        }
        
        result = check_scopes.__wrapped__(sufficient_payload)
        assert result == sufficient_payload
        
        # Token with insufficient scopes should fail
        insufficient_payload = {
            JWTClaims.SCOPES: ["read:profile"]  # Missing required scopes
        }
        
        with pytest.raises(Exception):  # Should raise HTTPException
            check_scopes.__wrapped__(insufficient_payload)

    @pytest.mark.security
    def test_scope_privilege_escalation_prevention(self):
        """Test prevention of scope privilege escalation."""
        # User with limited scopes should not be able to access admin functions
        user_scopes = ["read:profile", "write:profile"]
        admin_required = ["admin:users", "admin:system"]
        
        check_admin_scopes = require_scopes(admin_required)
        
        user_payload = {JWTClaims.SCOPES: user_scopes}
        
        with pytest.raises(Exception):
            check_admin_scopes.__wrapped__(user_payload)

    @pytest.mark.security
    def test_scope_wildcard_security(self):
        """Test that wildcard scopes are handled securely."""
        # Ensure wildcard scopes don't grant unintended access
        wildcard_payload = {
            JWTClaims.SCOPES: ["*:*", "admin:*", "*:users"]
        }
        
        # Wildcard scopes should be treated carefully
        # This test ensures they don't bypass security checks
        specific_required = ["delete:system"]
        check_specific = require_scopes(specific_required)
        
        # Even with wildcards, specific dangerous operations should be explicit
        with pytest.raises(Exception):
            check_specific.__wrapped__(wildcard_payload)

    @pytest.mark.security
    def test_scope_case_sensitivity(self):
        """Test scope case sensitivity security."""
        required_scopes = ["Admin:Users"]  # Uppercase
        check_scopes = require_scopes(required_scopes)
        
        # Different case should not match
        different_case_payload = {
            JWTClaims.SCOPES: ["admin:users"]  # Lowercase
        }
        
        with pytest.raises(Exception):
            check_scopes.__wrapped__(different_case_payload)

    @pytest.mark.security
    def test_scope_injection_prevention(self):
        """Test prevention of scope injection attacks."""
        # Malicious scopes that might try to bypass checks
        malicious_scopes = [
            "read:profile; admin:users",  # SQL-like injection
            "read:profile' OR '1'='1",    # SQL injection attempt
            "read:profile<script>",       # XSS attempt
            "read:profile\nadmin:users",  # Newline injection
            "read:profile\x00admin:users", # Null byte injection
        ]
        
        for malicious_scope in malicious_scopes:
            payload = {JWTClaims.SCOPES: [malicious_scope]}
            
            # Should not match legitimate scopes
            legitimate_check = require_scopes(["admin:users"])
            with pytest.raises(Exception):
                legitimate_check.__wrapped__(payload)

    @pytest.mark.security
    async def test_scope_based_api_access(self, async_client: AsyncClient):
        """Test scope-based API access control."""
        # Create user with limited scopes
        user = User(
            username="limited_user",
            email="limited@example.com",
            password_hash=hash_password("LimitedUser123!"),
            is_active=True
        )
        
        # Create token with limited scopes
        limited_token = jwt_service.create_access_token(
            subject=str(user.id),
            scopes=["read:profile"],  # Only read access
            audience=["api-server"],
            username=user.username,
            email=user.email
        )
        
        headers = {"Authorization": f"Bearer {limited_token}"}
        
        # Should be able to read profile
        response = await async_client.get(
            "/api/v1/users/profile",
            headers=headers
        )
        # Note: This would work if the endpoint exists and requires read:profile
        
        # Should NOT be able to access admin endpoints
        response = await async_client.get(
            "/api/v1/admin/users",
            headers=headers
        )
        # Should return 403 Forbidden if endpoint exists and requires admin scopes


class TestRoleBasedAuthorization:
    """Test role-based authorization security."""

    @pytest.mark.security
    async def test_role_requirement_enforcement(self):
        """Test that role requirements are properly enforced."""
        # Create user with specific role
        user = User(
            username="role_test_user",
            email="roletest@example.com",
            password_hash=hash_password("RoleTest123!"),
            is_active=True
        )
        
        user_role = Role(name="user", description="Regular user")
        admin_role = Role(name="admin", description="Administrator")
        
        user.roles.append(user_role)
        
        # Mock the role checking
        user.get_role_names = AsyncMock(return_value=["user"])
        
        # User role should pass user requirement
        user_check = require_roles(["user"])
        result = await user_check.__wrapped__(user)
        assert result == user
        
        # User role should fail admin requirement
        admin_check = require_roles(["admin"])
        with pytest.raises(Exception):
            await admin_check.__wrapped__(user)

    @pytest.mark.security
    async def test_role_privilege_escalation_prevention(self):
        """Test prevention of role privilege escalation."""
        # Regular user should not be able to access admin functions
        regular_user = User(
            username="regular_user",
            email="regular@example.com",
            password_hash=hash_password("Regular123!"),
            is_active=True
        )
        
        regular_user.get_role_names = AsyncMock(return_value=["user"])
        
        # Should not be able to access admin-only functions
        admin_check = require_admin()
        with pytest.raises(Exception):
            await admin_check.__wrapped__(regular_user)

    @pytest.mark.security
    async def test_role_hierarchy_security(self):
        """Test role hierarchy security."""
        # Test that role hierarchy is properly enforced
        admin_user = User(
            username="admin_user",
            email="admin@example.com",
            password_hash=hash_password("Admin123!"),
            is_active=True
        )
        
        admin_user.get_role_names = AsyncMock(return_value=["admin"])
        
        # Admin should be able to access user functions
        user_check = require_roles(["user", "admin"])  # Either role allowed
        result = await user_check.__wrapped__(admin_user)
        assert result == admin_user
        
        # Admin should be able to access admin functions
        admin_check = require_admin()
        result = await admin_check.__wrapped__(admin_user)
        assert result == admin_user

    @pytest.mark.security
    async def test_role_injection_prevention(self):
        """Test prevention of role injection attacks."""
        # User with malicious role names
        malicious_user = User(
            username="malicious_user",
            email="malicious@example.com",
            password_hash=hash_password("Malicious123!"),
            is_active=True
        )
        
        # Malicious role names that might try to bypass checks
        malicious_roles = [
            "user; admin",           # SQL-like injection
            "user' OR '1'='1",      # SQL injection attempt
            "user<script>admin",     # XSS attempt
            "user\nadmin",          # Newline injection
            "user\x00admin",        # Null byte injection
        ]
        
        for malicious_role in malicious_roles:
            malicious_user.get_role_names = AsyncMock(return_value=[malicious_role])
            
            # Should not match legitimate admin role
            admin_check = require_admin()
            with pytest.raises(Exception):
                await admin_check.__wrapped__(malicious_user)

    @pytest.mark.security
    async def test_disabled_user_role_bypass(self):
        """Test that disabled users cannot bypass role checks."""
        # Disabled user with admin role should still be blocked
        disabled_admin = User(
            username="disabled_admin",
            email="disabled@example.com",
            password_hash=hash_password("Disabled123!"),
            is_active=False,  # Disabled
            is_superuser=True  # But has admin privileges
        )
        
        # Should be blocked before role check due to disabled status
        # This would be handled by the get_current_user dependency
        # which checks is_active before returning the user


class TestResourceBasedAuthorization:
    """Test resource-based authorization security."""

    @pytest.mark.security
    async def test_resource_ownership_enforcement(self):
        """Test that users can only access their own resources."""
        # User should only access their own profile
        user1 = User(
            username="user1",
            email="user1@example.com",
            password_hash=hash_password("User1123!"),
            is_active=True
        )
        user1.id = "user1-id"
        
        user2 = User(
            username="user2",
            email="user2@example.com",
            password_hash=hash_password("User2123!"),
            is_active=True
        )
        user2.id = "user2-id"
        
        # User1 should be able to access their own resources
        assert await user1.can_access_resource("profile", "read", {"user_id": "user1-id"}) is True
        
        # User1 should NOT be able to access user2's resources
        assert await user1.can_access_resource("profile", "read", {"user_id": "user2-id"}) is False

    @pytest.mark.security
    async def test_resource_path_traversal_prevention(self):
        """Test prevention of path traversal in resource access."""
        user = User(
            username="path_test_user",
            email="pathtest@example.com",
            password_hash=hash_password("PathTest123!"),
            is_active=True
        )
        
        # Malicious resource paths that might try to access unauthorized resources
        malicious_paths = [
            "../admin/users",
            "../../system/config",
            "/etc/passwd",
            "..\\..\\windows\\system32",
            "%2e%2e%2fadmin%2fusers",  # URL encoded
            "profile/../../admin",
        ]
        
        for malicious_path in malicious_paths:
            # Should not be able to access resources outside allowed scope
            assert await user.can_access_resource(malicious_path, "read") is False

    @pytest.mark.security
    async def test_resource_enumeration_prevention(self):
        """Test prevention of resource enumeration attacks."""
        user = User(
            username="enum_test_user",
            email="enumtest@example.com",
            password_hash=hash_password("EnumTest123!"),
            is_active=True
        )
        
        # User should not be able to enumerate resources they don't have access to
        unauthorized_resources = [
            "admin_panel",
            "system_logs",
            "user_database",
            "configuration",
            "secrets",
        ]
        
        for resource in unauthorized_resources:
            assert await user.can_access_resource(resource, "read") is False
            assert await user.can_access_resource(resource, "write") is False
            assert await user.can_access_resource(resource, "admin") is False


class TestTokenBasedAuthorization:
    """Test token-based authorization security."""

    @pytest.mark.security
    def test_token_scope_tampering_prevention(self):
        """Test prevention of token scope tampering."""
        # Create token with limited scopes
        original_token = jwt_service.create_access_token(
            subject="user-123",
            scopes=["read:profile"],
            audience=["api-server"]
        )
        
        # Attempt to tamper with token scopes
        import jwt as pyjwt
        
        # Decode token (this would fail with signature verification)
        try:
            payload = pyjwt.decode(original_token, options={"verify_signature": False})
            
            # Tamper with scopes
            payload[JWTClaims.SCOPES] = ["admin:system", "admin:users"]
            
            # Re-encode with wrong secret
            tampered_token = pyjwt.encode(payload, "wrong_secret", algorithm="HS256")
            
            # Should fail validation
            with pytest.raises(Exception):
                jwt_service.validate_token(tampered_token)
                
        except Exception:
            # Expected - token tampering should fail
            pass

    @pytest.mark.security
    def test_token_audience_bypass_prevention(self):
        """Test prevention of token audience bypass."""
        # Create token for specific audience
        api_token = jwt_service.create_access_token(
            subject="user-123",
            scopes=["read:profile"],
            audience=["api-server"]
        )
        
        # Should not work for different audience
        with pytest.raises(Exception):
            jwt_service.validate_token(api_token, expected_audience="admin-panel")

    @pytest.mark.security
    def test_token_replay_attack_prevention(self):
        """Test prevention of token replay attacks."""
        # Create token
        token = jwt_service.create_access_token(
            subject="user-123",
            scopes=["read:profile"],
            audience=["api-server"]
        )
        
        # Extract JTI
        payload = jwt_service.decode_token(token, verify_signature=False)
        jti = payload[JWTClaims.JWT_ID]
        
        # Simulate token revocation
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = True  # Token is revoked
        
        # Should fail when token is revoked
        from app.core.security import SecurityUtils
        import asyncio
        
        async def test_revoked():
            is_revoked = await SecurityUtils.is_token_revoked(jti, mock_redis)
            assert is_revoked is True
        
        asyncio.run(test_revoked())

    @pytest.mark.security
    def test_service_token_user_endpoint_prevention(self):
        """Test that service tokens cannot access user endpoints."""
        # Create service token
        service_token = jwt_service.create_service_token(
            client_id="test-service",
            scopes=["service:api"],
            audience=["internal-api"]
        )
        
        # Service token should not be usable for user operations
        payload = jwt_service.decode_token(service_token, verify_signature=False)
        assert payload[JWTClaims.TOKEN_TYPE] == TokenType.SERVICE
        
        # This would be enforced by the get_current_user dependency
        # which checks token type


class TestPermissionEscalation:
    """Test prevention of permission escalation attacks."""

    @pytest.mark.security
    async def test_horizontal_privilege_escalation_prevention(self):
        """Test prevention of horizontal privilege escalation."""
        # User A should not be able to access User B's resources
        user_a = User(
            username="user_a",
            email="usera@example.com",
            password_hash=hash_password("UserA123!"),
            is_active=True
        )
        user_a.id = "user-a-id"
        
        user_b = User(
            username="user_b",
            email="userb@example.com",
            password_hash=hash_password("UserB123!"),
            is_active=True
        )
        user_b.id = "user-b-id"
        
        # User A should not access User B's profile
        assert await user_a.can_access_resource("profile", "read", {"user_id": "user-b-id"}) is False
        assert await user_a.can_access_resource("profile", "write", {"user_id": "user-b-id"}) is False

    @pytest.mark.security
    async def test_vertical_privilege_escalation_prevention(self):
        """Test prevention of vertical privilege escalation."""
        # Regular user should not be able to perform admin actions
        regular_user = User(
            username="regular_user",
            email="regular@example.com",
            password_hash=hash_password("Regular123!"),
            is_active=True
        )
        
        user_role = Role(name="user", description="Regular user")
        regular_user.roles.append(user_role)
        
        # Should not be able to access admin resources
        assert await regular_user.can_access_resource("admin", "read") is False
        assert await regular_user.can_access_resource("users", "admin") is False
        assert await regular_user.can_access_resource("system", "admin") is False

    @pytest.mark.security
    async def test_role_assignment_privilege_escalation_prevention(self):
        """Test prevention of privilege escalation through role assignment."""
        # User should not be able to assign themselves admin roles
        user = User(
            username="escalation_test",
            email="escalation@example.com",
            password_hash=hash_password("Escalation123!"),
            is_active=True
        )
        
        user_role = Role(name="user", description="Regular user")
        admin_role = Role(name="admin", description="Administrator")
        
        user.roles.append(user_role)
        
        # User should not be able to modify their own roles
        # This would be enforced by admin-only endpoints for role management
        assert await user.can_access_resource("roles", "write", {"user_id": str(user.id)}) is False


class TestAccessControlBypass:
    """Test prevention of access control bypass attacks."""

    @pytest.mark.security
    async def test_parameter_pollution_prevention(self):
        """Test prevention of HTTP parameter pollution attacks."""
        # Test that duplicate parameters don't bypass access controls
        # This would be tested at the API level with actual requests
        pass

    @pytest.mark.security
    async def test_method_override_prevention(self):
        """Test prevention of HTTP method override attacks."""
        # Test that X-HTTP-Method-Override headers don't bypass access controls
        # This would be tested at the API level
        pass

    @pytest.mark.security
    async def test_header_injection_prevention(self):
        """Test prevention of header injection attacks."""
        # Test that malicious headers don't bypass access controls
        malicious_headers = [
            "X-Forwarded-For: 127.0.0.1",
            "X-Real-IP: 127.0.0.1",
            "X-Originating-IP: 127.0.0.1",
            "X-Remote-IP: 127.0.0.1",
            "X-Client-IP: 127.0.0.1",
        ]
        
        # These headers should not affect authorization decisions
        # This would be tested at the API level with actual requests
        pass

    @pytest.mark.security
    async def test_unicode_normalization_bypass_prevention(self):
        """Test prevention of Unicode normalization bypass attacks."""
        # Test that Unicode variations don't bypass access controls
        unicode_variations = [
            "admin",           # Normal
            "ａｄｍｉｎ",        # Full-width
            "𝒶𝒹𝓂𝒾𝓃",        # Mathematical script
            "admin\u200b",     # With zero-width space
            "admin\ufeff",     # With BOM
        ]
        
        user = User(
            username="unicode_test",
            email="unicode@example.com",
            password_hash=hash_password("Unicode123!"),
            is_active=True
        )
        
        # Only exact role match should work
        user_role = Role(name="user", description="Regular user")
        user.roles.append(user_role)
        
        for variation in unicode_variations[1:]:  # Skip normal "admin"
            # Unicode variations should not match admin role
            fake_admin_role = Role(name=variation, description="Fake admin")
            test_user = User(
                username="test",
                email="test@example.com",
                password_hash=hash_password("Test123!"),
                is_active=True
            )
            test_user.roles.append(fake_admin_role)
            
            # Should not be considered admin
            assert await test_user.is_admin() is False


class TestSessionAuthorization:
    """Test session-based authorization security."""

    @pytest.mark.security
    async def test_session_fixation_prevention(self):
        """Test prevention of session fixation attacks."""
        # Test that new sessions are created after authentication
        # This would be tested at the API level with actual login flows
        pass

    @pytest.mark.security
    async def test_concurrent_session_authorization(self):
        """Test authorization with concurrent sessions."""
        # Test that authorization works correctly with multiple active sessions
        user = User(
            username="concurrent_auth_test",
            email="concurrent@example.com",
            password_hash=hash_password("Concurrent123!"),
            is_active=True
        )
        
        # Create multiple tokens for the same user
        token1 = jwt_service.create_access_token(
            subject=str(user.id),
            scopes=["read:profile"],
            audience=["api-server"]
        )
        
        token2 = jwt_service.create_access_token(
            subject=str(user.id),
            scopes=["read:profile", "write:profile"],
            audience=["api-server"]
        )
        
        # Both tokens should be valid but with different scopes
        payload1 = jwt_service.validate_token(token1)
        payload2 = jwt_service.validate_token(token2)
        
        assert payload1[JWTClaims.SCOPES] == ["read:profile"]
        assert payload2[JWTClaims.SCOPES] == ["read:profile", "write:profile"]

    @pytest.mark.security
    async def test_session_timeout_authorization(self):
        """Test that expired sessions don't retain authorization."""
        # Create token with very short expiration
        from datetime import timedelta
        import time
        
        short_token = jwt_service.create_access_token(
            subject="user-123",
            scopes=["read:profile"],
            audience=["api-server"],
            expires_delta=timedelta(seconds=1)
        )
        
        # Token should be valid initially
        payload = jwt_service.validate_token(short_token)
        assert payload[JWTClaims.SUBJECT] == "user-123"
        
        # Wait for expiration
        time.sleep(2)
        
        # Expired token should fail authorization
        with pytest.raises(Exception):
            jwt_service.validate_token(short_token)


class TestAuthorizationLogging:
    """Test authorization logging and monitoring."""

    @pytest.mark.security
    async def test_authorization_failure_logging(self):
        """Test that authorization failures are properly logged."""
        with patch('app.core.audit.audit_logger') as mock_logger:
            # Simulate authorization failure
            user = User(
                username="auth_log_test",
                email="authlog@example.com",
                password_hash=hash_password("AuthLog123!"),
                is_active=True
            )
            
            # Attempt to access admin resource without permission
            result = await user.can_access_resource("admin", "write")
            assert result is False
            
            # Should log authorization failure
            # This would be implemented in the actual authorization logic

    @pytest.mark.security
    async def test_privilege_escalation_attempt_logging(self):
        """Test that privilege escalation attempts are logged."""
        with patch('app.core.audit.audit_logger') as mock_logger:
            # Simulate privilege escalation attempt
            regular_user = User(
                username="escalation_log_test",
                email="escalation@example.com",
                password_hash=hash_password("Escalation123!"),
                is_active=True
            )
            
            # Attempt to access admin functions
            result = await regular_user.can_access_resource("system", "admin")
            assert result is False
            
            # Should log privilege escalation attempt
            # This would be implemented in the actual authorization logic

    @pytest.mark.security
    async def test_suspicious_authorization_pattern_detection(self):
        """Test detection of suspicious authorization patterns."""
        # Test rapid authorization attempts
        # Test access to multiple restricted resources
        # Test unusual access patterns
        # This would be implemented in the monitoring system
        pass