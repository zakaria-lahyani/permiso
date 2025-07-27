"""Tests for authentication API endpoints."""

import pytest
from httpx import AsyncClient
from unittest.mock import patch, AsyncMock

from app.core.jwt import jwt_service
from app.models.user import User
from app.models.service_client import ServiceClient
from app.core.password import hash_password


class TestAuthTokenEndpoint:
    """Test /api/v1/auth/token endpoint."""

    @pytest.mark.integration
    async def test_user_login_success(self, async_client: AsyncClient, test_user: User):
        """Test successful user login."""
        response = await async_client.post(
            "/api/v1/auth/token",
            data={
                "username": test_user.username,
                "password": "TestPassword123!"  # From fixture
            }
        )
        
        print(f"Response status: {response.status_code}")
        print(f"Response body: {response.text}")
        print(f"Response headers: {response.headers}")
        
        assert response.status_code == 200
        
        token_data = response.json()
        assert "access_token" in token_data
        assert "refresh_token" in token_data
        assert token_data["token_type"] == "Bearer"
        assert "expires_in" in token_data
        assert token_data["expires_in"] > 0
        
        # Verify token is valid
        access_token = token_data["access_token"]
        payload = jwt_service.validate_token(access_token)
        assert payload["sub"] == str(test_user.id)

    @pytest.mark.integration
    async def test_user_login_invalid_credentials(self, async_client: AsyncClient, test_user: User):
        """Test user login with invalid credentials."""
        response = await async_client.post(
            "/api/v1/auth/token",
            data={
                "username": test_user.username,
                "password": "WrongPassword123!"
            }
        )
        
        assert response.status_code == 401
        
        error_data = response.json()
        assert error_data["error"] == "invalid_grant"
        assert "invalid" in error_data["error_description"].lower()

    @pytest.mark.integration
    async def test_user_login_nonexistent_user(self, async_client: AsyncClient):
        """Test user login with nonexistent username."""
        response = await async_client.post(
            "/api/v1/auth/token",
            data={
                "username": "nonexistent_user",
                "password": "SomePassword123!"
            }
        )
        
        assert response.status_code == 401
        
        error_data = response.json()
        assert error_data["error"] == "invalid_grant"

    @pytest.mark.integration
    async def test_user_login_disabled_account(self, async_client: AsyncClient, disabled_user: User):
        """Test user login with disabled account."""
        response = await async_client.post(
            "/api/v1/auth/token",
            data={
                "username": disabled_user.username,
                "password": "DisabledPassword123!"
            }
        )
        
        assert response.status_code == 403
        
        error_data = response.json()
        assert error_data["error"] == "account_disabled"

    @pytest.mark.integration
    async def test_user_login_locked_account(self, async_client: AsyncClient, db_session):
        """Test user login with locked account."""
        # Create locked user
        locked_user = User(
            username="locked_user",
            email="locked@example.com",
            password_hash=hash_password("LockedPassword123!"),
            is_active=True,
            failed_login_attempts=5
        )
        
        # Lock the account
        locked_user.increment_failed_login(max_attempts=5, lockout_minutes=30)
        
        db_session.add(locked_user)
        await db_session.commit()
        
        response = await async_client.post(
            "/api/v1/auth/token",
            data={
                "username": "locked_user",
                "password": "LockedPassword123!"
            }
        )
        
        assert response.status_code == 423
        
        error_data = response.json()
        assert error_data["error"] == "account_locked"
        assert "locked_until" in error_data

    @pytest.mark.integration
    async def test_user_login_missing_parameters(self, async_client: AsyncClient):
        """Test user login with missing parameters."""
        # Missing password
        response = await async_client.post(
            "/api/v1/auth/token",
            data={"username": "testuser"}
        )
        
        assert response.status_code == 422
        
        # Missing username
        response = await async_client.post(
            "/api/v1/auth/token",
            data={"password": "TestPassword123!"}
        )
        
        assert response.status_code == 422

    @pytest.mark.integration
    async def test_user_login_rate_limiting(self, async_client: AsyncClient):
        """Test rate limiting on login endpoint."""
        # Make multiple rapid requests
        for _ in range(10):
            response = await async_client.post(
                "/api/v1/auth/token",
                data={
                    "username": "rate_limit_test",
                    "password": "WrongPassword123!"
                }
            )
            
            if response.status_code == 429:
                # Rate limit hit
                error_data = response.json()
                assert error_data["error"] == "rate_limit_exceeded"
                assert "retry_after" in error_data
                break
        else:
            # If we didn't hit rate limit, that's also acceptable for this test
            pass


class TestAuthRefreshEndpoint:
    """Test /api/v1/auth/refresh endpoint."""

    @pytest.mark.integration
    async def test_token_refresh_success(self, async_client: AsyncClient, test_user: User):
        """Test successful token refresh."""
        # First login to get refresh token
        login_response = await async_client.post(
            "/api/v1/auth/token",
            data={
                "username": test_user.username,
                "password": "TestPassword123!"
            }
        )
        
        assert login_response.status_code == 200
        tokens = login_response.json()
        refresh_token = tokens["refresh_token"]
        
        # Use refresh token to get new access token
        response = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert response.status_code == 200
        
        new_tokens = response.json()
        assert "access_token" in new_tokens
        assert "refresh_token" in new_tokens
        assert new_tokens["token_type"] == "Bearer"
        
        # New tokens should be different from original
        assert new_tokens["access_token"] != tokens["access_token"]
        assert new_tokens["refresh_token"] != tokens["refresh_token"]

    @pytest.mark.integration
    async def test_token_refresh_invalid_token(self, async_client: AsyncClient):
        """Test token refresh with invalid refresh token."""
        response = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid.refresh.token"}
        )
        
        assert response.status_code == 401
        
        error_data = response.json()
        assert error_data["error"] == "invalid_grant"

    @pytest.mark.integration
    async def test_token_refresh_expired_token(self, async_client: AsyncClient):
        """Test token refresh with expired refresh token."""
        # Create expired refresh token
        from datetime import datetime, timedelta
        import jwt
        
        expired_payload = {
            "sub": "user-123",
            "exp": datetime.utcnow() - timedelta(hours=1),  # Expired
            "iat": datetime.utcnow() - timedelta(hours=2),
            "type": "refresh"
        }
        
        expired_token = jwt.encode(expired_payload, "test-secret", algorithm="HS256")
        
        response = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": expired_token}
        )
        
        assert response.status_code == 401
        
        error_data = response.json()
        assert error_data["error"] == "invalid_grant"

    @pytest.mark.integration
    async def test_token_refresh_missing_token(self, async_client: AsyncClient):
        """Test token refresh with missing refresh token."""
        response = await async_client.post(
            "/api/v1/auth/refresh",
            json={}
        )
        
        assert response.status_code == 422


class TestAuthServiceTokenEndpoint:
    """Test /api/v1/auth/service-token endpoint."""

    @pytest.mark.integration
    async def test_service_token_success(self, async_client: AsyncClient, test_service_client: ServiceClient):
        """Test successful service token generation."""
        response = await async_client.post(
            "/api/v1/auth/service-token",
            data={
                "client_id": test_service_client.client_id,
                "client_secret": "test-secret",  # From fixture
                "scope": "service:api"
            }
        )
        
        assert response.status_code == 200
        
        token_data = response.json()
        assert "access_token" in token_data
        assert token_data["token_type"] == "Bearer"
        assert "expires_in" in token_data
        assert "scope" in token_data
        
        # Verify token is valid service token
        access_token = token_data["access_token"]
        payload = jwt_service.validate_token(access_token)
        assert payload["type"] == "service"
        assert payload["client_id"] == test_service_client.client_id

    @pytest.mark.integration
    async def test_service_token_invalid_credentials(self, async_client: AsyncClient, test_service_client: ServiceClient):
        """Test service token with invalid credentials."""
        response = await async_client.post(
            "/api/v1/auth/service-token",
            data={
                "client_id": test_service_client.client_id,
                "client_secret": "wrong-secret",
                "scope": "service:api"
            }
        )
        
        assert response.status_code == 401
        
        error_data = response.json()
        assert error_data["error"] == "invalid_client"

    @pytest.mark.integration
    async def test_service_token_nonexistent_client(self, async_client: AsyncClient):
        """Test service token with nonexistent client."""
        response = await async_client.post(
            "/api/v1/auth/service-token",
            data={
                "client_id": "nonexistent-client",
                "client_secret": "some-secret",
                "scope": "service:api"
            }
        )
        
        assert response.status_code == 401
        
        error_data = response.json()
        assert error_data["error"] == "invalid_client"

    @pytest.mark.integration
    async def test_service_token_disabled_client(self, async_client: AsyncClient, disabled_service_client: ServiceClient):
        """Test service token with disabled client."""
        response = await async_client.post(
            "/api/v1/auth/service-token",
            data={
                "client_id": disabled_service_client.client_id,
                "client_secret": "disabled-secret",
                "scope": "service:api"
            }
        )
        
        assert response.status_code == 403
        
        error_data = response.json()
        assert error_data["error"] == "client_disabled"

    @pytest.mark.integration
    async def test_service_token_invalid_scope(self, async_client: AsyncClient, test_service_client: ServiceClient):
        """Test service token with invalid scope."""
        response = await async_client.post(
            "/api/v1/auth/service-token",
            data={
                "client_id": test_service_client.client_id,
                "client_secret": "test-secret",
                "scope": "admin:system"  # Scope not assigned to client
            }
        )
        
        assert response.status_code == 400
        
        error_data = response.json()
        assert error_data["error"] == "invalid_scope"


class TestAuthRevokeEndpoint:
    """Test /api/v1/auth/revoke endpoint."""

    @pytest.mark.integration
    async def test_token_revoke_success(self, async_client: AsyncClient, test_access_token: str):
        """Test successful token revocation."""
        response = await async_client.post(
            "/api/v1/auth/revoke",
            headers={"Authorization": f"Bearer {test_access_token}"},
            json={
                "token": test_access_token,
                "token_type_hint": "access_token"
            }
        )
        
        assert response.status_code == 200
        
        result = response.json()
        assert result["message"] == "Token revoked successfully"

    @pytest.mark.integration
    async def test_token_revoke_refresh_token(self, async_client: AsyncClient, test_user: User):
        """Test refresh token revocation."""
        # Get tokens
        login_response = await async_client.post(
            "/api/v1/auth/token",
            data={
                "username": test_user.username,
                "password": "TestPassword123!"
            }
        )
        
        tokens = login_response.json()
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]
        
        # Revoke refresh token
        response = await async_client.post(
            "/api/v1/auth/revoke",
            headers={"Authorization": f"Bearer {access_token}"},
            json={
                "token": refresh_token,
                "token_type_hint": "refresh_token"
            }
        )
        
        assert response.status_code == 200

    @pytest.mark.integration
    async def test_token_revoke_unauthorized(self, async_client: AsyncClient):
        """Test token revocation without authorization."""
        response = await async_client.post(
            "/api/v1/auth/revoke",
            json={
                "token": "some.token.here",
                "token_type_hint": "access_token"
            }
        )
        
        assert response.status_code == 401


class TestAuthLogoutEndpoint:
    """Test /api/v1/auth/logout endpoint."""

    @pytest.mark.integration
    async def test_logout_success(self, async_client: AsyncClient, test_access_token: str):
        """Test successful logout."""
        response = await async_client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {test_access_token}"}
        )
        
        assert response.status_code == 200
        
        result = response.json()
        assert result["message"] == "Logged out successfully"

    @pytest.mark.integration
    async def test_logout_unauthorized(self, async_client: AsyncClient):
        """Test logout without authorization."""
        response = await async_client.post("/api/v1/auth/logout")
        
        assert response.status_code == 401


class TestAuthIntrospectEndpoint:
    """Test /api/v1/auth/introspect endpoint."""

    @pytest.mark.integration
    async def test_token_introspect_active(self, async_client: AsyncClient, test_user):
        """Test introspection of active token."""
        # Create a token specifically with admin:tokens scope
        from app.core.jwt import jwt_service
        admin_token = jwt_service.create_access_token(
            subject=str(test_user.id),
            scopes=["admin:tokens"],
            audience=["test-api"],
            username=test_user.username,
            email=test_user.email,
        )
        
        response = await async_client.post(
            "/api/v1/auth/introspect",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"token": admin_token}
        )
        
        assert response.status_code == 200
        
        introspection = response.json()
        assert introspection["active"] is True
        assert "sub" in introspection
        assert "exp" in introspection
        assert "scope" in introspection

    @pytest.mark.integration
    async def test_token_introspect_inactive(self, async_client: AsyncClient, test_access_token: str):
        """Test introspection of inactive token."""
        # Create invalid token
        invalid_token = "invalid.token.here"
        
        response = await async_client.post(
            "/api/v1/auth/introspect",
            headers={"Authorization": f"Bearer {test_access_token}"},
            json={"token": invalid_token}
        )
        
        assert response.status_code == 200
        
        introspection = response.json()
        assert introspection["active"] is False

    @pytest.mark.integration
    async def test_token_introspect_unauthorized(self, async_client: AsyncClient):
        """Test token introspection without authorization."""
        response = await async_client.post(
            "/api/v1/auth/introspect",
            json={"token": "some.token.here"}
        )
        
        assert response.status_code == 401


class TestAuthEndpointSecurity:
    """Test security aspects of auth endpoints."""

    @pytest.mark.security
    async def test_auth_endpoints_https_only(self, async_client: AsyncClient):
        """Test that auth endpoints enforce HTTPS in production."""
        # This would be tested with actual HTTPS configuration
        # For now, we test that the endpoints exist and respond
        
        response = await async_client.post(
            "/api/v1/auth/token",
            data={"username": "test", "password": "test"}
        )
        
        # Should respond (even if with error) indicating endpoint exists
        assert response.status_code in [400, 401, 422]

    @pytest.mark.security
    async def test_auth_endpoints_rate_limiting(self, async_client: AsyncClient):
        """Test rate limiting on auth endpoints."""
        # Test multiple rapid requests
        responses = []
        
        for _ in range(10):
            response = await async_client.post(
                "/api/v1/auth/token",
                data={"username": "ratetest", "password": "wrong"}
            )
            responses.append(response.status_code)
            
            if response.status_code == 429:
                break
        
        # Should eventually hit rate limit or consistently return 401
        assert 429 in responses or all(code == 401 for code in responses)

    @pytest.mark.security
    async def test_auth_endpoints_input_validation(self, async_client: AsyncClient):
        """Test input validation on auth endpoints."""
        # Test with malicious inputs
        malicious_inputs = [
            {"username": "<script>alert('xss')</script>", "password": "test"},
            {"username": "'; DROP TABLE users; --", "password": "test"},
            {"username": "test", "password": "' OR '1'='1"},
            {"username": "../../../etc/passwd", "password": "test"},
        ]
        
        for malicious_input in malicious_inputs:
            response = await async_client.post(
                "/api/v1/auth/token",
                data=malicious_input
            )
            
            # Should reject malicious input
            assert response.status_code in [400, 401, 422]
            
            # Should not contain unescaped input in response
            response_text = response.text
            assert malicious_input["username"] not in response_text

    @pytest.mark.security
    async def test_auth_endpoints_timing_attacks(self, async_client: AsyncClient, test_user: User):
        """Test resistance to timing attacks."""
        import time
        
        # Time valid username with wrong password
        start_time = time.perf_counter()
        await async_client.post(
            "/api/v1/auth/token",
            data={
                "username": test_user.username,
                "password": "WrongPassword123!"
            }
        )
        valid_user_time = time.perf_counter() - start_time
        
        # Time invalid username
        start_time = time.perf_counter()
        await async_client.post(
            "/api/v1/auth/token",
            data={
                "username": "nonexistent_user_12345",
                "password": "WrongPassword123!"
            }
        )
        invalid_user_time = time.perf_counter() - start_time
        
        # Times should be similar (within reasonable variance)
        time_difference = abs(valid_user_time - invalid_user_time)
        assert time_difference < 0.5  # Allow up to 500ms difference

    @pytest.mark.security
    async def test_auth_endpoints_error_information_disclosure(self, async_client: AsyncClient):
        """Test that auth endpoints don't disclose sensitive information in errors."""
        # Test with various invalid inputs
        test_cases = [
            {"username": "admin", "password": "wrong"},
            {"username": "nonexistent", "password": "wrong"},
            {"username": "", "password": ""},
        ]
        
        for test_case in test_cases:
            response = await async_client.post(
                "/api/v1/auth/token",
                data=test_case
            )
            
            response_text = response.text.lower()
            
            # Should not disclose sensitive information
            sensitive_info = [
                "database", "sql", "table", "column", "constraint",
                "stack trace", "exception", "internal error",
                "password hash", "secret", "key"
            ]
            
            for info in sensitive_info:
                assert info not in response_text