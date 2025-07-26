"""Unit tests for JWT token functionality."""

import pytest
import jwt
from datetime import datetime, timedelta
from unittest.mock import patch

from app.core.jwt import (
    JWTService,
    JWTClaims,
    TokenType,
    jwt_service,
)
from app.core.exceptions import AuthenticationError, AuthorizationError


class TestJWTService:
    """Test JWT service functionality."""

    @pytest.fixture
    def jwt_svc(self):
        """Create JWT service instance for testing."""
        return JWTService()

    @pytest.mark.unit
    def test_create_access_token(self, jwt_svc):
        """Test access token creation."""
        subject = "user-123"
        scopes = ["read:profile", "write:profile"]
        audience = ["api-server"]
        
        token = jwt_svc.create_access_token(
            subject=subject,
            scopes=scopes,
            audience=audience,
        )
        
        assert isinstance(token, str)
        assert len(token) > 100  # JWT tokens are long
        
        # Decode without verification to check structure
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload[JWTClaims.SUBJECT] == subject
        assert payload[JWTClaims.SCOPES] == scopes
        assert payload[JWTClaims.AUDIENCE] == audience
        assert payload[JWTClaims.TOKEN_TYPE] == TokenType.ACCESS

    @pytest.mark.unit
    def test_create_access_token_with_optional_claims(self, jwt_svc):
        """Test access token creation with optional claims."""
        subject = "user-123"
        scopes = ["read:profile"]
        audience = ["api-server"]
        roles = ["user", "admin"]
        username = "testuser"
        email = "test@example.com"
        client_id = "web-client"
        
        token = jwt_svc.create_access_token(
            subject=subject,
            scopes=scopes,
            audience=audience,
            roles=roles,
            username=username,
            email=email,
            client_id=client_id,
        )
        
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload[JWTClaims.ROLES] == roles
        assert payload[JWTClaims.USERNAME] == username
        assert payload[JWTClaims.EMAIL] == email
        assert payload[JWTClaims.CLIENT_ID] == client_id

    @pytest.mark.unit
    def test_create_refresh_token(self, jwt_svc):
        """Test refresh token creation."""
        subject = "user-123"
        client_id = "web-client"
        username = "testuser"
        
        token = jwt_svc.create_refresh_token(
            subject=subject,
            client_id=client_id,
            username=username,
        )
        
        assert isinstance(token, str)
        
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload[JWTClaims.SUBJECT] == subject
        assert payload[JWTClaims.CLIENT_ID] == client_id
        assert payload[JWTClaims.USERNAME] == username
        assert payload[JWTClaims.TOKEN_TYPE] == TokenType.REFRESH
        assert payload[JWTClaims.AUDIENCE] == [jwt_svc.issuer]

    @pytest.mark.unit
    def test_create_service_token(self, jwt_svc):
        """Test service token creation."""
        client_id = "service-client"
        scopes = ["service:api"]
        audience = ["internal-api"]
        
        token = jwt_svc.create_service_token(
            client_id=client_id,
            scopes=scopes,
            audience=audience,
        )
        
        assert isinstance(token, str)
        
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload[JWTClaims.SUBJECT] == client_id
        assert payload[JWTClaims.CLIENT_ID] == client_id
        assert payload[JWTClaims.SCOPES] == scopes
        assert payload[JWTClaims.AUDIENCE] == audience
        assert payload[JWTClaims.TOKEN_TYPE] == TokenType.SERVICE

    @pytest.mark.unit
    def test_decode_token_valid(self, jwt_svc):
        """Test decoding valid token."""
        subject = "user-123"
        scopes = ["read:profile"]
        audience = ["api-server"]
        
        token = jwt_svc.create_access_token(
            subject=subject,
            scopes=scopes,
            audience=audience,
        )
        
        payload = jwt_svc.decode_token(token)
        
        assert payload[JWTClaims.SUBJECT] == subject
        assert payload[JWTClaims.SCOPES] == scopes
        assert payload[JWTClaims.AUDIENCE] == audience

    @pytest.mark.unit
    def test_decode_token_invalid(self, jwt_svc):
        """Test decoding invalid token."""
        invalid_token = "invalid.token.here"
        
        with pytest.raises(AuthenticationError) as exc_info:
            jwt_svc.decode_token(invalid_token)
        
        assert "Invalid token" in str(exc_info.value)

    @pytest.mark.unit
    def test_decode_token_expired(self, jwt_svc):
        """Test decoding expired token."""
        # Create expired token
        expired_payload = {
            JWTClaims.SUBJECT: "user-123",
            JWTClaims.EXPIRATION: datetime.utcnow() - timedelta(hours=1),
            JWTClaims.ISSUED_AT: datetime.utcnow() - timedelta(hours=2),
        }
        
        expired_token = jwt.encode(
            expired_payload,
            jwt_svc.secret_key,
            algorithm=jwt_svc.algorithm
        )
        
        with pytest.raises(AuthenticationError) as exc_info:
            jwt_svc.decode_token(expired_token)
        
        assert "expired" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_validate_token_valid(self, jwt_svc):
        """Test validating valid token."""
        subject = "user-123"
        scopes = ["read:profile"]
        audience = ["api-server"]
        
        token = jwt_svc.create_access_token(
            subject=subject,
            scopes=scopes,
            audience=audience,
        )
        
        payload = jwt_svc.validate_token(token)
        
        assert payload[JWTClaims.SUBJECT] == subject
        assert payload[JWTClaims.SCOPES] == scopes

    @pytest.mark.unit
    def test_validate_token_wrong_type(self, jwt_svc):
        """Test validating token with wrong type."""
        token = jwt_svc.create_access_token(
            subject="user-123",
            scopes=["read:profile"],
            audience=["api-server"],
        )
        
        with pytest.raises(AuthenticationError) as exc_info:
            jwt_svc.validate_token(token, expected_type=TokenType.REFRESH)
        
        assert "Invalid token type" in str(exc_info.value)

    @pytest.mark.unit
    def test_validate_token_wrong_audience(self, jwt_svc):
        """Test validating token with wrong audience."""
        token = jwt_svc.create_access_token(
            subject="user-123",
            scopes=["read:profile"],
            audience=["api-server"],
        )
        
        with pytest.raises(AuthenticationError) as exc_info:
            jwt_svc.validate_token(token, expected_audience="wrong-audience")
        
        assert "Invalid audience" in str(exc_info.value)

    @pytest.mark.unit
    def test_validate_token_insufficient_scopes(self, jwt_svc):
        """Test validating token with insufficient scopes."""
        token = jwt_svc.create_access_token(
            subject="user-123",
            scopes=["read:profile"],
            audience=["api-server"],
        )
        
        with pytest.raises(AuthorizationError) as exc_info:
            jwt_svc.validate_token(token, required_scopes=["write:profile"])
        
        assert "Insufficient permissions" in str(exc_info.value)

    @pytest.mark.unit
    def test_extract_token_info(self, jwt_svc):
        """Test extracting token information."""
        subject = "user-123"
        scopes = ["read:profile"]
        audience = ["api-server"]
        username = "testuser"
        
        token = jwt_svc.create_access_token(
            subject=subject,
            scopes=scopes,
            audience=audience,
            username=username,
        )
        
        payload = jwt_svc.decode_token(token, verify_signature=False)
        info = jwt_svc.extract_token_info(payload)
        
        assert info["subject"] == subject
        assert info["scopes"] == scopes
        assert info["audience"] == audience
        assert info["username"] == username
        assert info["token_type"] == TokenType.ACCESS
        assert "jti" in info
        assert "issued_at" in info
        assert "expires_at" in info

    @pytest.mark.unit
    def test_is_token_expired(self, jwt_svc):
        """Test token expiration check."""
        # Valid token
        valid_payload = {
            JWTClaims.EXPIRATION: datetime.utcnow() + timedelta(hours=1)
        }
        assert jwt_svc.is_token_expired(valid_payload) is False
        
        # Expired token
        expired_payload = {
            JWTClaims.EXPIRATION: datetime.utcnow() - timedelta(hours=1)
        }
        assert jwt_svc.is_token_expired(expired_payload) is True
        
        # Token without expiration
        no_exp_payload = {}
        assert jwt_svc.is_token_expired(no_exp_payload) is True

    @pytest.mark.unit
    def test_get_token_remaining_time(self, jwt_svc):
        """Test getting token remaining time."""
        # Token with 1 hour remaining
        future_exp = datetime.utcnow() + timedelta(hours=1)
        payload = {JWTClaims.EXPIRATION: future_exp}
        
        remaining = jwt_svc.get_token_remaining_time(payload)
        assert remaining is not None
        assert remaining.total_seconds() > 3500  # Close to 1 hour
        
        # Expired token
        past_exp = datetime.utcnow() - timedelta(hours=1)
        expired_payload = {JWTClaims.EXPIRATION: past_exp}
        
        remaining = jwt_svc.get_token_remaining_time(expired_payload)
        assert remaining.total_seconds() == 0
        
        # Token without expiration
        no_exp_payload = {}
        remaining = jwt_svc.get_token_remaining_time(no_exp_payload)
        assert remaining is None

    @pytest.mark.unit
    def test_refresh_access_token(self, jwt_svc):
        """Test refreshing access token."""
        subject = "user-123"
        username = "testuser"
        
        refresh_token = jwt_svc.create_refresh_token(
            subject=subject,
            username=username,
        )
        
        new_scopes = ["read:profile", "write:profile"]
        new_audience = ["api-server"]
        
        tokens = jwt_svc.refresh_access_token(
            refresh_token=refresh_token,
            new_scopes=new_scopes,
            new_audience=new_audience,
        )
        
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        
        # Verify new access token
        access_payload = jwt_svc.decode_token(tokens["access_token"], verify_signature=False)
        assert access_payload[JWTClaims.SUBJECT] == subject
        assert access_payload[JWTClaims.SCOPES] == new_scopes
        assert access_payload[JWTClaims.AUDIENCE] == new_audience

    @pytest.mark.unit
    def test_refresh_access_token_invalid_refresh(self, jwt_svc):
        """Test refreshing with invalid refresh token."""
        invalid_refresh_token = "invalid.refresh.token"
        
        with pytest.raises(AuthenticationError):
            jwt_svc.refresh_access_token(
                refresh_token=invalid_refresh_token,
                new_scopes=["read:profile"],
                new_audience=["api-server"],
            )

    @pytest.mark.unit
    def test_create_token_response(self, jwt_svc):
        """Test creating OAuth2 token response."""
        access_token = "access.token.here"
        refresh_token = "refresh.token.here"
        expires_in = 3600
        scope = "read:profile write:profile"
        
        response = jwt_svc.create_token_response(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in,
            scope=scope,
        )
        
        assert response["access_token"] == access_token
        assert response["refresh_token"] == refresh_token
        assert response["token_type"] == "Bearer"
        assert response["expires_in"] == expires_in
        assert response["scope"] == scope

    @pytest.mark.unit
    def test_create_token_response_minimal(self, jwt_svc):
        """Test creating minimal token response."""
        access_token = "access.token.here"
        
        response = jwt_svc.create_token_response(access_token=access_token)
        
        assert response["access_token"] == access_token
        assert response["token_type"] == "Bearer"
        assert "expires_in" in response
        assert "refresh_token" not in response
        assert "scope" not in response

    @pytest.mark.unit
    def test_custom_expiration_times(self, jwt_svc):
        """Test tokens with custom expiration times."""
        subject = "user-123"
        scopes = ["read:profile"]
        audience = ["api-server"]
        
        # Custom access token expiration
        custom_expires = timedelta(minutes=30)
        token = jwt_svc.create_access_token(
            subject=subject,
            scopes=scopes,
            audience=audience,
            expires_delta=custom_expires,
        )
        
        payload = jwt_svc.decode_token(token, verify_signature=False)
        exp_time = datetime.fromtimestamp(payload[JWTClaims.EXPIRATION])
        iat_time = datetime.fromtimestamp(payload[JWTClaims.ISSUED_AT])
        
        # Should be approximately 30 minutes difference
        diff = exp_time - iat_time
        assert 29 * 60 <= diff.total_seconds() <= 31 * 60

    @pytest.mark.unit
    def test_additional_claims(self, jwt_svc):
        """Test tokens with additional custom claims."""
        subject = "user-123"
        scopes = ["read:profile"]
        audience = ["api-server"]
        additional_claims = {
            "custom_field": "custom_value",
            "tenant_id": "tenant-123",
        }
        
        token = jwt_svc.create_access_token(
            subject=subject,
            scopes=scopes,
            audience=audience,
            additional_claims=additional_claims,
        )
        
        payload = jwt_svc.decode_token(token, verify_signature=False)
        assert payload["custom_field"] == "custom_value"
        assert payload["tenant_id"] == "tenant-123"


class TestJWTClaims:
    """Test JWT claims constants."""

    @pytest.mark.unit
    def test_jwt_claims_constants(self):
        """Test JWT claims constants are defined."""
        assert JWTClaims.ISSUER == "iss"
        assert JWTClaims.AUDIENCE == "aud"
        assert JWTClaims.SUBJECT == "sub"
        assert JWTClaims.EXPIRATION == "exp"
        assert JWTClaims.ISSUED_AT == "iat"
        assert JWTClaims.NOT_BEFORE == "nbf"
        assert JWTClaims.JWT_ID == "jti"
        assert JWTClaims.TOKEN_TYPE == "type"
        assert JWTClaims.ROLES == "roles"
        assert JWTClaims.SCOPES == "scopes"
        assert JWTClaims.CLIENT_ID == "client_id"
        assert JWTClaims.USERNAME == "username"
        assert JWTClaims.EMAIL == "email"


class TestTokenType:
    """Test token type constants."""

    @pytest.mark.unit
    def test_token_type_constants(self):
        """Test token type constants are defined."""
        assert TokenType.ACCESS == "access"
        assert TokenType.REFRESH == "refresh"
        assert TokenType.SERVICE == "service"


class TestGlobalJWTService:
    """Test global JWT service instance."""

    @pytest.mark.unit
    def test_global_jwt_service_exists(self):
        """Test that global JWT service instance exists."""
        assert jwt_service is not None
        assert isinstance(jwt_service, JWTService)

    @pytest.mark.unit
    def test_global_jwt_service_methods(self):
        """Test global JWT service methods work."""
        subject = "test-user"
        scopes = ["test:scope"]
        audience = ["test-api"]
        
        # Test access token creation
        token = jwt_service.create_access_token(
            subject=subject,
            scopes=scopes,
            audience=audience,
        )
        
        assert isinstance(token, str)
        
        # Test token validation
        payload = jwt_service.validate_token(token)
        assert payload[JWTClaims.SUBJECT] == subject