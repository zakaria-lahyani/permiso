"""JWT token management and validation utilities."""

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

from app.config.settings import settings
from app.core.exceptions import AuthenticationError, AuthorizationError


class JWTClaims:
    """JWT claim constants."""
    
    ISSUER = "iss"
    AUDIENCE = "aud"
    SUBJECT = "sub"
    EXPIRATION = "exp"
    ISSUED_AT = "iat"
    NOT_BEFORE = "nbf"
    JWT_ID = "jti"
    TOKEN_TYPE = "type"
    ROLES = "roles"
    SCOPES = "scopes"
    CLIENT_ID = "client_id"
    USERNAME = "username"
    EMAIL = "email"
    IS_SUPERUSER = "is_superuser"
    IS_TRUSTED = "is_trusted"
    EXPIRES_AT = "exp"  # Alias for EXPIRATION


class TokenType:
    """Token type constants."""
    
    ACCESS = "access"
    REFRESH = "refresh"
    SERVICE = "service"


class JWTService:
    """JWT token creation, validation, and management service."""

    def __init__(self):
        self.secret_key = settings.JWT_SECRET_KEY
        self.algorithm = settings.JWT_ALGORITHM
        self.issuer = settings.JWT_ISSUER
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.REFRESH_TOKEN_EXPIRE_DAYS
        self.service_token_expire_minutes = settings.SERVICE_TOKEN_EXPIRE_MINUTES

    def create_access_token(
        self,
        subject: str,
        scopes: List[str],
        audience: List[str],
        roles: Optional[List[str]] = None,
        username: Optional[str] = None,
        email: Optional[str] = None,
        client_id: Optional[str] = None,
        expires_delta: Optional[timedelta] = None,
        additional_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create an access token.
        
        Args:
            subject: Token subject (user ID or client ID)
            scopes: List of scopes
            audience: List of intended audiences
            roles: List of user roles
            username: Username (for user tokens)
            email: User email (for user tokens)
            client_id: OAuth2 client ID
            expires_delta: Custom expiration time
            additional_claims: Additional claims to include
            
        Returns:
            Encoded JWT access token
        """
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)

        payload = {
            JWTClaims.ISSUER: self.issuer,
            JWTClaims.AUDIENCE: audience,
            JWTClaims.SUBJECT: subject,
            JWTClaims.EXPIRATION: expire,
            JWTClaims.ISSUED_AT: datetime.utcnow(),
            JWTClaims.NOT_BEFORE: datetime.utcnow(),
            JWTClaims.JWT_ID: str(uuid.uuid4()),
            JWTClaims.TOKEN_TYPE: TokenType.ACCESS,
            JWTClaims.SCOPES: scopes,
        }

        # Add optional claims
        if roles:
            payload[JWTClaims.ROLES] = roles
        if username:
            payload[JWTClaims.USERNAME] = username
        if email:
            payload[JWTClaims.EMAIL] = email
        if client_id:
            payload[JWTClaims.CLIENT_ID] = client_id

        # Add additional claims
        if additional_claims:
            payload.update(additional_claims)

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(
        self,
        subject: str,
        client_id: Optional[str] = None,
        username: Optional[str] = None,
        expires_delta: Optional[timedelta] = None,
        additional_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a refresh token.
        
        Args:
            subject: Token subject (user ID or client ID)
            client_id: OAuth2 client ID
            username: Username (for user tokens)
            expires_delta: Custom expiration time
            additional_claims: Additional claims to include
            
        Returns:
            Encoded JWT refresh token
        """
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)

        payload = {
            JWTClaims.ISSUER: self.issuer,
            JWTClaims.AUDIENCE: [self.issuer],  # Refresh tokens are for auth server only
            JWTClaims.SUBJECT: subject,
            JWTClaims.EXPIRATION: expire,
            JWTClaims.ISSUED_AT: datetime.utcnow(),
            JWTClaims.NOT_BEFORE: datetime.utcnow(),
            JWTClaims.JWT_ID: str(uuid.uuid4()),
            JWTClaims.TOKEN_TYPE: TokenType.REFRESH,
        }

        # Add optional claims
        if client_id:
            payload[JWTClaims.CLIENT_ID] = client_id
        if username:
            payload[JWTClaims.USERNAME] = username

        # Add additional claims
        if additional_claims:
            payload.update(additional_claims)

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def create_service_token(
        self,
        client_id: str,
        scopes: List[str],
        audience: List[str],
        expires_delta: Optional[timedelta] = None,
        additional_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a service token for client credentials flow.
        
        Args:
            client_id: Service client ID
            scopes: List of scopes
            audience: List of intended audiences
            expires_delta: Custom expiration time
            additional_claims: Additional claims to include
            
        Returns:
            Encoded JWT service token
        """
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.service_token_expire_minutes)

        payload = {
            JWTClaims.ISSUER: self.issuer,
            JWTClaims.AUDIENCE: audience,
            JWTClaims.SUBJECT: client_id,
            JWTClaims.EXPIRATION: expire,
            JWTClaims.ISSUED_AT: datetime.utcnow(),
            JWTClaims.NOT_BEFORE: datetime.utcnow(),
            JWTClaims.JWT_ID: str(uuid.uuid4()),
            JWTClaims.TOKEN_TYPE: TokenType.SERVICE,
            JWTClaims.CLIENT_ID: client_id,
            JWTClaims.SCOPES: scopes,
        }

        # Add additional claims
        if additional_claims:
            payload.update(additional_claims)

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode_token(self, token: str, verify_signature: bool = True) -> Dict[str, Any]:
        """
        Decode a JWT token without validation.
        
        Args:
            token: JWT token to decode
            verify_signature: Whether to verify signature
            
        Returns:
            Token payload
            
        Raises:
            AuthenticationError: If token is invalid
        """
        try:
            options = {
                "verify_signature": verify_signature,
                "verify_exp": verify_signature,
                "verify_nbf": verify_signature,
                "verify_iat": verify_signature,
                "verify_aud": False,  # Don't verify audience in decode_token
                "verify_iss": verify_signature,
            }
            payload = jwt.decode(
                token,
                self.secret_key if verify_signature else None,
                algorithms=[self.algorithm] if verify_signature else None,
                options=options,
            )
            return payload
        except ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except InvalidTokenError as e:
            # Handle malformed tokens gracefully without exposing internal details
            error_msg = str(e).lower()
            if "invalid header" in error_msg or "decode" in error_msg or "utf-8" in error_msg:
                raise AuthenticationError("Invalid token format")
            else:
                raise AuthenticationError(f"Invalid token: {str(e)}")
        except Exception as e:
            # Catch any other unexpected errors during token decoding
            raise AuthenticationError("Invalid token format")

    def validate_token(
        self,
        token: str,
        expected_type: Optional[str] = None,
        expected_audience: Optional[str] = None,
        required_scopes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Validate a JWT token with comprehensive checks.
        
        Args:
            token: JWT token to validate
            expected_type: Expected token type
            expected_audience: Expected audience
            required_scopes: Required scopes for authorization
            
        Returns:
            Validated token payload
            
        Raises:
            AuthenticationError: If token is invalid
            AuthorizationError: If token lacks required permissions
        """
        try:
            # Decode and verify token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": False,  # We'll verify audience manually
                    "verify_iss": True,
                }
            )

            # Validate token type
            if expected_type:
                token_type = payload.get(JWTClaims.TOKEN_TYPE)
                if token_type != expected_type:
                    raise AuthenticationError(f"Invalid token type. Expected {expected_type}, got {token_type}")

            # Validate audience
            if expected_audience:
                audiences = payload.get(JWTClaims.AUDIENCE, [])
                if isinstance(audiences, str):
                    audiences = [audiences]
                if expected_audience not in audiences:
                    raise AuthenticationError(f"Invalid audience. Token not intended for {expected_audience}")

            # Validate scopes for authorization
            if required_scopes:
                token_scopes = payload.get(JWTClaims.SCOPES, [])
                missing_scopes = set(required_scopes) - set(token_scopes)
                if missing_scopes:
                    raise AuthorizationError(f"Insufficient permissions. Missing scopes: {', '.join(missing_scopes)}")

            return payload

        except ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except AuthenticationError:
            # Re-raise AuthenticationError (like audience validation) without modification
            raise
        except AuthorizationError:
            # Re-raise AuthorizationError without modification
            raise
        except InvalidTokenError as e:
            # Handle malformed tokens gracefully without exposing internal details
            error_msg = str(e).lower()
            if "invalid header" in error_msg or "decode" in error_msg or "utf-8" in error_msg:
                raise AuthenticationError("Invalid token format")
            else:
                raise AuthenticationError(f"Invalid token: {str(e)}")
        except Exception as e:
            # Catch any other unexpected errors during token validation
            raise AuthenticationError("Invalid token format")

    def extract_token_info(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract useful information from token payload.
        
        Args:
            payload: Token payload
            
        Returns:
            Extracted token information
        """
        return {
            "jti": payload.get(JWTClaims.JWT_ID),
            "subject": payload.get(JWTClaims.SUBJECT),
            "token_type": payload.get(JWTClaims.TOKEN_TYPE),
            "scopes": payload.get(JWTClaims.SCOPES, []),
            "roles": payload.get(JWTClaims.ROLES, []),
            "username": payload.get(JWTClaims.USERNAME),
            "email": payload.get(JWTClaims.EMAIL),
            "client_id": payload.get(JWTClaims.CLIENT_ID),
            "audience": payload.get(JWTClaims.AUDIENCE, []),
            "issued_at": payload.get(JWTClaims.ISSUED_AT),
            "expires_at": payload.get(JWTClaims.EXPIRATION),
            "not_before": payload.get(JWTClaims.NOT_BEFORE),
        }

    def is_token_expired(self, payload: Dict[str, Any]) -> bool:
        """
        Check if token is expired based on payload.
        
        Args:
            payload: Token payload
            
        Returns:
            True if token is expired
        """
        exp = payload.get(JWTClaims.EXPIRATION)
        if not exp:
            return True
        
        if isinstance(exp, (int, float)):
            exp = datetime.fromtimestamp(exp)
        
        return datetime.utcnow() > exp

    def get_token_remaining_time(self, payload: Dict[str, Any]) -> Optional[timedelta]:
        """
        Get remaining time until token expires.
        
        Args:
            payload: Token payload
            
        Returns:
            Time remaining until expiration (None if no expiration)
        """
        exp = payload.get(JWTClaims.EXPIRATION)
        if not exp:
            return None
        
        if isinstance(exp, (int, float)):
            exp = datetime.fromtimestamp(exp)
        
        remaining = exp - datetime.utcnow()
        return remaining if remaining.total_seconds() > 0 else timedelta(0)

    def refresh_access_token(
        self,
        refresh_token: str,
        new_scopes: Optional[List[str]] = None,
        new_audience: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """
        Create new access token from refresh token.
        
        Args:
            refresh_token: Valid refresh token
            new_scopes: New scopes for access token
            new_audience: New audience for access token
            
        Returns:
            Dictionary with new access and refresh tokens
            
        Raises:
            AuthenticationError: If refresh token is invalid
        """
        # Validate refresh token
        payload = self.validate_token(
            refresh_token,
            expected_type=TokenType.REFRESH,
            expected_audience=self.issuer,
        )

        subject = payload.get(JWTClaims.SUBJECT)
        username = payload.get(JWTClaims.USERNAME)
        client_id = payload.get(JWTClaims.CLIENT_ID)

        if not subject:
            raise AuthenticationError("Invalid refresh token: missing subject")

        # Use provided scopes/audience or defaults
        scopes = new_scopes or []
        audience = new_audience or [self.issuer]

        # Create new access token
        access_token = self.create_access_token(
            subject=subject,
            scopes=scopes,
            audience=audience,
            username=username,
            client_id=client_id,
        )

        # Create new refresh token (token rotation)
        new_refresh_token = self.create_refresh_token(
            subject=subject,
            client_id=client_id,
            username=username,
        )

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
        }

    def create_token_response(
        self,
        access_token: str,
        refresh_token: Optional[str] = None,
        token_type: str = "Bearer",
        expires_in: Optional[int] = None,
        scope: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create OAuth2-compliant token response.
        
        Args:
            access_token: Access token
            refresh_token: Refresh token (optional)
            token_type: Token type (default: Bearer)
            expires_in: Token expiration in seconds
            scope: Granted scopes
            
        Returns:
            Token response dictionary
        """
        response = {
            "access_token": access_token,
            "token_type": token_type,
        }

        if refresh_token:
            response["refresh_token"] = refresh_token

        if expires_in is None:
            expires_in = self.access_token_expire_minutes * 60
        response["expires_in"] = expires_in

        if scope:
            response["scope"] = scope

        # Add JTI for token tracking
        try:
            payload = self.decode_token(access_token, verify_signature=False)
            response["jti"] = payload.get(JWTClaims.JWT_ID)
        except Exception:
            pass

        return response


# Global JWT service instance
jwt_service = JWTService()