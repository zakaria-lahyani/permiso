"""Security utilities and FastAPI dependencies for authentication and authorization."""

import functools
from typing import List, Optional, Union, TYPE_CHECKING
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.database import get_db
from app.config.redis import get_redis, RedisClient
from app.core.jwt import jwt_service, JWTClaims, TokenType
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
)

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.service_client import ServiceClient
    from app.models.refresh_token import RefreshToken
else:
    from app.models.user import User
    from app.models.service_client import ServiceClient
    from app.models.refresh_token import RefreshToken


# HTTP Bearer token security scheme
security = HTTPBearer(auto_error=False)


class SecurityUtils:
    """Security utility functions."""

    @staticmethod
    def extract_bearer_token(credentials: Optional[HTTPAuthorizationCredentials]) -> str:
        """
        Extract bearer token from authorization credentials.
        
        Args:
            credentials: HTTP authorization credentials
            
        Returns:
            Bearer token string
            
        Raises:
            AuthenticationError: If no token provided
        """
        if not credentials or not credentials.credentials:
            raise AuthenticationError("No authentication token provided")
        
        return credentials.credentials

    @staticmethod
    async def is_token_revoked(jti: str, redis: RedisClient) -> bool:
        """
        Check if token is revoked using Redis blacklist.
        
        Args:
            jti: JWT ID to check
            redis: Redis client
            
        Returns:
            True if token is revoked
        """
        try:
            return await redis.exists(f"revoked_token:{jti}")
        except Exception:
            # If Redis is unavailable, assume token is not revoked
            # In production, you might want to fail closed instead
            return False

    @staticmethod
    async def revoke_token(jti: str, redis: RedisClient, ttl: int = 86400) -> None:
        """
        Add token to revocation blacklist.
        
        Args:
            jti: JWT ID to revoke
            redis: Redis client
            ttl: Time to live for blacklist entry
        """
        try:
            await redis.set(f"revoked_token:{jti}", "1", expire=ttl)
        except Exception:
            # Log error but don't fail the operation
            pass

    @staticmethod
    async def get_user_by_id(user_id: str, db: AsyncSession) -> User:
        """
        Get user by ID with validation.
        
        Args:
            user_id: User ID
            db: Database session
            
        Returns:
            User instance
            
        Raises:
            UserNotFoundError: If user not found
            UserDisabledError: If user is disabled
            UserLockedError: If user is locked
        """
        from sqlalchemy import select
        
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        if not user.is_active:
            raise UserDisabledError("User account is disabled")
        
        if user.is_locked:
            raise UserLockedError("User account is locked")
        
        return user

    @staticmethod
    async def get_service_client_by_id(client_id: str, db: AsyncSession) -> ServiceClient:
        """
        Get service client by ID with validation.
        
        Args:
            client_id: Service client ID
            db: Database session
            
        Returns:
            ServiceClient instance
            
        Raises:
            ServiceClientNotFoundError: If client not found
            ServiceClientDisabledError: If client is disabled
        """
        from sqlalchemy import select
        
        result = await db.execute(select(ServiceClient).where(ServiceClient.client_id == client_id))
        client = result.scalar_one_or_none()
        
        if not client:
            raise ServiceClientNotFoundError(f"Service client {client_id} not found")
        
        if not client.enabled:
            raise ServiceClientDisabledError("Service client is disabled")
        
        return client


def _get_implied_scopes(token_scopes: List[str]) -> List[str]:
    """
    Get scopes that are implied by the given token scopes.
    
    Args:
        token_scopes: List of scopes in the token
        
    Returns:
        List of implied scopes
    """
    implied = []
    
    for scope in token_scopes:
        # Admin scopes imply read/write scopes for the same resource
        if scope.startswith("admin:"):
            resource = scope.split(":", 1)[1]
            implied.extend([f"read:{resource}", f"write:{resource}"])
        
        # System admin implies everything
        if scope == "admin:system":
            implied.extend([
                "read:profile", "write:profile",
                "read:trades", "write:trades",
                "admin:users", "admin:clients",
                "service:mt5", "service:api"
            ])
    
    return implied


def _classify_scope_security_level(scope: str) -> str:
    """
    Classify the security level of a scope.
    
    Args:
        scope: Scope name to classify
        
    Returns:
        Security level classification
    """
    if scope.startswith("admin:"):
        return "restricted"
    elif scope.startswith("write:") or scope.startswith("service:"):
        return "protected"
    elif scope.startswith("read:"):
        return "public"
    else:
        return "custom"


async def get_current_token_payload(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    redis: RedisClient = Depends(get_redis),
) -> dict:
    """
    Extract and validate current token payload.
    
    Args:
        credentials: HTTP authorization credentials
        redis: Redis client
        
    Returns:
        Token payload dictionary
        
    Raises:
        HTTPException: If token is invalid
    """
    try:
        token = SecurityUtils.extract_bearer_token(credentials)
        payload = jwt_service.validate_token(token)
        
        # Check if token is revoked
        jti = payload.get(JWTClaims.JWT_ID)
        if jti and await SecurityUtils.is_token_revoked(jti, redis):
            raise RevokedTokenError("Token has been revoked")
        
        return payload
    
    except (AuthenticationError, AuthorizationError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    payload: dict = Depends(get_current_token_payload),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Get current authenticated user.
    
    Args:
        payload: Token payload
        db: Database session
        
    Returns:
        Current user
        
    Raises:
        HTTPException: If user not found or invalid
    """
    try:
        # Ensure this is a user token (not service token)
        token_type = payload.get(JWTClaims.TOKEN_TYPE)
        if token_type == TokenType.SERVICE:
            raise AuthenticationError("Service tokens cannot be used for user authentication")
        
        user_id = payload.get(JWTClaims.SUBJECT)
        if not user_id:
            raise AuthenticationError("Invalid token: missing user ID")
        
        return await SecurityUtils.get_user_by_id(user_id, db)
    
    except (AuthenticationError, UserNotFoundError, UserDisabledError, UserLockedError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_service_client(
    payload: dict = Depends(get_current_token_payload),
    db: AsyncSession = Depends(get_db),
):
    """
    Get current authenticated service client.
    
    Args:
        payload: Token payload
        db: Database session
        
    Returns:
        Current service client
        
    Raises:
        HTTPException: If service client not found or invalid
    """
    try:
        # Ensure this is a service token
        token_type = payload.get(JWTClaims.TOKEN_TYPE)
        if token_type != TokenType.SERVICE:
            raise AuthenticationError("Only service tokens can be used for service authentication")
        
        client_id = payload.get(JWTClaims.CLIENT_ID)
        if not client_id:
            raise AuthenticationError("Invalid token: missing client ID")
        
        return await SecurityUtils.get_service_client_by_id(client_id, db)
    
    except (AuthenticationError, ServiceClientNotFoundError, ServiceClientDisabledError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_scopes(required_scopes: List[str]):
    """
    Dependency factory for scope-based authorization with enhanced parsing.
    
    Args:
        required_scopes: List of required scopes
        
    Returns:
        FastAPI dependency function
    """
    async def check_scopes(token_payload: dict = Depends(get_current_token_payload)) -> dict:
        try:
            token_scopes = token_payload.get(JWTClaims.SCOPES, [])
            
            # Parse scopes if they come as a string
            if isinstance(token_scopes, str):
                token_scopes = token_scopes.split()
            
            # Check for exact matches first
            missing_scopes = set(required_scopes) - set(token_scopes)
            
            # If there are missing scopes, check for implied scopes
            if missing_scopes:
                implied_scopes = _get_implied_scopes(token_scopes)
                missing_scopes = missing_scopes - set(implied_scopes)
            
            if missing_scopes:
                raise InsufficientScopeError(
                    f"Insufficient permissions. Missing scopes: {', '.join(missing_scopes)}",
                    required_scopes=list(missing_scopes),
                )
            
            return token_payload
        
        except InsufficientScopeError:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "scope_check_failed", "error_description": str(e)},
            )
    
    # Create a simple function for tests to access
    def wrapped_check_scopes(token_payload: dict) -> dict:
        token_scopes = token_payload.get(JWTClaims.SCOPES, [])
        
        # Parse scopes if they come as a string
        if isinstance(token_scopes, str):
            token_scopes = token_scopes.split()
        
        # Check for exact matches first
        missing_scopes = set(required_scopes) - set(token_scopes)
        
        # If there are missing scopes, check for implied scopes
        if missing_scopes:
            implied_scopes = _get_implied_scopes(token_scopes)
            missing_scopes = missing_scopes - set(implied_scopes)
        
        if missing_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_scope",
                    "error_description": f"Insufficient permissions. Missing scopes: {', '.join(missing_scopes)}",
                    "required_scopes": list(missing_scopes),
                },
            )
        
        return token_payload
    
    check_scopes.__wrapped__ = wrapped_check_scopes
    return check_scopes


def require_roles(required_roles: List[str]):
    """
    Dependency factory for role-based authorization.
    
    Args:
        required_roles: List of required roles
        
    Returns:
        FastAPI dependency function
    """
    async def check_roles(current_user: User = Depends(get_current_user)):
        try:
            user_roles = await current_user.get_role_names()
            if not any(role in user_roles for role in required_roles):
                raise AuthorizationError(
                    f"Insufficient permissions. Required roles: {', '.join(required_roles)}",
                    details={"required_roles": required_roles, "user_roles": user_roles},
                )
            
            return current_user
        
        except AuthorizationError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(e),
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Role check failed: {str(e)}",
            )
    
    # Create a simple function for tests to access
    async def wrapped_check_roles(current_user):
        user_roles = await current_user.get_role_names()
        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_role",
                    "error_description": f"Insufficient permissions. Required roles: {', '.join(required_roles)}",
                    "required_roles": required_roles,
                    "user_roles": user_roles,
                },
            )
        
        return current_user
    
    check_roles.__wrapped__ = wrapped_check_roles
    return check_roles


# Cache the admin roles dependency to ensure object identity
_admin_roles_dependency = None

def require_admin():
    """
    Dependency for admin-only endpoints.
    
    Returns:
        FastAPI dependency function equivalent to require_roles(["admin"])
    """
    global _admin_roles_dependency
    if _admin_roles_dependency is None:
        _admin_roles_dependency = require_roles(["admin"])
    return _admin_roles_dependency


def require_any_scope(allowed_scopes: List[str]):
    """
    Dependency factory for "any of" scope authorization with enhanced parsing.
    
    Args:
        allowed_scopes: List of allowed scopes (user needs at least one)
        
    Returns:
        FastAPI dependency function
    """
    async def check_any_scope(payload: dict = Depends(get_current_token_payload)) -> dict:
        try:
            token_scopes = payload.get(JWTClaims.SCOPES, [])
            
            # Parse scopes if they come as a string
            if isinstance(token_scopes, str):
                token_scopes = token_scopes.split()
            
            # Check for direct matches first
            has_scope = any(scope in token_scopes for scope in allowed_scopes)
            
            # If no direct match, check implied scopes
            if not has_scope:
                implied_scopes = _get_implied_scopes(token_scopes)
                has_scope = any(scope in implied_scopes for scope in allowed_scopes)
            
            if not has_scope:
                raise InsufficientScopeError(
                    f"Insufficient permissions. Need at least one of: {', '.join(allowed_scopes)}",
                    required_scopes=allowed_scopes,
                )
            
            return payload
        
        except InsufficientScopeError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(e),
            )
    
    # Create a simple function for tests to access
    def wrapped_check_any_scope(payload: dict) -> dict:
        token_scopes = payload.get(JWTClaims.SCOPES, [])
        
        # Parse scopes if they come as a string
        if isinstance(token_scopes, str):
            token_scopes = token_scopes.split()
        
        # Check for direct matches first
        has_scope = any(scope in token_scopes for scope in allowed_scopes)
        
        # If no direct match, check implied scopes
        if not has_scope:
            implied_scopes = _get_implied_scopes(token_scopes)
            has_scope = any(scope in implied_scopes for scope in allowed_scopes)
        
        if not has_scope:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_scope",
                    "error_description": f"Insufficient permissions. Need at least one of: {', '.join(allowed_scopes)}",
                    "required_scopes": allowed_scopes,
                },
            )
        
        return payload
    
    check_any_scope.__wrapped__ = wrapped_check_any_scope
    return check_any_scope


def require_user_or_service():
    """
    Dependency that accepts either user or service tokens.
    
    Returns:
        Token payload
    """
    async def check_user_or_service(
        payload: dict = Depends(get_current_token_payload)
    ) -> dict:
        token_type = payload.get(JWTClaims.TOKEN_TYPE)
        if token_type not in [TokenType.ACCESS, TokenType.SERVICE]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "invalid_token_type", "error_description": "Invalid token type"},
            )
        return payload
    
    return check_user_or_service


async def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis),
):
    """
    Get current user if token is provided (optional authentication).
    
    Args:
        credentials: HTTP authorization credentials (optional)
        db: Database session
        redis: Redis client
        
    Returns:
        Current user or None if no token provided
    """
    if not credentials or not credentials.credentials:
        return None
    
    try:
        token = credentials.credentials
        payload = jwt_service.validate_token(token)
        
        # Check if token is revoked
        jti = payload.get(JWTClaims.JWT_ID)
        if jti and await SecurityUtils.is_token_revoked(jti, redis):
            return None
        
        # Ensure this is a user token
        token_type = payload.get(JWTClaims.TOKEN_TYPE)
        if token_type == TokenType.SERVICE:
            return None
        
        user_id = payload.get(JWTClaims.SUBJECT)
        if not user_id:
            return None
        
        return await SecurityUtils.get_user_by_id(user_id, db)
    
    except Exception:
        # If any error occurs, return None (optional auth)
        return None


# Convenience dependencies
CurrentUser = Depends(get_current_user)
CurrentServiceClient = Depends(get_current_service_client)
OptionalCurrentUser = Depends(get_optional_current_user)
AdminUser = require_admin()