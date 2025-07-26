"""Authentication API endpoints for Keystone authentication system."""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Form, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config.database import get_db
from app.config.redis import get_redis
from app.config.settings import get_settings
from app.core.jwt import jwt_service, JWTClaims, TokenType
from app.core.password import verify_password, hash_password
from app.core.security import (
    get_current_token_payload,
    get_current_user,
    SecurityUtils,
    require_scopes
)
from app.core.exceptions import (
    AuthenticationError,
    UserNotFoundError,
    UserDisabledError,
    UserLockedError,
    InvalidTokenError,
    ServiceClientNotFoundError,
    ServiceClientDisabledError
)
from app.models.user import User
from app.models.service_client import ServiceClient
from app.models.refresh_token import RefreshToken
from app.services.session_service import SessionService, get_session_service
from app.schemas.auth import (
    TokenRequest,
    ServiceTokenRequest,
    TokenResponse,
    RefreshTokenRequest,
    TokenIntrospectionRequest,
    TokenIntrospectionResponse,
    TokenRevocationRequest,
    LogoutResponse,
    AuthError
)

router = APIRouter()
settings = get_settings()


@router.post("/token", response_model=TokenResponse, responses={
    400: {"model": AuthError, "description": "Invalid request"},
    401: {"model": AuthError, "description": "Invalid credentials"},
    423: {"model": AuthError, "description": "Account locked"}
})
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis),
    session_service: SessionService = Depends(get_session_service)
):
    """
    OAuth2 compatible token login endpoint for user authentication.
    
    Supports both username and email for login.
    Returns access token and optional refresh token.
    """
    try:
        # Get user by username or email
        user = await User.get_by_username_or_email(db, form_data.username)
        
        if not user:
            # Increment failed login attempts for rate limiting
            await _track_failed_login(redis, form_data.username, request.client.host)
            raise AuthenticationError("Invalid username or password")
        
        # Verify password
        if not verify_password(form_data.password, user.password_hash):
            user.increment_failed_login(
                max_attempts=settings.max_login_attempts,
                lockout_minutes=settings.account_lockout_minutes
            )
            await db.commit()
            await _track_failed_login(redis, form_data.username, request.client.host)
            raise AuthenticationError("Invalid username or password")
        
        # Check if user account is active
        if not user.is_active:
            raise UserDisabledError("User account is disabled")
        
        # Check if user account is locked
        if user.is_locked:
            raise UserLockedError(
                "Account is temporarily locked due to too many failed login attempts",
                locked_until=user.locked_until
            )
        
        # Update last login and reset failed attempts
        user.update_last_login()
        await db.commit()
        
        # Get user scopes
        user_scopes = await user.get_scopes()
        
        # Parse requested scopes
        requested_scopes = form_data.scopes if form_data.scopes else user_scopes
        granted_scopes = list(set(requested_scopes) & set(user_scopes))
        
        # Create access token
        access_payload = {
            JWTClaims.SUBJECT: str(user.id),
            JWTClaims.USERNAME: user.username,
            JWTClaims.EMAIL: user.email,
            JWTClaims.SCOPES: granted_scopes,
            JWTClaims.TOKEN_TYPE: TokenType.ACCESS,
            JWTClaims.IS_SUPERUSER: user.is_superuser
        }
        
        access_token = jwt_service.create_access_token(access_payload)
        access_payload_decoded = jwt_service.validate_token(access_token)
        access_jti = access_payload_decoded.get(JWTClaims.JWT_ID)
        
        # Create refresh token
        refresh_payload = {
            JWTClaims.SUBJECT: str(user.id),
            JWTClaims.USERNAME: user.username,
            JWTClaims.TOKEN_TYPE: TokenType.REFRESH
        }
        
        refresh_token = jwt_service.create_refresh_token(refresh_payload)
        refresh_payload_decoded = jwt_service.validate_token(refresh_token)
        refresh_jti = refresh_payload_decoded.get(JWTClaims.JWT_ID)
        
        # Store refresh token in database
        db_refresh_token = RefreshToken(
            user_id=user.id,
            token_hash=hash_password(refresh_token),  # Hash the token for security
            expires_at=datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
        )
        db.add(db_refresh_token)
        await db.commit()
        
        # Create user session
        user_agent = request.headers.get("user-agent")
        ip_address = request.client.host if request.client else "unknown"
        
        session = await session_service.create_session(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            duration_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            access_token_jti=access_jti,
            refresh_token_jti=refresh_jti,
        )
        
        # Track successful login
        await _track_successful_login(redis, user.username, ip_address)
        
        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            refresh_token=refresh_token,
            scope=" ".join(granted_scopes) if granted_scopes else None,
            session_id=session.session_id
        )
        
    except (AuthenticationError, UserDisabledError, UserLockedError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED if isinstance(e, AuthenticationError) else status.HTTP_423_LOCKED,
            detail=e.to_dict(),
            headers={"WWW-Authenticate": "Bearer"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": "An internal error occurred"}
        )


@router.post("/service-token", response_model=TokenResponse, responses={
    400: {"model": AuthError, "description": "Invalid request"},
    401: {"model": AuthError, "description": "Invalid client credentials"},
    403: {"model": AuthError, "description": "Client disabled"}
})
async def service_token(
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db)
):
    """
    OAuth2 client credentials flow for service-to-service authentication.
    
    Returns access token for service clients.
    """
    try:
        # Get service client
        result = await db.execute(
            select(ServiceClient).where(ServiceClient.client_id == client_id)
        )
        client = result.scalar_one_or_none()
        
        if not client:
            raise ServiceClientNotFoundError(f"Service client {client_id} not found")
        
        # Verify client secret
        if not verify_password(client_secret, client.client_secret_hash):
            raise AuthenticationError("Invalid client credentials")
        
        # Check if client is active
        if not client.is_active:
            raise ServiceClientDisabledError("Service client is disabled")
        
        # Get client scopes
        client_scopes = client.get_scope_names()
        
        # Parse requested scopes
        requested_scopes = scope.split() if scope else client_scopes
        granted_scopes = list(set(requested_scopes) & set(client_scopes))
        
        # Create service token
        service_payload = {
            JWTClaims.CLIENT_ID: client.client_id,
            JWTClaims.SCOPES: granted_scopes,
            JWTClaims.TOKEN_TYPE: TokenType.SERVICE,
            JWTClaims.IS_TRUSTED: client.is_trusted
        }
        
        access_token = jwt_service.create_service_token(
            service_payload,
            expires_delta=timedelta(seconds=client.access_token_lifetime)
        )
        
        # Update client usage
        client.update_usage()
        await db.commit()
        
        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=client.access_token_lifetime,
            scope=" ".join(granted_scopes) if granted_scopes else None
        )
        
    except (ServiceClientNotFoundError, ServiceClientDisabledError, AuthenticationError) as e:
        status_code = status.HTTP_401_UNAUTHORIZED
        if isinstance(e, ServiceClientDisabledError):
            status_code = status.HTTP_403_FORBIDDEN
            
        raise HTTPException(
            status_code=status_code,
            detail=e.to_dict(),
            headers={"WWW-Authenticate": "Bearer"}
        )


@router.post("/refresh", response_model=TokenResponse, responses={
    400: {"model": AuthError, "description": "Invalid request"},
    401: {"model": AuthError, "description": "Invalid refresh token"}
})
async def refresh_access_token(
    refresh_request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using refresh token.
    
    Returns new access token and refresh token.
    """
    try:
        # Validate refresh token
        payload = jwt_service.validate_token(refresh_request.refresh_token)
        
        if payload.get(JWTClaims.TOKEN_TYPE) != TokenType.REFRESH:
            raise InvalidTokenError("Invalid token type")
        
        user_id = payload.get(JWTClaims.SUBJECT)
        if not user_id:
            raise InvalidTokenError("Invalid token payload")
        
        # Get user
        user = await SecurityUtils.get_user_by_id(user_id, db)
        
        # Verify refresh token exists in database
        token_hash = hash_password(refresh_request.refresh_token)
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user.id,
                RefreshToken.token_hash == token_hash,
                RefreshToken.expires_at > datetime.utcnow()
            )
        )
        db_refresh_token = result.scalar_one_or_none()
        
        if not db_refresh_token:
            raise InvalidTokenError("Refresh token not found or expired")
        
        # Get user scopes
        user_scopes = await user.get_scopes()
        
        # Create new access token
        access_payload = {
            JWTClaims.SUBJECT: str(user.id),
            JWTClaims.USERNAME: user.username,
            JWTClaims.EMAIL: user.email,
            JWTClaims.SCOPES: user_scopes,
            JWTClaims.TOKEN_TYPE: TokenType.ACCESS,
            JWTClaims.IS_SUPERUSER: user.is_superuser
        }
        
        access_token = jwt_service.create_access_token(access_payload)
        
        # Create new refresh token
        refresh_payload = {
            JWTClaims.SUBJECT: str(user.id),
            JWTClaims.USERNAME: user.username,
            JWTClaims.TOKEN_TYPE: TokenType.REFRESH
        }
        
        new_refresh_token = jwt_service.create_refresh_token(refresh_payload)
        
        # Update refresh token in database
        db_refresh_token.token_hash = hash_password(new_refresh_token)
        db_refresh_token.expires_at = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
        await db.commit()
        
        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=settings.access_token_expire_minutes * 60,
            refresh_token=new_refresh_token,
            scope=" ".join(user_scopes) if user_scopes else None
        )
        
    except (InvalidTokenError, UserNotFoundError, UserDisabledError, UserLockedError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.to_dict(),
            headers={"WWW-Authenticate": "Bearer"}
        )


@router.post("/introspect", response_model=TokenIntrospectionResponse)
async def introspect_token(
    introspection_request: TokenIntrospectionRequest,
    payload: dict = Depends(require_scopes(["admin:tokens"])),
    db: AsyncSession = Depends(get_db)
):
    """
    RFC 7662 OAuth2 Token Introspection endpoint.
    
    Requires admin:tokens scope.
    """
    try:
        # Validate the token to introspect
        token_payload = jwt_service.validate_token(introspection_request.token)
        
        # Check token type
        token_type = token_payload.get(JWTClaims.TOKEN_TYPE)
        
        if token_type == TokenType.ACCESS:
            # User access token
            user_id = token_payload.get(JWTClaims.SUBJECT)
            username = token_payload.get(JWTClaims.USERNAME)
            scopes = token_payload.get(JWTClaims.SCOPES, [])
            
            return TokenIntrospectionResponse(
                active=True,
                sub=user_id,
                username=username,
                scope=" ".join(scopes) if scopes else None,
                exp=token_payload.get(JWTClaims.EXPIRES_AT),
                iat=token_payload.get(JWTClaims.ISSUED_AT),
                token_type="access_token"
            )
            
        elif token_type == TokenType.SERVICE:
            # Service token
            client_id = token_payload.get(JWTClaims.CLIENT_ID)
            scopes = token_payload.get(JWTClaims.SCOPES, [])
            
            return TokenIntrospectionResponse(
                active=True,
                sub=client_id,
                client_id=client_id,
                scope=" ".join(scopes) if scopes else None,
                exp=token_payload.get(JWTClaims.EXPIRES_AT),
                iat=token_payload.get(JWTClaims.ISSUED_AT),
                token_type="service_token"
            )
            
        elif token_type == TokenType.REFRESH:
            # Refresh token
            user_id = token_payload.get(JWTClaims.SUBJECT)
            username = token_payload.get(JWTClaims.USERNAME)
            
            return TokenIntrospectionResponse(
                active=True,
                sub=user_id,
                username=username,
                exp=token_payload.get(JWTClaims.EXPIRES_AT),
                iat=token_payload.get(JWTClaims.ISSUED_AT),
                token_type="refresh_token"
            )
        
        else:
            return TokenIntrospectionResponse(active=False)
            
    except Exception:
        # Token is invalid
        return TokenIntrospectionResponse(active=False)


@router.post("/revoke", responses={
    200: {"description": "Token revoked successfully"},
    401: {"model": AuthError, "description": "Unauthorized"}
})
async def revoke_token(
    revocation_request: TokenRevocationRequest,
    payload: dict = Depends(get_current_token_payload),
    redis = Depends(get_redis)
):
    """
    RFC 7009 OAuth2 Token Revocation endpoint.
    
    Revokes the specified token.
    """
    try:
        # Validate the token to revoke
        token_payload = jwt_service.validate_token(revocation_request.token)
        
        # Get JWT ID for blacklisting
        jti = token_payload.get(JWTClaims.JWT_ID)
        if jti:
            # Add token to blacklist
            exp = token_payload.get(JWTClaims.EXPIRES_AT, 0)
            ttl = max(0, exp - int(datetime.utcnow().timestamp()))
            await SecurityUtils.revoke_token(jti, redis, ttl)
        
        return {"message": "Token revoked successfully"}
        
    except Exception:
        # Even if token is invalid, return success (per RFC 7009)
        return {"message": "Token revoked successfully"}


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    current_user: User = Depends(get_current_user),
    payload: dict = Depends(get_current_token_payload),
    redis = Depends(get_redis),
    db: AsyncSession = Depends(get_db),
    session_service: SessionService = Depends(get_session_service)
):
    """
    Logout current user and revoke tokens.
    
    Revokes current access token and all refresh tokens.
    """
    try:
        sessions_terminated = 0
        
        # Revoke current access token
        jti = payload.get(JWTClaims.JWT_ID)
        if jti:
            exp = payload.get(JWTClaims.EXPIRES_AT, 0)
            ttl = max(0, exp - int(datetime.utcnow().timestamp()))
            await SecurityUtils.revoke_token(jti, redis, ttl)
            sessions_terminated += 1
        
        # Revoke all refresh tokens for the user
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.user_id == current_user.id)
        )
        refresh_tokens = result.scalars().all()
        
        for refresh_token in refresh_tokens:
            await db.delete(refresh_token)
            sessions_terminated += 1
        
        # Invalidate all user sessions
        session_count = await session_service.invalidate_all_user_sessions(current_user.id)
        sessions_terminated += session_count
        
        await db.commit()
        
        return LogoutResponse(
            message="Logged out successfully",
            sessions_terminated=sessions_terminated
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": "Logout failed"}
        )


async def _track_failed_login(redis, username: str, ip_address: str):
    """Track failed login attempt for rate limiting."""
    try:
        # Track by username
        username_key = f"failed_login:username:{username}"
        await redis.incr(username_key)
        await redis.expire(username_key, 3600)  # 1 hour
        
        # Track by IP
        ip_key = f"failed_login:ip:{ip_address}"
        await redis.incr(ip_key)
        await redis.expire(ip_key, 3600)  # 1 hour
        
    except Exception:
        # Don't fail login process if Redis is unavailable
        pass


async def _track_successful_login(redis, username: str, ip_address: str):
    """Track successful login and reset failed attempts."""
    try:
        # Reset failed login counters
        username_key = f"failed_login:username:{username}"
        ip_key = f"failed_login:ip:{ip_address}"
        
        await redis.delete(username_key)
        await redis.delete(ip_key)
        
        # Track successful login
        success_key = f"successful_login:{datetime.utcnow().strftime('%Y-%m-%d')}"
        await redis.incr(success_key)
        await redis.expire(success_key, 86400 * 7)  # 7 days
        
    except Exception:
        # Don't fail login process if Redis is unavailable
        pass