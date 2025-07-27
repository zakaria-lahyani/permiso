"""User management API endpoints for Keystone authentication system."""

import math
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from sqlalchemy.orm import selectinload

from app.config.database import get_db
from app.config.redis import get_redis
from app.core.password import hash_password, verify_password
from app.core.security import (
    get_current_user,
    require_admin,
    require_scopes,
    require_roles
)
from app.core.exceptions import (
    UserNotFoundError,
    ValidationError,
    ConflictError
)
from app.models.user import User
from app.models.role import Role
from app.schemas.user import (
    UserCreate,
    UserUpdate,
    UserResponse,
    UserListResponse,
    UserSearchParams,
    UserPasswordUpdate,
    UserRoleUpdate,
    UserProfileUpdate,
    UserStats,
    PasswordResetRequest,
    PasswordResetConfirm,
    EmailVerificationRequest,
    EmailVerificationConfirm
)

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    request: Request,
    db = Depends(get_db),
    redis = Depends(get_redis)
):
    """
    Register a new user account.
    
    Creates a new user with the provided information.
    Public endpoint - no authentication required.
    """
    try:
        # Check rate limiting first
        ip_address = request.client.host if request.client else "unknown"
        await _check_registration_rate_limit(redis, ip_address)
        
        # Handle async generator properly
        try:
            if hasattr(db, '__anext__'):
                db_session = await db.__anext__()
            else:
                db_session = db
        except StopAsyncIteration:
            from app.config.database import get_db
            async_gen = get_db()
            db_session = await async_gen.__anext__()
            
        # Check if username already exists
        existing_user = await User.get_by_username(db_session, user_data.username)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "conflict", "error_description": "Username already exists"}
            )
        
        # Check if email already exists
        existing_email = await User.get_by_email(db_session, user_data.email)
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "conflict", "error_description": "Email already exists"}
            )
        
        # Hash password
        password_hash = hash_password(user_data.password)
        
        # Create user
        user = User(
            username=user_data.username,
            email=user_data.email,
            password_hash=password_hash,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            display_name=user_data.display_name,
            bio=user_data.bio,
            is_active=True,  # New users are active by default
            is_verified=False  # Email verification required
        )
        
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        
        return UserResponse.from_orm(user)
        
    except HTTPException:
        raise
    except Exception as e:
        if hasattr(db_session, 'rollback'):
            await db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("", response_model=UserListResponse)
@router.get("/", response_model=UserListResponse)
async def list_users(
    search: Optional[str] = Query(None, description="Search term for username, email, or name"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    is_verified: Optional[bool] = Query(None, description="Filter by verification status"),
    role_id: Optional[int] = Query(None, description="Filter by role ID"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user = Depends(require_admin()),
    db = Depends(get_db)
):
    """
    List users with pagination and filtering.
    
    Requires admin role.
    """
    try:
        # Build query
        query = select(User).options(selectinload(User.roles))
        
        # Apply filters
        conditions = []
        
        if search:
            search_term = f"%{search}%"
            conditions.append(
                or_(
                    User.username.ilike(search_term),
                    User.email.ilike(search_term),
                    User.first_name.ilike(search_term),
                    User.last_name.ilike(search_term),
                    User.display_name.ilike(search_term)
                )
            )
        
        if is_active is not None:
            conditions.append(User.is_active == is_active)
        
        if is_verified is not None:
            conditions.append(User.is_verified == is_verified)
        
        if role_id is not None:
            query = query.join(User.roles).where(Role.id == role_id)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Get total count
        count_query = select(func.count(User.id))
        if conditions:
            count_query = count_query.where(and_(*conditions))
        if role_id is not None:
            count_query = count_query.select_from(User).join(User.roles).where(Role.id == role_id)
        
        # Handle async generator properly
        try:
            if hasattr(db, '__anext__'):
                db_session = await db.__anext__()
            else:
                db_session = db
        except StopAsyncIteration:
            from app.config.database import get_db
            async_gen = get_db()
            db_session = await async_gen.__anext__()
            
        total_result = await db_session.execute(count_query)
        total = total_result.scalar()
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        # Execute query
        result = await db_session.execute(query)
        users = result.scalars().all()
        
        # Calculate pages
        pages = math.ceil(total / per_page) if total > 0 else 1
        
        return UserListResponse(
            users=[UserResponse.from_orm(user) for user in users],
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    current_user = Depends(require_admin()),
    db = Depends(get_db)
):
    """
    Create a new user.
    
    Requires admin role.
    """
    try:
        # Handle async generator properly
        try:
            if hasattr(db, '__anext__'):
                db_session = await db.__anext__()
            else:
                db_session = db
        except StopAsyncIteration:
            from app.config.database import get_db
            async_gen = get_db()
            db_session = await async_gen.__anext__()
            
        # Check if username already exists
        existing_user = await User.get_by_username(db_session, user_data.username)
        if existing_user:
            raise ConflictError("Username already exists")
        
        # Check if email already exists
        existing_email = await User.get_by_email(db_session, user_data.email)
        if existing_email:
            raise ConflictError("Email already exists")
        
        # Hash password
        password_hash = hash_password(user_data.password)
        
        # Create user
        user = User(
            username=user_data.username,
            email=user_data.email,
            password_hash=password_hash,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            display_name=user_data.display_name,
            bio=user_data.bio,
            is_active=user_data.is_active,
            is_verified=user_data.is_verified
        )
        
        db_session.add(user)
        await db_session.flush()  # Get user ID
        
        # Assign roles if provided
        if user_data.role_ids:
            roles_result = await db_session.execute(
                select(Role).where(Role.id.in_(user_data.role_ids))
            )
            roles = roles_result.scalars().all()
            user.roles.extend(roles)
        
        await db_session.commit()
        await db_session.refresh(user)
        
        return UserResponse.from_orm(user)
        
    except ConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "conflict", "error_description": str(e)}
        )
    except Exception as e:
        if hasattr(db_session, 'rollback'):
            await db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user = Depends(get_current_user)
):
    """
    Get current user's profile.
    
    Returns the authenticated user's information.
    """
    return UserResponse.from_orm(current_user)


@router.get("/profile", response_model=UserResponse)
async def get_user_profile(
    current_user = Depends(get_current_user)
):
    """
    Get current user's profile (alias for /me).
    
    Returns the authenticated user's information.
    """
    return UserResponse.from_orm(current_user)


@router.put("/me", response_model=UserResponse)
async def update_current_user_profile(
    profile_data: UserProfileUpdate,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """
    Update current user's profile.
    
    Users can update their own profile information.
    """
    try:
        # Check if email is being changed and already exists
        if profile_data.email and profile_data.email != current_user.email:
            existing_email = await User.get_by_email(db, profile_data.email)
            if existing_email:
                raise ConflictError("Email already exists")
            current_user.email = profile_data.email
            current_user.is_verified = False  # Re-verify email
        
        # Update other fields
        if profile_data.first_name is not None:
            current_user.first_name = profile_data.first_name
        if profile_data.last_name is not None:
            current_user.last_name = profile_data.last_name
        if profile_data.display_name is not None:
            current_user.display_name = profile_data.display_name
        if profile_data.bio is not None:
            current_user.bio = profile_data.bio
        
        await db.commit()
        await db.refresh(current_user)
        
        return UserResponse.from_orm(current_user)
        
    except ConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "conflict", "error_description": str(e)}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """
    Get user by ID.
    
    Users can view their own profile or admins can view any profile.
    """
    try:
        # Handle async generator properly
        try:
            if hasattr(db, '__anext__'):
                # db is an async generator, get the actual session
                db_session = await db.__anext__()
            else:
                db_session = db
        except StopAsyncIteration:
            # If the generator is exhausted, we need to get a new one
            from app.config.database import get_db
            async_gen = get_db()
            db_session = await async_gen.__anext__()
            
        # Check if user is accessing their own profile or is admin
        if user_id != str(current_user.id) and not await current_user.is_admin():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "forbidden", "error_description": "Access denied"}
            )
        
        # Get user
        result = await db_session.execute(
            select(User).options(selectinload(User.roles)).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        return UserResponse.from_orm(user)
        
    except UserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "User not found"}
        )
    except Exception as e:
        import traceback
        print(f"Exception in get_user: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    current_user = Depends(require_admin()),
    db = Depends(get_db)
):
    """
    Update user by ID.
    
    Requires admin role.
    """
    try:
        # Get user
        result = await db.execute(
            select(User).options(selectinload(User.roles)).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        # Check if email is being changed and already exists
        if user_data.email and user_data.email != user.email:
            existing_email = await User.get_by_email(db, user_data.email)
            if existing_email:
                raise ConflictError("Email already exists")
            user.email = user_data.email
            if not user_data.is_verified:
                user.is_verified = False  # Re-verify email if not explicitly verified
        
        # Update fields
        if user_data.first_name is not None:
            user.first_name = user_data.first_name
        if user_data.last_name is not None:
            user.last_name = user_data.last_name
        if user_data.display_name is not None:
            user.display_name = user_data.display_name
        if user_data.bio is not None:
            user.bio = user_data.bio
        if user_data.is_active is not None:
            user.is_active = user_data.is_active
        if user_data.is_verified is not None:
            user.is_verified = user_data.is_verified
        
        # Update roles if provided
        if user_data.role_ids is not None:
            roles_result = await db.execute(
                select(Role).where(Role.id.in_(user_data.role_ids))
            )
            roles = roles_result.scalars().all()
            user.roles.clear()
            user.roles.extend(roles)
        
        await db.commit()
        await db.refresh(user)
        
        return UserResponse.from_orm(user)
        
    except (UserNotFoundError, ConflictError) as e:
        status_code = status.HTTP_404_NOT_FOUND if isinstance(e, UserNotFoundError) else status.HTTP_409_CONFLICT
        raise HTTPException(
            status_code=status_code,
            detail={"error": "not_found" if isinstance(e, UserNotFoundError) else "conflict", "error_description": str(e)}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    current_user = Depends(require_admin()),
    db = Depends(get_db)
):
    """
    Delete user by ID.
    
    Requires admin role. Users cannot delete themselves.
    """
    try:
        # Prevent self-deletion
        if user_id == current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "forbidden", "error_description": "Cannot delete your own account"}
            )
        
        # Get user
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        # Delete user
        await db.delete(user)
        await db.commit()
        
    except UserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "User not found"}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.put("/{user_id}/password")
async def update_user_password(
    user_id: str,
    password_data: UserPasswordUpdate,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """
    Update user password.
    
    Users can update their own password or admins can update any password.
    """
    try:
        # Check if user is updating their own password or is admin
        if user_id != current_user.id and not await current_user.is_admin():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "forbidden", "error_description": "Access denied"}
            )
        
        # Get user
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        # Verify current password (only for self-update)
        if user_id == current_user.id:
            if not verify_password(password_data.current_password, user.password_hash):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"error": "invalid_password", "error_description": "Current password is incorrect"}
                )
        
        # Update password
        user.password_hash = hash_password(password_data.new_password)
        user.password_changed_at = datetime.utcnow()
        
        await db.commit()
        
        return {"message": "Password updated successfully"}
        
    except UserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "User not found"}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.put("/{user_id}/roles", response_model=UserResponse)
async def update_user_roles(
    user_id: str,
    role_data: UserRoleUpdate,
    current_user = Depends(require_admin()),
    db = Depends(get_db)
):
    """
    Update user roles.
    
    Requires admin role.
    """
    try:
        # Get user
        result = await db.execute(
            select(User).options(selectinload(User.roles)).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        # Get roles
        roles_result = await db.execute(
            select(Role).where(Role.id.in_(role_data.role_ids))
        )
        roles = roles_result.scalars().all()
        
        # Update user roles
        user.roles.clear()
        user.roles.extend(roles)
        
        await db.commit()
        await db.refresh(user)
        
        return UserResponse.from_orm(user)
        
    except UserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "User not found"}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/stats/overview", response_model=UserStats)
async def get_user_stats(
    current_user = Depends(require_admin()),
    db = Depends(get_db)
):
    """
    Get user statistics overview.
    
    Requires admin role.
    """
    try:
        # Get total users
        total_result = await db.execute(select(func.count(User.id)))
        total_users = total_result.scalar()
        
        # Get active users
        active_result = await db.execute(
            select(func.count(User.id)).where(User.is_active == True)
        )
        active_users = active_result.scalar()
        
        # Get verified users
        verified_result = await db.execute(
            select(func.count(User.id)).where(User.is_verified == True)
        )
        verified_users = verified_result.scalar()
        
        # Get locked users
        locked_result = await db.execute(
            select(func.count(User.id)).where(User.locked_until > datetime.utcnow())
        )
        locked_users = locked_result.scalar()
        
        # Get recent registrations (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_result = await db.execute(
            select(func.count(User.id)).where(User.created_at >= thirty_days_ago)
        )
        recent_registrations = recent_result.scalar()
        
        return UserStats(
            total_users=total_users,
            active_users=active_users,
            verified_users=verified_users,
            locked_users=locked_users,
            recent_registrations=recent_registrations
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.post("/password-reset/request")
async def request_password_reset(
    reset_request: PasswordResetRequest,
    db = Depends(get_db)
):
    """
    Request password reset.
    
    Sends password reset email to user.
    """
    try:
        # Get user by email
        user = await User.get_by_email(db, reset_request.email)
        
        if user and user.is_active:
            # Generate reset token (in production, use secure token generation)
            import secrets
            reset_token = secrets.token_urlsafe(32)
            
            # Store reset token
            user.set_password_reset_token(reset_token)
            await db.commit()
            
            # TODO: Send email with reset token
            # In production, integrate with email service
            
        # Always return success to prevent email enumeration
        return {"message": "If the email exists, a password reset link has been sent"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.post("/password-reset/confirm")
async def confirm_password_reset(
    reset_confirm: PasswordResetConfirm,
    db = Depends(get_db)
):
    """
    Confirm password reset with token.
    
    Resets user password using reset token.
    """
    try:
        # Find user with reset token
        result = await db.execute(
            select(User).where(
                User.password_reset_token == reset_confirm.token,
                User.password_reset_sent_at > datetime.utcnow() - timedelta(hours=24)  # 24 hour expiry
            )
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_token", "error_description": "Invalid or expired reset token"}
            )
        
        # Update password
        user.password_hash = hash_password(reset_confirm.new_password)
        user.password_changed_at = datetime.utcnow()
        user.clear_password_reset_token()
        
        await db.commit()
        
        return {"message": "Password reset successfully"}
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.post("/email-verification/request")
async def request_email_verification(
    verification_request: EmailVerificationRequest,
    db = Depends(get_db)
):
    """
    Request email verification.
    
    Sends verification email to user.
    """
    try:
        # Get user by email
        user = await User.get_by_email(db, verification_request.email)
        
        if user and user.is_active and not user.is_verified:
            # Generate verification token
            import secrets
            verification_token = secrets.token_urlsafe(32)
            
            # Store verification token
            user.set_email_verification_token(verification_token)
            await db.commit()
            
            # TODO: Send verification email
            # In production, integrate with email service
        
        # Always return success to prevent email enumeration
        return {"message": "If the email exists and is unverified, a verification link has been sent"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


async def _check_registration_rate_limit(redis, ip_address: str):
    """Check registration rate limiting."""
    try:
        # Handle the case where redis might be a coroutine from dependency injection
        if asyncio.iscoroutine(redis):
            redis_client = await redis
        elif callable(redis) and not hasattr(redis, 'get'):
            # If redis is a function, try to call it
            try:
                redis_client = await redis() if asyncio.iscoroutinefunction(redis) else redis()
            except Exception:
                return  # Skip rate limiting if Redis is not available
        else:
            redis_client = redis
        
        # Rate limit: 3 registrations per hour per IP
        rate_limit_key = f"registration_rate_limit:{ip_address}"
        current_count = await redis_client.get(rate_limit_key)
        
        if current_count is None:
            current_count = 0
        else:
            current_count = int(current_count)
        
        # Check if rate limit exceeded (3 per hour)
        if current_count >= 3:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "rate_limit_exceeded",
                    "error_description": "Too many registration attempts. Please try again later."
                },
                headers={"Retry-After": "3600"}  # 1 hour
            )
        
        # Increment counter
        await redis_client.incr(rate_limit_key)
        await redis_client.expire(rate_limit_key, 3600)  # 1 hour expiry
        
    except HTTPException:
        raise
    except Exception:
        # Don't fail registration if Redis is unavailable
        pass


@router.post("/email-verification/confirm")
async def confirm_email_verification(
    verification_confirm: EmailVerificationConfirm,
    db = Depends(get_db)
):
    """
    Confirm email verification with token.
    
    Verifies user email using verification token.
    """
    try:
        # Find user with verification token
        result = await db.execute(
            select(User).where(
                User.email_verification_token == verification_confirm.token,
                User.email_verification_sent_at > datetime.utcnow() - timedelta(hours=48)  # 48 hour expiry
            )
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_token", "error_description": "Invalid or expired verification token"}
            )
        
        # Verify email
        user.verify_email()
        await db.commit()
        
        return {"message": "Email verified successfully"}
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )