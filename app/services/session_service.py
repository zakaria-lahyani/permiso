"""Session management service for handling user sessions."""

from datetime import datetime, timedelta
from typing import List, Optional
from uuid import uuid4
import uuid

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete

from app.models.session import UserSession
from app.models.user import User
from app.config.database import get_db
from app.config.redis import RedisClient, get_redis
from app.config.settings import get_settings

settings = get_settings()


class SessionService:
    """Service for managing user sessions."""

    def __init__(self, db: AsyncSession, redis: Optional[RedisClient] = None):
        """
        Initialize session service.
        
        Args:
            db: Database session
            redis: Redis client for caching
        """
        self.db = db
        self.redis = redis

    async def create_session(
        self,
        user: User,
        ip_address: str,
        user_agent: Optional[str] = None,
        duration_seconds: int = 3600,  # 1 hour default
        access_token_jti: Optional[str] = None,
        refresh_token_jti: Optional[str] = None,
    ) -> UserSession:
        """
        Create a new user session.
        
        Args:
            user: User instance
            ip_address: Client IP address
            user_agent: User agent string
            duration_seconds: Session duration in seconds
            access_token_jti: Access token JTI
            refresh_token_jti: Refresh token JTI
            
        Returns:
            New UserSession instance
        """
        session = UserSession.create_session(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            duration_seconds=duration_seconds,
            access_token_jti=access_token_jti,
            refresh_token_jti=refresh_token_jti,
        )
        
        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)
        
        # Cache session in Redis if available
        if self.redis:
            await self._cache_session(session)
        
        return session

    async def get_session(self, session_id: str) -> Optional[UserSession]:
        """
        Get session by session ID.
        
        Args:
            session_id: Session ID
            
        Returns:
            UserSession instance or None
        """
        # Try Redis cache first
        if self.redis:
            cached_session = await self._get_cached_session(session_id)
            if cached_session:
                return cached_session
        
        # Fallback to database
        session = await UserSession.get_by_session_id(self.db, session_id)
        
        # Cache in Redis if found
        if session and self.redis:
            await self._cache_session(session)
        
        return session

    async def get_valid_session(self, session_id: str) -> Optional[UserSession]:
        """
        Get valid session by session ID.
        
        Args:
            session_id: Session ID
            
        Returns:
            Valid UserSession instance or None
        """
        session = await self.get_session(session_id)
        
        if not session or not session.is_valid:
            return None
        
        return session

    async def update_session_activity(self, session_id: str) -> bool:
        """
        Update session last activity timestamp.
        
        Args:
            session_id: Session ID
            
        Returns:
            True if session was updated
        """
        session = await self.get_session(session_id)
        
        if not session or not session.is_valid:
            return False
        
        session.update_activity()
        await self.db.commit()
        
        # Update cache
        if self.redis:
            await self._cache_session(session)
        
        return True

    async def renew_session(
        self,
        session_id: str,
        duration_seconds: int = 3600,
    ) -> Optional[UserSession]:
        """
        Renew session with new expiry time.
        
        Args:
            session_id: Session ID
            duration_seconds: New session duration in seconds
            
        Returns:
            Renewed UserSession instance or None
        """
        session = await self.get_session(session_id)
        
        if not session or not session.is_valid:
            return None
        
        session.renew(duration_seconds)
        await self.db.commit()
        
        # Update cache
        if self.redis:
            await self._cache_session(session)
        
        return session

    async def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate a session.
        
        Args:
            session_id: Session ID
            
        Returns:
            True if session was invalidated
        """
        session = await self.get_session(session_id)
        
        if not session:
            return False
        
        session.invalidate()
        await self.db.commit()
        
        # Remove from cache
        if self.redis:
            await self._remove_cached_session(session_id)
        
        return True

    async def get_user_sessions(self, user_id: uuid.UUID) -> List[UserSession]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of active UserSession instances
        """
        return await UserSession.get_active_sessions_for_user(self.db, user_id)

    async def invalidate_all_user_sessions(self, user_id: uuid.UUID) -> int:
        """
        Invalidate all sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Number of sessions invalidated
        """
        # Get all active sessions first for cache cleanup
        sessions = await self.get_user_sessions(user_id)
        
        # Invalidate in database
        count = await UserSession.invalidate_all_user_sessions(self.db, user_id)
        await self.db.commit()
        
        # Remove from cache
        if self.redis:
            for session in sessions:
                await self._remove_cached_session(session.session_id)
        
        return count

    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        count = await UserSession.cleanup_expired_sessions(self.db)
        await self.db.commit()
        return count

    async def get_session_stats(self) -> dict:
        """
        Get session statistics.
        
        Returns:
            Dictionary with session statistics
        """
        now = datetime.utcnow()
        
        # Total active sessions
        active_sessions_stmt = select(UserSession).where(
            UserSession.is_active == True,
            UserSession.expires_at > now,
        )
        active_sessions_result = await self.db.execute(active_sessions_stmt)
        active_sessions = len(list(active_sessions_result.scalars().all()))
        
        # Sessions created today
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        today_sessions_stmt = select(UserSession).where(
            UserSession.created_at >= today_start
        )
        today_sessions_result = await self.db.execute(today_sessions_stmt)
        today_sessions = len(list(today_sessions_result.scalars().all()))
        
        # Expired sessions (not cleaned up yet)
        expired_sessions_stmt = select(UserSession).where(
            UserSession.expires_at <= now
        )
        expired_sessions_result = await self.db.execute(expired_sessions_stmt)
        expired_sessions = len(list(expired_sessions_result.scalars().all()))
        
        return {
            "active_sessions": active_sessions,
            "sessions_created_today": today_sessions,
            "expired_sessions": expired_sessions,
            "total_sessions": active_sessions + expired_sessions,
        }

    async def _cache_session(self, session: UserSession) -> None:
        """
        Cache session in Redis.
        
        Args:
            session: UserSession instance
        """
        if not self.redis:
            return
        
        try:
            cache_key = f"{settings.CACHE_SESSION_PREFIX}{session.session_id}"
            session_data = session.to_dict()
            
            # Calculate TTL based on session expiry
            ttl = session.get_remaining_lifetime() if session.is_valid else 60
            
            await self.redis.setex(cache_key, ttl, session_data)
        except Exception:
            # Don't fail if caching fails
            pass

    async def _get_cached_session(self, session_id: str) -> Optional[UserSession]:
        """
        Get session from Redis cache.
        
        Args:
            session_id: Session ID
            
        Returns:
            UserSession instance or None
        """
        if not self.redis:
            return None
        
        try:
            cache_key = f"{settings.CACHE_SESSION_PREFIX}{session_id}"
            session_data = await self.redis.get(cache_key)
            
            if not session_data:
                return None
            
            # Reconstruct session from cached data
            # Note: This is a simplified approach - in production you might want
            # to store serialized objects or use a more sophisticated caching strategy
            return None  # For now, always fall back to database
            
        except Exception:
            return None

    async def _remove_cached_session(self, session_id: str) -> None:
        """
        Remove session from Redis cache.
        
        Args:
            session_id: Session ID
        """
        if not self.redis:
            return
        
        try:
            cache_key = f"{settings.CACHE_SESSION_PREFIX}{session_id}"
            await self.redis.delete(cache_key)
        except Exception:
            # Don't fail if cache removal fails
            pass


# Dependency for getting session service
async def get_session_service(
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis),
) -> SessionService:
    """
    Get session service instance.
    
    Args:
        db: Database session
        redis: Redis client
        
    Returns:
        SessionService instance
    """
    return SessionService(db, redis)