"""User session model for session management using SQLAlchemy 2.0 style."""

from datetime import datetime, timedelta
from typing import Optional, TYPE_CHECKING
from uuid import uuid4
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.user import User


class UserSession(BaseModel):
    """User session model for tracking active user sessions."""

    __tablename__ = "user_sessions"

    # Session identification
    session_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: str(uuid4()),
        comment="Unique session identifier",
    )
    
    # Session metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Session creation timestamp",
    )
    last_activity: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Last activity timestamp",
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Session expiration timestamp",
    )
    
    # Client information
    ip_address: Mapped[str] = mapped_column(
        String(45),  # IPv6 max length
        nullable=False,
        comment="Client IP address",
    )
    user_agent: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="User agent string",
    )
    
    # Session status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        comment="Whether session is active",
    )
    
    # Token references
    access_token_jti: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Current access token JTI",
    )
    refresh_token_jti: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Current refresh token JTI",
    )

    # Foreign key
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        comment="User who owns this session",
    )

    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="sessions",
        lazy="select",
    )

    def __repr__(self) -> str:
        """String representation of the session."""
        return f"<UserSession(id={self.id}, session_id='{self.session_id}', user_id={self.user_id})>"

    @property
    def is_expired(self) -> bool:
        """
        Check if session is expired.
        
        Returns:
            True if session is expired
        """
        return datetime.utcnow() > self.expires_at

    @property
    def is_valid(self) -> bool:
        """
        Check if session is valid (active and not expired).
        
        Returns:
            True if session is valid
        """
        return self.is_active and not self.is_expired

    @property
    def time_until_expiry(self) -> timedelta:
        """
        Get time until session expires.
        
        Returns:
            Time delta until expiration
        """
        return self.expires_at - datetime.utcnow()

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.utcnow()

    def extend_session(self, additional_seconds: int) -> None:
        """
        Extend session expiry time.
        
        Args:
            additional_seconds: Seconds to add to expiry
        """
        self.expires_at += timedelta(seconds=additional_seconds)

    def invalidate(self) -> None:
        """Invalidate the session."""
        self.is_active = False

    def renew(self, duration_seconds: int = 3600) -> None:
        """
        Renew session with new expiry time.
        
        Args:
            duration_seconds: New session duration in seconds
        """
        self.expires_at = datetime.utcnow() + timedelta(seconds=duration_seconds)
        self.update_activity()

    def to_dict(self) -> dict:
        """
        Convert session to dictionary.
        
        Returns:
            Session dictionary
        """
        base_dict = super().to_dict()
        
        # Add computed fields
        base_dict.update({
            "is_expired": self.is_expired,
            "is_valid": self.is_valid,
            "remaining_seconds": int(self.time_until_expiry.total_seconds()) if not self.is_expired else 0,
        })
        
        return base_dict

    @classmethod
    def create_session(
        cls,
        user_id: uuid.UUID,
        ip_address: str,
        user_agent: Optional[str] = None,
        duration_seconds: int = 3600,  # 1 hour default
        access_token_jti: Optional[str] = None,
        refresh_token_jti: Optional[str] = None,
    ) -> "UserSession":
        """
        Create a new user session.
        
        Args:
            user_id: User ID who owns the session
            ip_address: Client IP address
            user_agent: User agent string
            duration_seconds: Session duration in seconds
            access_token_jti: Access token JTI
            refresh_token_jti: Refresh token JTI
            
        Returns:
            New UserSession instance
        """
        expires_at = datetime.utcnow() + timedelta(seconds=duration_seconds)
        
        return cls(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
            access_token_jti=access_token_jti,
            refresh_token_jti=refresh_token_jti,
        )

    @classmethod
    async def get_by_session_id(cls, session, session_id: str) -> Optional["UserSession"]:
        """
        Get session by session ID.
        
        Args:
            session: Database session
            session_id: Session ID to search for
            
        Returns:
            UserSession instance or None
        """
        from sqlalchemy import select
        stmt = select(cls).where(cls.session_id == session_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def get_active_sessions_for_user(cls, session, user_id: uuid.UUID) -> list["UserSession"]:
        """
        Get all active sessions for a user.
        
        Args:
            session: Database session
            user_id: User ID to search for
            
        Returns:
            List of active UserSession instances
        """
        from sqlalchemy import select
        now = datetime.utcnow()
        stmt = select(cls).where(
            cls.user_id == user_id,
            cls.is_active == True,
            cls.expires_at > now,
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    @classmethod
    async def cleanup_expired_sessions(cls, session) -> int:
        """
        Clean up expired sessions.
        
        Args:
            session: Database session
            
        Returns:
            Number of sessions cleaned up
        """
        from sqlalchemy import delete
        
        now = datetime.utcnow()
        stmt = delete(cls).where(cls.expires_at < now)
        result = await session.execute(stmt)
        return result.rowcount or 0

    @classmethod
    async def invalidate_all_user_sessions(cls, session, user_id: uuid.UUID) -> int:
        """
        Invalidate all sessions for a user.
        
        Args:
            session: Database session
            user_id: User ID
            
        Returns:
            Number of sessions invalidated
        """
        from sqlalchemy import update
        
        stmt = (
            update(cls)
            .where(cls.user_id == user_id, cls.is_active == True)
            .values(is_active=False)
        )
        result = await session.execute(stmt)
        return result.rowcount or 0