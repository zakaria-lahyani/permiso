"""Refresh token model for JWT token management using SQLAlchemy 2.0 style."""

from datetime import datetime, timedelta
from typing import Optional, TYPE_CHECKING
from uuid import uuid4
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.user import User


class RefreshToken(BaseModel):
    """Refresh token model for JWT token rotation using SQLAlchemy 2.0 style."""

    __tablename__ = "refresh_tokens"

    # Token identification
    token_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: str(uuid4()),
        comment="Unique token identifier (JTI claim)",
    )
    token_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Hashed refresh token for security",
    )
    
    # Token metadata
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Token expiration timestamp",
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Token issuance timestamp",
    )
    
    # Token status
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether the token has been revoked",
    )
    is_used: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether the token has been used for refresh",
    )
    
    # Client information
    client_ip: Mapped[str | None] = mapped_column(
        String(45),  # IPv6 max length
        nullable=True,
        comment="IP address where token was issued",
    )
    user_agent: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="User agent string from token request",
    )
    
    # Token family for rotation
    token_family: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment="Token family ID for rotation tracking",
    )
    parent_token_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Parent token ID in rotation chain",
    )
    
    # Usage tracking
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last time token was used",
    )
    use_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
        server_default="0",
        comment="Number of times token has been used",
    )
    
    def __init__(self, **kwargs):
        """Initialize RefreshToken with proper defaults."""
        # Set Python defaults for fields that might not be set by SQLAlchemy
        if 'use_count' not in kwargs:
            kwargs['use_count'] = 0
        super().__init__(**kwargs)
    
    # Revocation details
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When token was revoked",
    )
    revocation_reason: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="Reason for token revocation",
    )

    # Foreign key
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        comment="User who owns this refresh token",
    )

    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="refresh_tokens",
        lazy="select",
    )

    def __repr__(self) -> str:
        """String representation of the refresh token."""
        return f"<RefreshToken(id={self.id}, token_id='{self.token_id}', user_id={self.user_id})>"

    @property
    def jti(self) -> str:
        """
        Get JWT ID (JTI) for this token.
        
        Returns:
            Token ID as JTI
        """
        return self.token_id

    @property
    def is_expired(self) -> bool:
        """
        Check if token is expired.
        
        Returns:
            True if token is expired
        """
        from datetime import timezone
        now = datetime.now(timezone.utc)
        return now > self.expires_at

    @property
    def is_valid(self) -> bool:
        """
        Check if token is valid (not expired, revoked, or used).
        
        Returns:
            True if token is valid
        """
        return not (self.is_expired or self.is_revoked or self.is_used)

    @property
    def time_until_expiry(self) -> timedelta:
        """
        Get time until token expires.
        
        Returns:
            Time delta until expiration
        """
        from datetime import timezone
        now = datetime.now(timezone.utc)
        return self.expires_at - now

    def is_near_expiry(self, threshold_minutes: int = 60) -> bool:
        """
        Check if token is near expiry.
        
        Args:
            threshold_minutes: Minutes before expiry to consider "near"
            
        Returns:
            True if token expires within threshold
        """
        if self.is_expired:
            return True
        return self.time_until_expiry.total_seconds() < (threshold_minutes * 60)

    def mark_as_used(self) -> None:
        """Mark token as used and update usage statistics."""
        from datetime import timezone
        self.is_used = True
        self.last_used_at = datetime.now(timezone.utc)
        self.use_count += 1

    def revoke(self, reason: str = "manual") -> None:
        """
        Revoke the token.
        
        Args:
            reason: Reason for revocation
        """
        from datetime import timezone
        self.is_revoked = True
        self.revoked_at = datetime.now(timezone.utc)
        self.revocation_reason = reason

    def extend_expiry(self, additional_seconds: int) -> None:
        """
        Extend token expiry time.
        
        Args:
            additional_seconds: Seconds to add to expiry
        """
        self.expires_at += timedelta(seconds=additional_seconds)

    def get_remaining_lifetime(self) -> int:
        """
        Get remaining lifetime in seconds.
        
        Returns:
            Remaining seconds until expiry (0 if expired)
        """
        if self.is_expired:
            return 0
        return int(self.time_until_expiry.total_seconds())

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert refresh token to dictionary.
        
        Args:
            include_sensitive: Whether to include sensitive fields
            
        Returns:
            Refresh token dictionary
        """
        base_dict = super().to_dict()
        
        # Remove sensitive fields by default
        if not include_sensitive:
            base_dict.pop("token_hash", None)
        
        # Add computed fields
        base_dict.update({
            "is_expired": self.is_expired,
            "is_valid": self.is_valid,
            "remaining_seconds": self.get_remaining_lifetime(),
            "is_near_expiry": self.is_near_expiry(),
        })
        
        return base_dict

    @classmethod
    def create_token(
        cls,
        user_id: uuid.UUID,
        token_hash: str,
        expires_in_seconds: int = 604800,  # 7 days
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        token_family: Optional[str] = None,
        parent_token_id: Optional[str] = None,
    ) -> "RefreshToken":
        """
        Create a new refresh token.
        
        Args:
            user_id: User ID who owns the token
            token_hash: Hashed token value
            expires_in_seconds: Token lifetime in seconds
            client_ip: Client IP address
            user_agent: User agent string
            token_family: Token family for rotation
            parent_token_id: Parent token in rotation chain
            
        Returns:
            New RefreshToken instance
        """
        from datetime import timezone
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
        
        return cls(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            client_ip=client_ip,
            user_agent=user_agent,
            token_family=token_family or str(uuid4()),
            parent_token_id=parent_token_id,
        )

    @classmethod
    def create_for_user(
        cls,
        user: "User",
        client_id: Optional[str] = None,
        scope: Optional[str] = None,
        expires_in_seconds: int = 604800,  # 7 days
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> "RefreshToken":
        """
        Create a new refresh token for a user.
        
        Args:
            user: User instance
            client_id: Client ID (optional)
            scope: Token scope (optional, for compatibility)
            expires_in_seconds: Token lifetime in seconds
            client_ip: Client IP address
            user_agent: User agent string
            
        Returns:
            New RefreshToken instance
        """
        import hashlib
        import secrets
        
        # Generate a secure token
        token_value = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token_value.encode()).hexdigest()
        
        from datetime import timezone
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
        
        return cls(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            client_ip=client_ip,
            user_agent=user_agent,
            token_family=str(uuid4()),
        )

    @classmethod
    def create_for_service_client(
        cls,
        service_client,
        expires_in_seconds: int = 604800,  # 7 days
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> "RefreshToken":
        """
        Create a new refresh token for a service client.
        
        Args:
            service_client: ServiceClient instance
            expires_in_seconds: Token lifetime in seconds
            client_ip: Client IP address
            user_agent: User agent string
            
        Returns:
            New RefreshToken instance
        """
        import hashlib
        import secrets
        
        # Generate a secure token
        token_value = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token_value.encode()).hexdigest()
        
        from datetime import timezone
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
        
        # For service clients, we'll use the service client's ID as user_id
        # This is a simplified implementation - in production you might want a separate table
        return cls(
            user_id=service_client.id,  # Use service client's UUID as user_id
            token_hash=token_hash,
            expires_at=expires_at,
            client_ip=client_ip,
            user_agent=user_agent,
            token_family=str(uuid4()),
        )

    @classmethod
    def get_by_token_id(cls, session, token_id: str) -> Optional["RefreshToken"]:
        """
        Get refresh token by token ID.
        
        Args:
            session: Database session
            token_id: Token ID to search for
            
        Returns:
            RefreshToken instance or None
        """
        from sqlalchemy import select
        stmt = select(cls).where(cls.token_id == token_id)
        return session.scalar(stmt)

    @classmethod
    def get_by_token_hash(cls, session, token_hash: str) -> Optional["RefreshToken"]:
        """
        Get refresh token by token hash.
        
        Args:
            session: Database session
            token_hash: Token hash to search for
            
        Returns:
            RefreshToken instance or None
        """
        from sqlalchemy import select
        stmt = select(cls).where(cls.token_hash == token_hash)
        return session.scalar(stmt)

    @classmethod
    def get_valid_tokens_for_user(cls, session, user_id: uuid.UUID) -> list["RefreshToken"]:
        """
        Get all valid refresh tokens for a user.
        
        Args:
            session: Database session
            user_id: User ID to search for
            
        Returns:
            List of valid RefreshToken instances
        """
        from sqlalchemy import select
        from datetime import timezone
        now = datetime.now(timezone.utc)
        stmt = select(cls).where(
            cls.user_id == user_id,
            cls.is_revoked == False,
            cls.is_used == False,
            cls.expires_at > now,
        )
        return list(session.scalars(stmt))

    @classmethod
    def get_tokens_by_family(cls, session, token_family: str) -> list["RefreshToken"]:
        """
        Get all tokens in a token family.
        
        Args:
            session: Database session
            token_family: Token family ID
            
        Returns:
            List of RefreshToken instances in the family
        """
        from sqlalchemy import select
        stmt = select(cls).where(cls.token_family == token_family)
        return list(session.scalars(stmt))

    @classmethod
    def revoke_all_for_user(cls, session, user_id: uuid.UUID, reason: str = "logout") -> int:
        """
        Revoke all refresh tokens for a user.
        
        Args:
            session: Database session
            user_id: User ID
            reason: Revocation reason
            
        Returns:
            Number of tokens revoked
        """
        from sqlalchemy import select, update
        
        # Get count of tokens to revoke
        count_stmt = select(func.count(cls.id)).where(
            cls.user_id == user_id,
            cls.is_revoked == False,
        )
        count = session.scalar(count_stmt) or 0
        
        # Revoke tokens
        update_stmt = (
            update(cls)
            .where(cls.user_id == user_id, cls.is_revoked == False)
            .values(
                is_revoked=True,
                revoked_at=func.now(),
                revocation_reason=reason,
            )
        )
        session.execute(update_stmt)
        
        return count

    @classmethod
    def revoke_token_family(cls, session, token_family: str, reason: str = "rotation") -> int:
        """
        Revoke all tokens in a token family.
        
        Args:
            session: Database session
            token_family: Token family ID
            reason: Revocation reason
            
        Returns:
            Number of tokens revoked
        """
        from sqlalchemy import select, update
        
        # Get count of tokens to revoke
        count_stmt = select(func.count(cls.id)).where(
            cls.token_family == token_family,
            cls.is_revoked == False,
        )
        count = session.scalar(count_stmt) or 0
        
        # Revoke tokens
        update_stmt = (
            update(cls)
            .where(cls.token_family == token_family, cls.is_revoked == False)
            .values(
                is_revoked=True,
                revoked_at=func.now(),
                revocation_reason=reason,
            )
        )
        session.execute(update_stmt)
        
        return count

    @classmethod
    def cleanup_expired_tokens(cls, session) -> int:
        """
        Clean up expired refresh tokens.
        
        Args:
            session: Database session
            
        Returns:
            Number of tokens cleaned up
        """
        from sqlalchemy import delete
        
        from datetime import timezone
        now = datetime.now(timezone.utc)
        stmt = delete(cls).where(cls.expires_at < now)
        result = session.execute(stmt)
        return result.rowcount or 0