"""User model for authentication and authorization using SQLAlchemy 2.0 style."""

from datetime import datetime
from typing import List, Optional, TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.role import Role
    from app.models.refresh_token import RefreshToken
    from app.models.session import UserSession


class User(BaseModel):
    """User model for authentication and authorization using SQLAlchemy 2.0 style."""

    __tablename__ = "users"

    # Basic user information
    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique username for login",
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="User's email address",
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Argon2 hashed password",
    )
    
    # Profile information
    first_name: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="User's first name",
    )
    last_name: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="User's last name",
    )
    display_name: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="Display name for UI",
    )
    bio: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="User biography or description",
    )
    
    # Account status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        server_default="true",
        comment="Whether the user account is active",
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether the user's email is verified",
    )
    is_superuser: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether the user has superuser privileges",
    )
    
    # Security and tracking
    last_login: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last login timestamp",
    )
    failed_login_attempts: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
        server_default="0",
        comment="Number of consecutive failed login attempts",
    )
    
    def __init__(self, **kwargs):
        """Initialize User with proper defaults."""
        # Set Python defaults for fields that might not be set by SQLAlchemy
        if 'failed_login_attempts' not in kwargs:
            kwargs['failed_login_attempts'] = 0
        if 'is_active' not in kwargs:
            kwargs['is_active'] = True
        if 'is_verified' not in kwargs:
            kwargs['is_verified'] = False
        if 'is_superuser' not in kwargs:
            kwargs['is_superuser'] = False
        super().__init__(**kwargs)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Account locked until this timestamp",
    )
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="When password was last changed",
    )
    
    # Email verification
    email_verification_token: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Token for email verification",
    )
    email_verification_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When email verification was sent",
    )
    
    # Password reset
    password_reset_token: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Token for password reset",
    )
    password_reset_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When password reset was sent",
    )

    # Relationships
    roles: Mapped[List["Role"]] = relationship(
        "Role",
        secondary="user_roles",
        back_populates="users",
        lazy="selectin",
    )
    refresh_tokens: Mapped[List["RefreshToken"]] = relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )
    sessions: Mapped[List["UserSession"]] = relationship(
        "UserSession",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def __repr__(self) -> str:
        """String representation of the user."""
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"

    @property
    def full_name(self) -> str:
        """
        Get user's full name.
        
        Returns:
            Full name or display name or username as fallback
        """
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.display_name:
            return self.display_name
        return self.username

    @property
    def is_locked(self) -> bool:
        """
        Check if user account is currently locked.
        
        Returns:
            True if account is locked
        """
        if not self.locked_until:
            return False
        return datetime.utcnow() < self.locked_until

    @property
    def can_login(self) -> bool:
        """
        Check if user can currently log in.
        
        Returns:
            True if user can log in
        """
        return bool(self.is_active and not self.is_locked)

    async def get_scopes(self) -> List[str]:
        """
        Get all scopes available to this user through their roles.
        
        Returns:
            List of scope names
        """
        scopes = set()
        for role in self.roles:
            for scope in role.scopes:
                scopes.add(scope.name)
        return list(scopes)

    async def get_role_names(self) -> List[str]:
        """
        Get all role names for this user.
        
        Returns:
            List of role names
        """
        return [role.name for role in self.roles]

    async def has_scope(self, scope_name: str) -> bool:
        """
        Check if user has a specific scope.
        
        Args:
            scope_name: Name of the scope to check
            
        Returns:
            True if user has the scope
        """
        scopes = await self.get_scopes()
        return scope_name in scopes

    async def has_role(self, role_name: str) -> bool:
        """
        Check if user has a specific role.
        
        Args:
            role_name: Name of the role to check
            
        Returns:
            True if user has the role
        """
        return any(role.name == role_name for role in self.roles)

    async def is_admin(self) -> bool:
        """
        Check if user has admin privileges.
        
        Returns:
            True if user is superuser or has admin role
        """
        if self.is_superuser:
            return True
        return await self.has_role("admin")

    async def can_access_resource(self, resource: str, action: str = "read", context: dict = None) -> bool:
        """
        Check if user can access a resource with specific action.
        
        Args:
            resource: Resource name (e.g., 'profile', 'trades')
            action: Action to perform (e.g., 'read', 'write', 'admin')
            context: Additional context for access control (e.g., {'user_id': 'target-user-id'})
            
        Returns:
            True if user can access the resource
        """
        # Superusers can access everything
        if self.is_superuser:
            return True
        
        # Special handling for sensitive resources that users should never modify themselves
        sensitive_resources = ["roles", "permissions", "scopes"]
        if resource in sensitive_resources and action in ["write", "admin"]:
            # Only admins can modify roles/permissions/scopes, even their own
            if not await self.has_scope("admin:users") and not await self.has_scope("admin:system"):
                return False
        
        # Check resource ownership if context provided
        if context and "user_id" in context:
            target_user_id = context["user_id"]
            # Users can access their own resources (except sensitive ones handled above)
            if str(self.id) == str(target_user_id):
                # For sensitive resources, we already checked admin permissions above
                if resource not in sensitive_resources or action == "read":
                    return True
            # For other users' resources, need admin permissions
            if not await self.has_scope("admin:users") and not await self.has_scope("admin:system"):
                return False
        
        # Check for specific scope
        scope_name = f"{action}:{resource}"
        if await self.has_scope(scope_name):
            return True
        
        # Check for admin scope on resource
        admin_scope = f"admin:{resource}"
        if await self.has_scope(admin_scope):
            return True
        
        # Check for general admin scope
        if action != "admin" and await self.has_scope("admin:system"):
            return True
        
        return False

    def update_last_login(self) -> None:
        """Update last login timestamp and reset failed attempts."""
        self.last_login = datetime.utcnow()
        self.failed_login_attempts = 0
        self.locked_until = None

    def increment_failed_login(self, max_attempts: int = 5, lockout_minutes: int = 30) -> None:
        """
        Increment failed login attempts and lock account if needed.
        
        Args:
            max_attempts: Maximum failed attempts before lockout
            lockout_minutes: Minutes to lock account
        """
        self.failed_login_attempts += 1
        
        if self.failed_login_attempts >= max_attempts:
            from datetime import timedelta
            self.locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)

    def reset_failed_logins(self) -> None:
        """Reset failed login attempts and unlock account."""
        self.failed_login_attempts = 0
        self.locked_until = None

    def set_password_reset_token(self, token: str) -> None:
        """
        Set password reset token and timestamp.
        
        Args:
            token: Password reset token
        """
        self.password_reset_token = token
        self.password_reset_sent_at = datetime.utcnow()

    def clear_password_reset_token(self) -> None:
        """Clear password reset token and timestamp."""
        self.password_reset_token = None
        self.password_reset_sent_at = None

    def set_email_verification_token(self, token: str) -> None:
        """
        Set email verification token and timestamp.
        
        Args:
            token: Email verification token
        """
        self.email_verification_token = token
        self.email_verification_sent_at = datetime.utcnow()

    def verify_email(self) -> None:
        """Mark email as verified and clear verification token."""
        self.is_verified = True
        self.email_verification_token = None
        self.email_verification_sent_at = None

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert user to dictionary.
        
        Args:
            include_sensitive: Whether to include sensitive fields
            
        Returns:
            User dictionary
        """
        base_dict = super().to_dict()
        
        # Remove sensitive fields by default
        if not include_sensitive:
            sensitive_fields = [
                "password_hash",
                "email_verification_token",
                "password_reset_token",
            ]
            for field in sensitive_fields:
                base_dict.pop(field, None)
        
        # Add computed fields - ensure boolean values are properly set
        # Note: For async methods, we provide sync alternatives or skip them
        try:
            role_names = [role.name for role in self.roles] if self.roles else []
        except:
            role_names = []
            
        try:
            # For scope_names, we need to access role.scopes which might cause issues
            # So we'll provide a basic implementation or skip it
            scope_names = []
            if self.roles:
                for role in self.roles:
                    try:
                        for scope in role.scopes:
                            scope_names.append(scope.name)
                    except:
                        pass
        except:
            scope_names = []
        
        base_dict.update({
            "full_name": self.full_name,
            "is_locked": bool(self.is_locked),
            "can_login": bool(self.can_login),
            "is_admin": bool(self.is_superuser),  # Use sync field instead of async method
            "role_names": role_names,
            "scope_names": scope_names,
        })
        
        return base_dict

    @classmethod
    async def get_by_username(cls, session, username: str) -> Optional["User"]:
        """
        Get user by username.
        
        Args:
            session: Database session
            username: Username to search for
            
        Returns:
            User instance or None
        """
        from sqlalchemy import select
        stmt = select(cls).where(cls.username == username)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def get_by_email(cls, session, email: str) -> Optional["User"]:
        """
        Get user by email.
        
        Args:
            session: Database session
            email: Email to search for
            
        Returns:
            User instance or None
        """
        from sqlalchemy import select
        stmt = select(cls).where(cls.email == email)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def get_by_username_or_email(cls, session, identifier: str) -> Optional["User"]:
        """
        Get user by username or email.
        
        Args:
            session: Database session
            identifier: Username or email to search for
            
        Returns:
            User instance or None
        """
        from sqlalchemy import select, or_
        stmt = select(cls).where(
            or_(cls.username == identifier, cls.email == identifier)
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()