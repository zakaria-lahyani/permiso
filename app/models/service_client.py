"""Service client model for service-to-service authentication using SQLAlchemy 2.0 style."""

from datetime import datetime
from typing import List, Optional, TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.scope import Scope


class ServiceClient(BaseModel):
    """Service client model for OAuth2 client credentials flow using SQLAlchemy 2.0 style."""

    __tablename__ = "service_clients"

    # Client identification
    client_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique client identifier for OAuth2",
    )
    client_secret_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Hashed client secret for authentication",
    )
    
    # Client metadata
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Human-readable client name",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Description of the client application",
    )
    client_type: Mapped[str] = mapped_column(
        String(20),
        default="confidential",
        nullable=False,
        comment="OAuth2 client type (confidential, public)",
    )
    
    # Client configuration
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        comment="Whether the client is active and can authenticate",
    )
    is_trusted: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether the client is trusted (can skip some validations)",
    )
    
    # Token configuration
    access_token_lifetime: Mapped[int] = mapped_column(
        default=3600,  # 1 hour
        nullable=False,
        comment="Access token lifetime in seconds",
    )
    refresh_token_lifetime: Mapped[int | None] = mapped_column(
        nullable=True,
        comment="Refresh token lifetime in seconds (null = no refresh tokens)",
    )
    
    # Rate limiting
    rate_limit_per_minute: Mapped[int] = mapped_column(
        default=60,
        nullable=False,
        comment="Maximum requests per minute",
    )
    rate_limit_per_hour: Mapped[int] = mapped_column(
        default=1000,
        nullable=False,
        comment="Maximum requests per hour",
    )
    
    # Tracking
    last_used: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last time client was used for authentication",
    )
    total_requests: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
        server_default="0",
        comment="Total number of requests made by this client",
    )
    
    def __init__(self, **kwargs):
        """Initialize ServiceClient with proper defaults."""
        # Set Python defaults for fields that might not be set by SQLAlchemy
        if 'total_requests' not in kwargs:
            kwargs['total_requests'] = 0
        super().__init__(**kwargs)
    
    # Contact information
    contact_email: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Contact email for the client owner",
    )
    website_url: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Website URL of the client application",
    )
    
    # Security
    allowed_ips: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Comma-separated list of allowed IP addresses/ranges",
    )
    webhook_url: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Webhook URL for notifications",
    )

    # Relationships
    scopes: Mapped[List["Scope"]] = relationship(
        "Scope",
        secondary="service_client_scopes",
        back_populates="service_clients",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        """String representation of the service client."""
        return f"<ServiceClient(id={self.id}, client_id='{self.client_id}', name='{self.name}')>"

    @property
    def can_authenticate(self) -> bool:
        """
        Check if client can currently authenticate.
        
        Returns:
            True if client is active and can authenticate
        """
        return self.is_active
    
    @property
    def enabled(self) -> bool:
        """
        Check if client is enabled (alias for is_active).
        
        Returns:
            True if client is enabled/active
        """
        return self.is_active

    @property
    def supports_refresh_tokens(self) -> bool:
        """
        Check if client supports refresh tokens.
        
        Returns:
            True if client has refresh token lifetime configured
        """
        return self.refresh_token_lifetime is not None and self.refresh_token_lifetime > 0

    def get_scope_names(self) -> List[str]:
        """
        Get list of scope names for this client.
        
        Returns:
            List of scope names
        """
        return [scope.name for scope in self.scopes]

    def has_scope(self, scope_name: str) -> bool:
        """
        Check if client has a specific scope.
        
        Args:
            scope_name: Name of the scope to check
            
        Returns:
            True if client has the scope
        """
        return scope_name in self.get_scope_names()

    def can_access_resource(self, resource: str, action: str = "read") -> bool:
        """
        Check if client can access a resource with specific action.
        
        Args:
            resource: Resource name (e.g., 'profile', 'trades')
            action: Action to perform (e.g., 'read', 'write', 'admin')
            
        Returns:
            True if client can access the resource
        """
        # Check for specific scope
        scope_name = f"{action}:{resource}"
        if self.has_scope(scope_name):
            return True
        
        # Check for admin scope on resource
        admin_scope = f"admin:{resource}"
        if self.has_scope(admin_scope):
            return True
        
        # Trusted clients with system admin scope can access everything
        if self.is_trusted and self.has_scope("admin:system"):
            return True
        
        return False

    def is_ip_allowed(self, ip_address: str) -> bool:
        """
        Check if IP address is allowed for this client.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is allowed (or no restrictions)
        """
        if not self.allowed_ips:
            return True  # No restrictions
        
        allowed_list = [ip.strip() for ip in self.allowed_ips.split(",")]
        
        # Simple IP matching (could be enhanced with CIDR support)
        for allowed_ip in allowed_list:
            if allowed_ip == ip_address:
                return True
            # Basic wildcard support
            if "*" in allowed_ip:
                pattern = allowed_ip.replace("*", ".*")
                import re
                if re.match(pattern, ip_address):
                    return True
        
        return False

    def update_usage(self) -> None:
        """Update usage statistics."""
        self.last_used = datetime.utcnow()
        self.total_requests += 1

    def get_rate_limits(self) -> dict:
        """
        Get rate limit configuration.
        
        Returns:
            Dictionary with rate limit settings
        """
        return {
            "per_minute": self.rate_limit_per_minute,
            "per_hour": self.rate_limit_per_hour,
        }

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert service client to dictionary.
        
        Args:
            include_sensitive: Whether to include sensitive fields
            
        Returns:
            Service client dictionary
        """
        base_dict = super().to_dict()
        
        # Remove sensitive fields by default
        if not include_sensitive:
            base_dict.pop("client_secret_hash", None)
        
        # Add computed fields
        base_dict.update({
            "can_authenticate": self.can_authenticate,
            "supports_refresh_tokens": self.supports_refresh_tokens,
            "scope_names": self.get_scope_names(),
            "rate_limits": self.get_rate_limits(),
        })
        
        return base_dict

    @classmethod
    def get_by_client_id(cls, session, client_id: str) -> Optional["ServiceClient"]:
        """
        Get service client by client ID.
        
        Args:
            session: Database session
            client_id: Client ID to search for
            
        Returns:
            ServiceClient instance or None
        """
        from sqlalchemy import select
        stmt = select(cls).where(cls.client_id == client_id)
        return session.scalar(stmt)

    @classmethod
    def get_active_clients(cls, session) -> List["ServiceClient"]:
        """
        Get all active service clients.
        
        Args:
            session: Database session
            
        Returns:
            List of active ServiceClient instances
        """
        from sqlalchemy import select
        stmt = select(cls).where(cls.is_active == True)
        return list(session.scalars(stmt))

    @classmethod
    def get_trusted_clients(cls, session) -> List["ServiceClient"]:
        """
        Get all trusted service clients.
        
        Args:
            session: Database session
            
        Returns:
            List of trusted ServiceClient instances
        """
        from sqlalchemy import select
        stmt = select(cls).where(cls.is_trusted == True, cls.is_active == True)
        return list(session.scalars(stmt))

    @classmethod
    def get_clients_by_scope(cls, session, scope_name: str) -> List["ServiceClient"]:
        """
        Get all clients that have a specific scope.
        
        Args:
            session: Database session
            scope_name: Scope name to filter by
            
        Returns:
            List of ServiceClient instances with the scope
        """
        from sqlalchemy import select
        from app.models.scope import Scope
        
        stmt = (
            select(cls)
            .join(cls.scopes)
            .where(Scope.name == scope_name, cls.is_active == True)
        )
        return list(session.scalars(stmt))

    @classmethod
    def create_default_clients(cls) -> List[dict]:
        """
        Get list of default service clients to create.
        
        Returns:
            List of client dictionaries
        """
        return [
            {
                "client_id": "mt5-service",
                "name": "MT5 Trading Service",
                "description": "MetaTrader 5 integration service for trading operations",
                "client_type": "confidential",
                "is_trusted": True,
                "access_token_lifetime": 7200,  # 2 hours
                "refresh_token_lifetime": 86400,  # 24 hours
                "rate_limit_per_minute": 120,
                "rate_limit_per_hour": 5000,
                "contact_email": "admin@trading.com",
            },
            {
                "client_id": "api-gateway",
                "name": "API Gateway Service",
                "description": "Internal API gateway for service routing",
                "client_type": "confidential",
                "is_trusted": True,
                "access_token_lifetime": 3600,  # 1 hour
                "rate_limit_per_minute": 300,
                "rate_limit_per_hour": 10000,
                "contact_email": "admin@trading.com",
            },
            {
                "client_id": "mobile-app",
                "name": "Mobile Trading App",
                "description": "Official mobile application for trading",
                "client_type": "public",
                "is_trusted": False,
                "access_token_lifetime": 1800,  # 30 minutes
                "refresh_token_lifetime": 604800,  # 7 days
                "rate_limit_per_minute": 60,
                "rate_limit_per_hour": 1000,
                "contact_email": "mobile@trading.com",
            },
        ]