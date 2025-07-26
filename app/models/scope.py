"""Scope model for fine-grained access control using SQLAlchemy 2.0 style."""

from typing import List, TYPE_CHECKING

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.role import Role
    from app.models.service_client import ServiceClient


class Scope(BaseModel):
    """Scope model for OAuth2-style permissions using SQLAlchemy 2.0 style."""

    __tablename__ = "scopes"

    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique scope name (e.g., 'read:profile', 'write:trades')",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable description of what this scope allows",
    )
    resource: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        index=True,
        comment="Resource this scope applies to (e.g., 'profile', 'trades')",
    )

    # Relationships
    roles: Mapped[List["Role"]] = relationship(
        "Role",
        secondary="role_scopes",
        back_populates="scopes",
        lazy="selectin",
    )
    service_clients: Mapped[List["ServiceClient"]] = relationship(
        "ServiceClient",
        secondary="service_client_scopes",
        back_populates="scopes",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        """String representation of the scope."""
        return f"<Scope(id={self.id}, name='{self.name}')>"

    @property
    def action(self) -> str:
        """
        Extract action from scope name (e.g., 'read' from 'read:profile').
        
        Returns:
            Action part of the scope name
        """
        if ":" in self.name:
            return self.name.split(":", 1)[0]
        return self.name

    @property
    def resource_name(self) -> str:
        """
        Extract resource from scope name (e.g., 'profile' from 'read:profile').
        
        Returns:
            Resource part of the scope name
        """
        if ":" in self.name:
            return self.name.split(":", 1)[1]
        return self.resource or ""

    def is_read_scope(self) -> bool:
        """
        Check if this is a read scope.
        
        Returns:
            True if scope allows read access
        """
        return self.action.lower() in ["read", "get", "list", "view"]

    def is_write_scope(self) -> bool:
        """
        Check if this is a write scope.
        
        Returns:
            True if scope allows write access
        """
        return self.action.lower() in ["write", "create", "update", "delete", "modify"]

    def is_admin_scope(self) -> bool:
        """
        Check if this is an admin scope.
        
        Returns:
            True if scope provides admin access
        """
        return self.action.lower() in ["admin", "manage"] or "admin" in self.name.lower()

    @classmethod
    def get_default_scopes(cls) -> List[dict]:
        """
        Get list of default scopes to create.
        
        Returns:
            List of scope dictionaries with name, description, and resource
        """
        return [
            # User profile scopes
            {
                "name": "read:profile",
                "description": "Read user profile information",
                "resource": "profile",
            },
            {
                "name": "write:profile",
                "description": "Update user profile information",
                "resource": "profile",
            },
            # Trading scopes
            {
                "name": "read:trades",
                "description": "Read trading data and history",
                "resource": "trades",
            },
            {
                "name": "write:trades",
                "description": "Execute trades and modify trading data",
                "resource": "trades",
            },
            # Admin scopes
            {
                "name": "admin:users",
                "description": "Manage user accounts and permissions",
                "resource": "users",
            },
            {
                "name": "admin:clients",
                "description": "Manage service clients and API access",
                "resource": "clients",
            },
            {
                "name": "admin:system",
                "description": "System administration and configuration",
                "resource": "system",
            },
            # Service scopes
            {
                "name": "service:mt5",
                "description": "Access MT5 trading platform services",
                "resource": "mt5",
            },
            {
                "name": "service:api",
                "description": "Access internal API services",
                "resource": "api",
            },
        ]

    def to_dict(self) -> dict:
        """Convert scope to dictionary with additional metadata."""
        base_dict = super().to_dict()
        base_dict.update({
            "action": self.action,
            "resource_name": self.resource_name,
            "is_read": self.is_read_scope(),
            "is_write": self.is_write_scope(),
            "is_admin": self.is_admin_scope(),
            "role_count": len(self.roles) if self.roles else 0,
            "client_count": len(self.service_clients) if self.service_clients else 0,
        })
        return base_dict

    @classmethod
    def parse_scope_string(cls, scope_string: str) -> List[str]:
        """
        Parse space-separated scope string into list of scope names.
        
        Args:
            scope_string: Space-separated scope names
            
        Returns:
            List of individual scope names
        """
        if not scope_string:
            return []
        return [scope.strip() for scope in scope_string.split() if scope.strip()]

    @classmethod
    def validate_scope_format(cls, scope_name: str) -> bool:
        """
        Validate scope name format.
        
        Args:
            scope_name: Scope name to validate
            
        Returns:
            True if scope name is valid
        """
        if not scope_name or not isinstance(scope_name, str):
            return False
        
        # Basic validation: alphanumeric, colon, underscore, hyphen
        import re
        pattern = r"^[a-zA-Z0-9_:-]+$"
        return bool(re.match(pattern, scope_name))