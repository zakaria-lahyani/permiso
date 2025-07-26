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
        return f"<Scope(name='{self.name}', resource={repr(self.resource)})>"

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

    @classmethod
    async def get_by_name(cls, session, name: str):
        """
        Get scope by name.
        
        Args:
            session: Database session
            name: Scope name to search for
            
        Returns:
            Scope instance or None
        """
        from sqlalchemy import select
        stmt = select(cls).where(cls.name == name)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    def validate(self) -> bool:
        """
        Validate scope data.
        
        Returns:
            True if valid
            
        Raises:
            ValueError: If validation fails
        """
        if not self.name or len(self.name.strip()) == 0:
            raise ValueError("Scope name cannot be empty")
        
        if len(self.name) > 100:
            raise ValueError("Scope name cannot exceed 100 characters")
        
        if not self.validate_scope_format(self.name):
            raise ValueError("Invalid scope name format")
        
        return True

    def parse_name(self) -> dict:
        """
        Parse scope name into components.
        
        Returns:
            Dictionary with action and resource components
        """
        if ":" in self.name:
            action, resource = self.name.split(":", 1)
            return {"action": action, "resource": resource}
        return {"action": self.name, "resource": None}

    def get_action(self) -> str:
        """
        Get the action part of the scope.
        
        Returns:
            Action string
        """
        return self.action

    def get_resource(self) -> str:
        """
        Get the resource part of the scope.
        
        Returns:
            Resource string
        """
        return self.resource_name

    def matches_pattern(self, pattern: str) -> bool:
        """
        Check if scope matches a pattern.
        
        Args:
            pattern: Pattern to match against
            
        Returns:
            True if scope matches pattern
        """
        import re
        # Convert pattern to regex (simple wildcard support)
        regex_pattern = pattern.replace("*", ".*").replace("?", ".")
        return bool(re.match(f"^{regex_pattern}$", self.name))

    def implies(self, other_scope: str) -> bool:
        """
        Check if this scope implies another scope.
        
        Args:
            other_scope: Other scope name to check
            
        Returns:
            True if this scope implies the other
        """
        # Admin scopes imply read/write scopes for the same resource
        if self.is_admin_scope():
            if ":" in self.name and ":" in other_scope:
                _, self_resource = self.name.split(":", 1)
                other_action, other_resource = other_scope.split(":", 1)
                if self_resource == other_resource:
                    return True
        
        # System admin implies everything
        if self.name == "admin:system":
            return True
        
        return False

    def get_permission_level(self) -> str:
        """
        Get permission level of the scope.
        
        Returns:
            Permission level string
        """
        if self.is_admin_scope():
            return "admin"
        elif self.is_write_scope():
            return "write"
        elif self.is_read_scope():
            return "read"
        else:
            return "custom"

    @classmethod
    async def get_admin_scopes(cls, session):
        """
        Get all admin scopes.
        
        Args:
            session: Database session
            
        Returns:
            List of admin scopes
        """
        from sqlalchemy import select
        stmt = select(cls).where(cls.name.like("admin:%"))
        result = await session.execute(stmt)
        return result.scalars().all()

    def serialize(self) -> dict:
        """
        Serialize scope to dictionary.
        
        Returns:
            Serialized scope data
        """
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "resource": self.resource,
            "action": self.action,
            "resource_name": self.resource_name,
            "is_read": self.is_read_scope(),
            "is_write": self.is_write_scope(),
            "is_admin": self.is_admin_scope(),
            "permission_level": self.get_permission_level(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def get_security_level(self) -> str:
        """
        Get security level classification.
        
        Returns:
            Security level string
        """
        if self.is_admin_scope():
            return "restricted"
        elif self.is_write_scope():
            return "protected"
        elif self.is_read_scope():
            return "public"
        else:
            return "custom"

    def __eq__(self, other) -> bool:
        """Check equality based on name and id."""
        if not isinstance(other, Scope):
            return False
        return self.name == other.name and self.id == other.id

    def __hash__(self) -> int:
        """Hash based on name and id."""
        return hash((self.name, self.id))