"""Role model for role-based access control using SQLAlchemy 2.0 style."""

from typing import List, TYPE_CHECKING

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.scope import Scope
    from app.models.service_client import ServiceClient


class Role(BaseModel):
    """Role model for RBAC system using SQLAlchemy 2.0 style."""

    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique role name (e.g., 'admin', 'user', 'trader')",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable description of the role",
    )

    # Relationships
    users: Mapped[List["User"]] = relationship(
        "User",
        secondary="user_roles",
        back_populates="roles",
        lazy="selectin",
    )
    scopes: Mapped[List["Scope"]] = relationship(
        "Scope",
        secondary="role_scopes",
        back_populates="roles",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        """String representation of the role."""
        return f"<Role(name='{self.name}', description={repr(self.description)})>"

    async def has_scope(self, scope_name: str) -> bool:
        """
        Check if role has a specific scope.
        
        Args:
            scope_name: Name of the scope to check
            
        Returns:
            True if role has the scope
        """
        return any(scope.name == scope_name for scope in self.scopes)

    def get_scope_names(self) -> List[str]:
        """
        Get list of scope names for this role.
        
        Returns:
            List of scope names
        """
        return [scope.name for scope in self.scopes]

    def add_scope(self, scope: "Scope") -> None:
        """
        Add a scope to this role.
        
        Args:
            scope: Scope to add
        """
        if scope not in self.scopes:
            self.scopes.append(scope)

    def remove_scope(self, scope: "Scope") -> None:
        """
        Remove a scope from this role.
        
        Args:
            scope: Scope to remove
        """
        if scope in self.scopes:
            self.scopes.remove(scope)

    @classmethod
    async def get_by_name(cls, session, name: str):
        """
        Get role by name.
        
        Args:
            session: Database session
            name: Role name to search for
            
        Returns:
            Role instance or None
        """
        from sqlalchemy import select
        stmt = select(cls).where(cls.name == name)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    def validate(self) -> bool:
        """
        Validate role data.
        
        Returns:
            True if valid
            
        Raises:
            ValueError: If validation fails
        """
        if not self.name or len(self.name.strip()) == 0:
            raise ValueError("Role name cannot be empty")
        
        if len(self.name) > 50:
            raise ValueError("Role name cannot exceed 50 characters")
        
        return True

    def soft_delete(self) -> None:
        """
        Soft delete the role by marking it as inactive.
        """
        # For now, we'll use a simple approach
        # In a full implementation, you might add a deleted_at field
        self.name = f"deleted_{self.name}_{self.id}"

    async def get_permissions(self) -> List[str]:
        """
        Get all permissions for this role through scopes.
        
        Returns:
            List of permission strings
        """
        permissions = []
        for scope in self.scopes:
            if hasattr(scope, 'resource') and hasattr(scope, 'action'):
                if scope.resource and scope.action:
                    permissions.append(f"{scope.action}:{scope.resource}")
                else:
                    permissions.append(scope.name)
            else:
                permissions.append(scope.name)
        return permissions

    async def can_access_resource(self, resource: str, action: str = "read") -> bool:
        """
        Check if role can access a resource with specific action.
        
        Args:
            resource: Resource name
            action: Action to perform
            
        Returns:
            True if role can access the resource
        """
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

    def __eq__(self, other) -> bool:
        """Check equality based on name and id."""
        if not isinstance(other, Role):
            return False
        return self.name == other.name and self.id == other.id

    def __hash__(self) -> int:
        """Hash based on name and id."""
        return hash((self.name, self.id))

    @classmethod
    def get_default_roles(cls) -> List[dict]:
        """
        Get list of default role definitions.
        
        Returns:
            List of default role dictionaries
        """
        return [
            {"name": "user", "description": "Standard user role"},
            {"name": "admin", "description": "Administrator role"},
            {"name": "trader", "description": "Trading user role"},
            {"name": "service", "description": "Service client role"},
        ]

    def to_dict(self) -> dict:
        """Convert role to dictionary with scope information."""
        base_dict = super().to_dict()
        base_dict.update({
            "scopes": self.get_scope_names(),
            "scope_names": self.get_scope_names(),  # Add scope_names for test compatibility
            "user_count": len(self.users) if self.users else 0,
        })
        return base_dict