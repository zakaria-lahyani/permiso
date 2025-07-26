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
        return f"<Role(id={self.id}, name='{self.name}')>"

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
    def get_default_roles(cls) -> List[str]:
        """
        Get list of default role names.
        
        Returns:
            List of default role names
        """
        return ["user", "admin", "trader", "service"]

    def to_dict(self) -> dict:
        """Convert role to dictionary with scope information."""
        base_dict = super().to_dict()
        base_dict.update({
            "scopes": self.get_scope_names(),
            "scope_names": self.get_scope_names(),  # Add scope_names for test compatibility
            "user_count": len(self.users) if self.users else 0,
        })
        return base_dict