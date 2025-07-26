"""Database models package for Keystone authentication system."""

# Import base first
from app.models.base import Base, BaseModel

# Import association tables
from app.models.associations import (
    role_scopes,
    service_client_scopes,
    user_roles,
)

# Import all models
from app.models.refresh_token import RefreshToken
from app.models.role import Role
from app.models.scope import Scope
from app.models.service_client import ServiceClient
from app.models.user import User

# Export all models and tables for easy importing
__all__ = [
    # Base classes
    "Base",
    "BaseModel",
    # Association tables
    "user_roles",
    "role_scopes", 
    "service_client_scopes",
    # Models
    "User",
    "Role",
    "Scope",
    "ServiceClient",
    "RefreshToken",
]