"""Association tables for many-to-many relationships using SQLAlchemy 2.0 style."""

from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID

from app.models.base import Base

# User-Role association table
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    comment="Association table for user-role many-to-many relationship",
)

# Role-Scope association table
role_scopes = Table(
    "role_scopes",
    Base.metadata,
    Column("role_id", UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("scope_id", UUID(as_uuid=True), ForeignKey("scopes.id", ondelete="CASCADE"), primary_key=True),
    comment="Association table for role-scope many-to-many relationship",
)

# Service Client-Scope association table
service_client_scopes = Table(
    "service_client_scopes",
    Base.metadata,
    Column("service_client_id", UUID(as_uuid=True), ForeignKey("service_clients.id", ondelete="CASCADE"), primary_key=True),
    Column("scope_id", UUID(as_uuid=True), ForeignKey("scopes.id", ondelete="CASCADE"), primary_key=True),
    comment="Association table for service client-scope many-to-many relationship",
)