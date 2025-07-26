"""Role and permission-related Pydantic schemas for API request/response models."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class ScopeInfo(BaseModel):
    """Scope information for role responses."""
    id: int
    name: str
    description: Optional[str] = None
    resource: str
    action: str

    class Config:
        from_attributes = True


class RoleBase(BaseModel):
    """Base role schema with common fields."""
    name: str = Field(..., min_length=2, max_length=50, description="Unique role name")
    description: Optional[str] = Field(None, max_length=500, description="Role description")


class RoleCreate(RoleBase):
    """Schema for creating a new role."""
    scope_ids: Optional[List[int]] = Field(default=[], description="List of scope IDs to assign")


class RoleUpdate(BaseModel):
    """Schema for updating an existing role."""
    name: Optional[str] = Field(None, min_length=2, max_length=50, description="Role name")
    description: Optional[str] = Field(None, max_length=500, description="Role description")
    scope_ids: Optional[List[int]] = Field(None, description="List of scope IDs to assign")


class RoleResponse(BaseModel):
    """Schema for role response."""
    id: int
    name: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    scopes: List[ScopeInfo] = []
    user_count: int = 0

    class Config:
        from_attributes = True


class RoleListResponse(BaseModel):
    """Schema for paginated role list response."""
    roles: List[RoleResponse]
    total: int
    page: int
    per_page: int
    pages: int


class RoleSearchParams(BaseModel):
    """Schema for role search parameters."""
    search: Optional[str] = Field(None, description="Search term for role name or description")
    scope_id: Optional[int] = Field(None, description="Filter by scope ID")
    page: int = Field(1, ge=1, description="Page number")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")


class RoleScopeUpdate(BaseModel):
    """Schema for updating role scopes."""
    scope_ids: List[int] = Field(..., description="List of scope IDs to assign")


class ScopeBase(BaseModel):
    """Base scope schema with common fields."""
    name: str = Field(..., min_length=2, max_length=100, description="Unique scope name")
    description: Optional[str] = Field(None, max_length=500, description="Scope description")
    resource: str = Field(..., max_length=50, description="Resource name (e.g., 'users', 'trades')")
    action: str = Field(..., max_length=20, description="Action name (e.g., 'read', 'write', 'admin')")


class ScopeCreate(ScopeBase):
    """Schema for creating a new scope."""
    pass


class ScopeUpdate(BaseModel):
    """Schema for updating an existing scope."""
    name: Optional[str] = Field(None, min_length=2, max_length=100, description="Scope name")
    description: Optional[str] = Field(None, max_length=500, description="Scope description")
    resource: Optional[str] = Field(None, max_length=50, description="Resource name")
    action: Optional[str] = Field(None, max_length=20, description="Action name")


class ScopeResponse(BaseModel):
    """Schema for scope response."""
    id: int
    name: str
    description: Optional[str] = None
    resource: str
    action: str
    created_at: datetime
    updated_at: datetime
    role_count: int = 0

    class Config:
        from_attributes = True


class ScopeListResponse(BaseModel):
    """Schema for paginated scope list response."""
    scopes: List[ScopeResponse]
    total: int
    page: int
    per_page: int
    pages: int


class ScopeSearchParams(BaseModel):
    """Schema for scope search parameters."""
    search: Optional[str] = Field(None, description="Search term for scope name or description")
    resource: Optional[str] = Field(None, description="Filter by resource")
    action: Optional[str] = Field(None, description="Filter by action")
    page: int = Field(1, ge=1, description="Page number")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")


class PermissionCheck(BaseModel):
    """Schema for permission check request."""
    user_id: int = Field(..., description="User ID to check permissions for")
    resource: str = Field(..., description="Resource to check access to")
    action: str = Field(..., description="Action to check permission for")


class PermissionCheckResponse(BaseModel):
    """Schema for permission check response."""
    allowed: bool = Field(..., description="Whether the action is allowed")
    reason: str = Field(..., description="Reason for the decision")
    matching_scopes: List[str] = Field(default=[], description="Scopes that granted access")
    user_roles: List[str] = Field(default=[], description="User's roles")


class BulkPermissionCheck(BaseModel):
    """Schema for bulk permission check request."""
    user_id: int = Field(..., description="User ID to check permissions for")
    permissions: List[dict] = Field(..., description="List of resource/action pairs to check")


class BulkPermissionCheckResponse(BaseModel):
    """Schema for bulk permission check response."""
    results: List[PermissionCheckResponse] = Field(..., description="Permission check results")
    user_roles: List[str] = Field(default=[], description="User's roles")
    user_scopes: List[str] = Field(default=[], description="User's scopes")


class RoleStats(BaseModel):
    """Schema for role statistics."""
    total_roles: int
    total_scopes: int
    most_common_roles: List[dict]  # [{"name": "user", "count": 150}, ...]
    least_used_scopes: List[dict]  # [{"name": "admin:system", "count": 2}, ...]


class DefaultRolesResponse(BaseModel):
    """Schema for default roles response."""
    roles: List[str] = Field(..., description="List of default role names")
    description: str = Field(..., description="Description of default roles")


class RoleHierarchy(BaseModel):
    """Schema for role hierarchy information."""
    role_id: int
    role_name: str
    parent_roles: List[str] = Field(default=[], description="Parent roles in hierarchy")
    child_roles: List[str] = Field(default=[], description="Child roles in hierarchy")
    inherited_scopes: List[str] = Field(default=[], description="Scopes inherited from parents")
    direct_scopes: List[str] = Field(default=[], description="Directly assigned scopes")


class RoleHierarchyResponse(BaseModel):
    """Schema for role hierarchy response."""
    hierarchies: List[RoleHierarchy]
    total_levels: int = Field(..., description="Number of hierarchy levels")


class ScopeUsageStats(BaseModel):
    """Schema for scope usage statistics."""
    scope_id: int
    scope_name: str
    role_count: int = Field(..., description="Number of roles using this scope")
    user_count: int = Field(..., description="Number of users with this scope")
    service_client_count: int = Field(..., description="Number of service clients with this scope")
    last_used: Optional[datetime] = Field(None, description="Last time scope was used")


class ScopeUsageResponse(BaseModel):
    """Schema for scope usage response."""
    usage_stats: List[ScopeUsageStats]
    total_scopes: int
    unused_scopes: int


class RoleAssignmentHistory(BaseModel):
    """Schema for role assignment history."""
    id: int
    user_id: int
    role_id: int
    action: str = Field(..., description="assigned or removed")
    assigned_by: int = Field(..., description="User ID who made the change")
    timestamp: datetime
    reason: Optional[str] = Field(None, description="Reason for the change")

    class Config:
        from_attributes = True


class RoleAssignmentHistoryResponse(BaseModel):
    """Schema for role assignment history response."""
    history: List[RoleAssignmentHistory]
    total: int
    page: int
    per_page: int


class EffectivePermissions(BaseModel):
    """Schema for effective permissions response."""
    user_id: int
    username: str
    roles: List[str] = Field(default=[], description="User's roles")
    scopes: List[str] = Field(default=[], description="User's effective scopes")
    permissions: dict = Field(default={}, description="Organized permissions by resource")
    is_superuser: bool = Field(False, description="Whether user is superuser")


class ResourcePermissions(BaseModel):
    """Schema for resource-specific permissions."""
    resource: str
    actions: List[str] = Field(default=[], description="Allowed actions on resource")
    scopes: List[str] = Field(default=[], description="Scopes granting access")


class UserPermissionsResponse(BaseModel):
    """Schema for user permissions response."""
    user_id: int
    username: str
    resources: List[ResourcePermissions] = Field(default=[], description="Permissions by resource")
    global_permissions: List[str] = Field(default=[], description="Global permissions")
    is_superuser: bool = Field(False, description="Whether user is superuser")