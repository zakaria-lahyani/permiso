"""Role and permission management API endpoints for permiso authentication system."""

import math
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from sqlalchemy.orm import selectinload

from app.config.database import get_db
from app.core.security import (
    get_current_user,
    require_admin,
    require_scopes
)
from app.core.exceptions import (
    ValidationError,
    ConflictError,
    NotFoundError
)
from app.models.user import User
from app.models.role import Role
from app.models.scope import Scope
from app.schemas.role import (
    RoleCreate,
    RoleUpdate,
    RoleResponse,
    RoleListResponse,
    RoleSearchParams,
    RoleScopeUpdate,
    ScopeCreate,
    ScopeUpdate,
    ScopeResponse,
    ScopeListResponse,
    ScopeSearchParams,
    PermissionCheck,
    PermissionCheckResponse,
    BulkPermissionCheck,
    BulkPermissionCheckResponse,
    RoleStats,
    DefaultRolesResponse,
    EffectivePermissions,
    UserPermissionsResponse,
    ResourcePermissions
)

router = APIRouter()


# Role Management Endpoints

@router.get("/", response_model=RoleListResponse)
async def list_roles(
    search: Optional[str] = Query(None, description="Search term for role name or description"),
    scope_id: Optional[int] = Query(None, description="Filter by scope ID"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    List roles with pagination and filtering.
    
    Requires admin role.
    """
    try:
        # Build query
        query = select(Role).options(selectinload(Role.scopes), selectinload(Role.users))
        
        # Apply filters
        conditions = []
        
        if search:
            search_term = f"%{search}%"
            conditions.append(
                or_(
                    Role.name.ilike(search_term),
                    Role.description.ilike(search_term)
                )
            )
        
        if scope_id is not None:
            query = query.join(Role.scopes).where(Scope.id == scope_id)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Get total count
        count_query = select(func.count(Role.id))
        if conditions:
            count_query = count_query.where(and_(*conditions))
        if scope_id is not None:
            count_query = count_query.select_from(Role).join(Role.scopes).where(Scope.id == scope_id)
        
        total_result = await db.execute(count_query)
        total = total_result.scalar()
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        # Execute query
        result = await db.execute(query)
        roles = result.scalars().all()
        
        # Calculate pages
        pages = math.ceil(total / per_page) if total > 0 else 1
        
        return RoleListResponse(
            roles=[RoleResponse.from_orm(role) for role in roles],
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.post("/", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    role_data: RoleCreate,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new role.
    
    Requires admin role.
    """
    try:
        # Check if role name already exists
        existing_role = await db.execute(
            select(Role).where(Role.name == role_data.name)
        )
        if existing_role.scalar_one_or_none():
            raise ConflictError("Role name already exists")
        
        # Create role
        role = Role(
            name=role_data.name,
            description=role_data.description
        )
        
        db.add(role)
        await db.flush()  # Get role ID
        
        # Assign scopes if provided
        if role_data.scope_ids:
            scopes_result = await db.execute(
                select(Scope).where(Scope.id.in_(role_data.scope_ids))
            )
            scopes = scopes_result.scalars().all()
            role.scopes.extend(scopes)
        
        await db.commit()
        await db.refresh(role)
        
        return RoleResponse.from_orm(role)
        
    except ConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "conflict", "error_description": str(e)}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: int,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Get role by ID.
    
    Requires admin role.
    """
    try:
        result = await db.execute(
            select(Role).options(
                selectinload(Role.scopes),
                selectinload(Role.users)
            ).where(Role.id == role_id)
        )
        role = result.scalar_one_or_none()
        
        if not role:
            raise NotFoundError(f"Role with ID {role_id} not found")
        
        return RoleResponse.from_orm(role)
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Role not found"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.put("/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: int,
    role_data: RoleUpdate,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Update role by ID.
    
    Requires admin role.
    """
    try:
        # Get role
        result = await db.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == role_id)
        )
        role = result.scalar_one_or_none()
        
        if not role:
            raise NotFoundError(f"Role with ID {role_id} not found")
        
        # Check if name is being changed and already exists
        if role_data.name and role_data.name != role.name:
            existing_role = await db.execute(
                select(Role).where(Role.name == role_data.name)
            )
            if existing_role.scalar_one_or_none():
                raise ConflictError("Role name already exists")
            role.name = role_data.name
        
        # Update fields
        if role_data.description is not None:
            role.description = role_data.description
        
        # Update scopes if provided
        if role_data.scope_ids is not None:
            scopes_result = await db.execute(
                select(Scope).where(Scope.id.in_(role_data.scope_ids))
            )
            scopes = scopes_result.scalars().all()
            role.scopes.clear()
            role.scopes.extend(scopes)
        
        await db.commit()
        await db.refresh(role)
        
        return RoleResponse.from_orm(role)
        
    except (NotFoundError, ConflictError) as e:
        status_code = status.HTTP_404_NOT_FOUND if isinstance(e, NotFoundError) else status.HTTP_409_CONFLICT
        error_type = "not_found" if isinstance(e, NotFoundError) else "conflict"
        raise HTTPException(
            status_code=status_code,
            detail={"error": error_type, "error_description": str(e)}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: int,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete role by ID.
    
    Requires admin role.
    """
    try:
        # Get role
        result = await db.execute(select(Role).where(Role.id == role_id))
        role = result.scalar_one_or_none()
        
        if not role:
            raise NotFoundError(f"Role with ID {role_id} not found")
        
        # Check if role is in use
        users_count = await db.execute(
            select(func.count(User.id)).select_from(User).join(User.roles).where(Role.id == role_id)
        )
        if users_count.scalar() > 0:
            raise ConflictError("Cannot delete role that is assigned to users")
        
        # Delete role
        await db.delete(role)
        await db.commit()
        
    except (NotFoundError, ConflictError) as e:
        status_code = status.HTTP_404_NOT_FOUND if isinstance(e, NotFoundError) else status.HTTP_409_CONFLICT
        error_type = "not_found" if isinstance(e, NotFoundError) else "conflict"
        raise HTTPException(
            status_code=status_code,
            detail={"error": error_type, "error_description": str(e)}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.put("/{role_id}/scopes", response_model=RoleResponse)
async def update_role_scopes(
    role_id: int,
    scope_data: RoleScopeUpdate,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Update role scopes.
    
    Requires admin role.
    """
    try:
        # Get role
        result = await db.execute(
            select(Role).options(selectinload(Role.scopes)).where(Role.id == role_id)
        )
        role = result.scalar_one_or_none()
        
        if not role:
            raise NotFoundError(f"Role with ID {role_id} not found")
        
        # Get scopes
        scopes_result = await db.execute(
            select(Scope).where(Scope.id.in_(scope_data.scope_ids))
        )
        scopes = scopes_result.scalars().all()
        
        # Update role scopes
        role.scopes.clear()
        role.scopes.extend(scopes)
        
        await db.commit()
        await db.refresh(role)
        
        return RoleResponse.from_orm(role)
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Role not found"}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


# Scope Management Endpoints

@router.get("/scopes/", response_model=ScopeListResponse)
async def list_scopes(
    search: Optional[str] = Query(None, description="Search term for scope name or description"),
    resource: Optional[str] = Query(None, description="Filter by resource"),
    action: Optional[str] = Query(None, description="Filter by action"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    List scopes with pagination and filtering.
    
    Requires admin role.
    """
    try:
        # Build query
        query = select(Scope).options(selectinload(Scope.roles))
        
        # Apply filters
        conditions = []
        
        if search:
            search_term = f"%{search}%"
            conditions.append(
                or_(
                    Scope.name.ilike(search_term),
                    Scope.description.ilike(search_term)
                )
            )
        
        if resource:
            conditions.append(Scope.resource == resource)
        
        if action:
            conditions.append(Scope.action == action)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Get total count
        count_query = select(func.count(Scope.id))
        if conditions:
            count_query = count_query.where(and_(*conditions))
        
        total_result = await db.execute(count_query)
        total = total_result.scalar()
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        # Execute query
        result = await db.execute(query)
        scopes = result.scalars().all()
        
        # Calculate pages
        pages = math.ceil(total / per_page) if total > 0 else 1
        
        return ScopeListResponse(
            scopes=[ScopeResponse.from_orm(scope) for scope in scopes],
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.post("/scopes/", response_model=ScopeResponse, status_code=status.HTTP_201_CREATED)
async def create_scope(
    scope_data: ScopeCreate,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new scope.
    
    Requires admin role.
    """
    try:
        # Check if scope name already exists
        existing_scope = await db.execute(
            select(Scope).where(Scope.name == scope_data.name)
        )
        if existing_scope.scalar_one_or_none():
            raise ConflictError("Scope name already exists")
        
        # Create scope
        scope = Scope(
            name=scope_data.name,
            description=scope_data.description,
            resource=scope_data.resource,
            action=scope_data.action
        )
        
        db.add(scope)
        await db.commit()
        await db.refresh(scope)
        
        return ScopeResponse.from_orm(scope)
        
    except ConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "conflict", "error_description": str(e)}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/scopes/{scope_id}", response_model=ScopeResponse)
async def get_scope(
    scope_id: int,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Get scope by ID.
    
    Requires admin role.
    """
    try:
        result = await db.execute(
            select(Scope).options(selectinload(Scope.roles)).where(Scope.id == scope_id)
        )
        scope = result.scalar_one_or_none()
        
        if not scope:
            raise NotFoundError(f"Scope with ID {scope_id} not found")
        
        return ScopeResponse.from_orm(scope)
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Scope not found"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.put("/scopes/{scope_id}", response_model=ScopeResponse)
async def update_scope(
    scope_id: int,
    scope_data: ScopeUpdate,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Update scope by ID.
    
    Requires admin role.
    """
    try:
        # Get scope
        result = await db.execute(select(Scope).where(Scope.id == scope_id))
        scope = result.scalar_one_or_none()
        
        if not scope:
            raise NotFoundError(f"Scope with ID {scope_id} not found")
        
        # Check if name is being changed and already exists
        if scope_data.name and scope_data.name != scope.name:
            existing_scope = await db.execute(
                select(Scope).where(Scope.name == scope_data.name)
            )
            if existing_scope.scalar_one_or_none():
                raise ConflictError("Scope name already exists")
            scope.name = scope_data.name
        
        # Update fields
        if scope_data.description is not None:
            scope.description = scope_data.description
        if scope_data.resource is not None:
            scope.resource = scope_data.resource
        if scope_data.action is not None:
            scope.action = scope_data.action
        
        await db.commit()
        await db.refresh(scope)
        
        return ScopeResponse.from_orm(scope)
        
    except (NotFoundError, ConflictError) as e:
        status_code = status.HTTP_404_NOT_FOUND if isinstance(e, NotFoundError) else status.HTTP_409_CONFLICT
        error_type = "not_found" if isinstance(e, NotFoundError) else "conflict"
        raise HTTPException(
            status_code=status_code,
            detail={"error": error_type, "error_description": str(e)}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.delete("/scopes/{scope_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scope(
    scope_id: int,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete scope by ID.
    
    Requires admin role.
    """
    try:
        # Get scope
        result = await db.execute(select(Scope).where(Scope.id == scope_id))
        scope = result.scalar_one_or_none()
        
        if not scope:
            raise NotFoundError(f"Scope with ID {scope_id} not found")
        
        # Check if scope is in use
        roles_count = await db.execute(
            select(func.count(Role.id)).select_from(Role).join(Role.scopes).where(Scope.id == scope_id)
        )
        if roles_count.scalar() > 0:
            raise ConflictError("Cannot delete scope that is assigned to roles")
        
        # Delete scope
        await db.delete(scope)
        await db.commit()
        
    except (NotFoundError, ConflictError) as e:
        status_code = status.HTTP_404_NOT_FOUND if isinstance(e, NotFoundError) else status.HTTP_409_CONFLICT
        error_type = "not_found" if isinstance(e, NotFoundError) else "conflict"
        raise HTTPException(
            status_code=status_code,
            detail={"error": error_type, "error_description": str(e)}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


# Permission Check Endpoints

@router.post("/permissions/check", response_model=PermissionCheckResponse)
async def check_permission(
    permission_check: PermissionCheck,
    current_user = Depends(require_scopes(["admin:permissions"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Check if user has permission for specific resource and action.
    
    Requires admin:permissions scope.
    """
    try:
        # Get user
        result = await db.execute(
            select(User).options(selectinload(User.roles).selectinload(Role.scopes))
            .where(User.id == permission_check.user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise NotFoundError(f"User with ID {permission_check.user_id} not found")
        
        # Check permission
        allowed = await user.can_access_resource(
            permission_check.resource,
            permission_check.action
        )
        
        # Get user roles and scopes for context
        user_roles = await user.get_role_names()
        user_scopes = await user.get_scopes()
        
        # Find matching scopes
        matching_scopes = []
        scope_name = f"{permission_check.action}:{permission_check.resource}"
        admin_scope = f"admin:{permission_check.resource}"
        system_admin_scope = "admin:system"
        
        if scope_name in user_scopes:
            matching_scopes.append(scope_name)
        if admin_scope in user_scopes:
            matching_scopes.append(admin_scope)
        if system_admin_scope in user_scopes and permission_check.action != "admin":
            matching_scopes.append(system_admin_scope)
        
        # Determine reason
        if user.is_superuser:
            reason = "Superuser access"
        elif matching_scopes:
            reason = f"Granted by scopes: {', '.join(matching_scopes)}"
        else:
            reason = "No matching permissions found"
        
        return PermissionCheckResponse(
            allowed=allowed,
            reason=reason,
            matching_scopes=matching_scopes,
            user_roles=user_roles
        )
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "User not found"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.post("/permissions/check-bulk", response_model=BulkPermissionCheckResponse)
async def check_bulk_permissions(
    bulk_check: BulkPermissionCheck,
    current_user = Depends(require_scopes(["admin:permissions"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Check multiple permissions for a user.
    
    Requires admin:permissions scope.
    """
    try:
        # Get user
        result = await db.execute(
            select(User).options(selectinload(User.roles).selectinload(Role.scopes))
            .where(User.id == bulk_check.user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise NotFoundError(f"User with ID {bulk_check.user_id} not found")
        
        # Get user context
        user_roles = await user.get_role_names()
        user_scopes = await user.get_scopes()
        
        # Check each permission
        results = []
        for permission in bulk_check.permissions:
            resource = permission.get("resource")
            action = permission.get("action")
            
            if not resource or not action:
                continue
            
            allowed = await user.can_access_resource(resource, action)
            
            # Find matching scopes
            matching_scopes = []
            scope_name = f"{action}:{resource}"
            admin_scope = f"admin:{resource}"
            system_admin_scope = "admin:system"
            
            if scope_name in user_scopes:
                matching_scopes.append(scope_name)
            if admin_scope in user_scopes:
                matching_scopes.append(admin_scope)
            if system_admin_scope in user_scopes and action != "admin":
                matching_scopes.append(system_admin_scope)
            
            # Determine reason
            if user.is_superuser:
                reason = "Superuser access"
            elif matching_scopes:
                reason = f"Granted by scopes: {', '.join(matching_scopes)}"
            else:
                reason = "No matching permissions found"
            
            results.append(PermissionCheckResponse(
                allowed=allowed,
                reason=reason,
                matching_scopes=matching_scopes,
                user_roles=user_roles
            ))
        
        return BulkPermissionCheckResponse(
            results=results,
            user_roles=user_roles,
            user_scopes=user_scopes
        )
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "User not found"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/permissions/user/{user_id}", response_model=UserPermissionsResponse)
async def get_user_permissions(
    user_id: int,
    current_user = Depends(require_scopes(["admin:permissions"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get all permissions for a specific user.
    
    Requires admin:permissions scope.
    """
    try:
        # Get user
        result = await db.execute(
            select(User).options(selectinload(User.roles).selectinload(Role.scopes))
            .where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise NotFoundError(f"User with ID {user_id} not found")
        
        # Get user scopes
        user_scopes = await user.get_scopes()
        
        # Organize permissions by resource
        resources = {}
        global_permissions = []
        
        for scope_name in user_scopes:
            if ":" in scope_name:
                action, resource = scope_name.split(":", 1)
                if resource not in resources:
                    resources[resource] = ResourcePermissions(
                        resource=resource,
                        actions=[],
                        scopes=[]
                    )
                resources[resource].actions.append(action)
                resources[resource].scopes.append(scope_name)
            else:
                global_permissions.append(scope_name)
        
        return UserPermissionsResponse(
            user_id=user.id,
            username=user.username,
            resources=list(resources.values()),
            global_permissions=global_permissions,
            is_superuser=user.is_superuser
        )
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "User not found"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


# Statistics and Utility Endpoints

@router.get("/stats", response_model=RoleStats)
async def get_role_stats(
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Get role and permission statistics.
    
    Requires admin role.
    """
    try:
        # Get total counts
        total_roles_result = await db.execute(select(func.count(Role.id)))
        total_scopes_result = await db.execute(select(func.count(Scope.id)))
        
        total_roles = total_roles_result.scalar()
        total_scopes = total_scopes_result.scalar()
        
        # Get most common roles (simplified query)
        roles_with_users = await db.execute(
            select(Role.name, func.count(User.id).label('user_count'))
            .select_from(Role)
            .outerjoin(Role.users)
            .group_by(Role.id, Role.name)
            .order_by(func.count(User.id).desc())
            .limit(5)
        )
        most_common_roles = [
            {"name": row[0], "count": row[1]}
            for row in roles_with_users.fetchall()
        ]
        
        # Get least used scopes (simplified query)
        scopes_with_roles = await db.execute(
            select(Scope.name, func.count(Role.id).label('role_count'))
            .select_from(Scope)
            .outerjoin(Scope.roles)
            .group_by(Scope.id, Scope.name)
            .order_by(func.count(Role.id).asc())
            .limit(5)
        )
        least_used_scopes = [
            {"name": row[0], "count": row[1]}
            for row in scopes_with_roles.fetchall()
        ]
        
        return RoleStats(
            total_roles=total_roles,
            total_scopes=total_scopes,
            most_common_roles=most_common_roles,
            least_used_scopes=least_used_scopes
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/defaults", response_model=DefaultRolesResponse)
async def get_default_roles(
    current_user = Depends(require_admin())
):
    """
    Get default role names and descriptions.
    
    Requires admin role.
    """
    default_roles = Role.get_default_roles()
    
    return DefaultRolesResponse(
        roles=default_roles,
        description="Default roles that can be created in the system"
    )
            