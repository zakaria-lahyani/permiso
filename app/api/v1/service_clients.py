"""Service client management API endpoints for Keystone authentication system."""

import math
import secrets
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from sqlalchemy.orm import selectinload

from app.config.database import get_db
from app.core.password import hash_password, verify_password
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
from app.models.service_client import ServiceClient
from app.models.scope import Scope
from app.schemas.service_client import (
    ServiceClientCreate,
    ServiceClientUpdate,
    ServiceClientResponse,
    ServiceClientCreateResponse,
    ServiceClientListResponse,
    ServiceClientSearchParams,
    ServiceClientScopeUpdate,
    ServiceClientSecretRotation,
    ServiceClientStats,
    ServiceClientUsage,
    ServiceClientUsageResponse,
    ServiceClientHealthCheck,
    ServiceClientHealthResponse,
    ServiceClientWebhookTest,
    ServiceClientWebhookTestResponse,
    ServiceClientPermissions,
    ServiceClientRateLimit
)

router = APIRouter()


@router.get("/", response_model=ServiceClientListResponse)
async def list_service_clients(
    search: Optional[str] = Query(None, description="Search term for name or client_id"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    is_trusted: Optional[bool] = Query(None, description="Filter by trusted status"),
    client_type: Optional[str] = Query(None, description="Filter by client type"),
    scope_id: Optional[int] = Query(None, description="Filter by scope ID"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    List service clients with pagination and filtering.
    
    Requires admin role.
    """
    try:
        # Build query
        query = select(ServiceClient).options(selectinload(ServiceClient.scopes))
        
        # Apply filters
        conditions = []
        
        if search:
            search_term = f"%{search}%"
            conditions.append(
                or_(
                    ServiceClient.name.ilike(search_term),
                    ServiceClient.client_id.ilike(search_term),
                    ServiceClient.description.ilike(search_term)
                )
            )
        
        if is_active is not None:
            conditions.append(ServiceClient.is_active == is_active)
        
        if is_trusted is not None:
            conditions.append(ServiceClient.is_trusted == is_trusted)
        
        if client_type:
            conditions.append(ServiceClient.client_type == client_type)
        
        if scope_id is not None:
            query = query.join(ServiceClient.scopes).where(Scope.id == scope_id)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Get total count
        count_query = select(func.count(ServiceClient.id))
        if conditions:
            count_query = count_query.where(and_(*conditions))
        if scope_id is not None:
            count_query = count_query.select_from(ServiceClient).join(ServiceClient.scopes).where(Scope.id == scope_id)
        
        total_result = await db.execute(count_query)
        total = total_result.scalar()
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        # Execute query
        result = await db.execute(query)
        clients = result.scalars().all()
        
        # Calculate pages
        pages = math.ceil(total / per_page) if total > 0 else 1
        
        return ServiceClientListResponse(
            clients=[ServiceClientResponse.from_orm(client) for client in clients],
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


@router.post("/", response_model=ServiceClientCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_service_client(
    client_data: ServiceClientCreate,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new service client.
    
    Requires admin role.
    """
    try:
        # Generate client_id if not provided
        client_id = client_data.client_id or f"client_{secrets.token_urlsafe(8)}"
        
        # Check if client_id already exists
        existing_client = await db.execute(
            select(ServiceClient).where(ServiceClient.client_id == client_id)
        )
        if existing_client.scalar_one_or_none():
            raise ConflictError("Client ID already exists")
        
        # Generate client secret
        client_secret = client_data.client_secret or secrets.token_urlsafe(32)
        client_secret_hash = hash_password(client_secret)
        
        # Create service client
        client = ServiceClient(
            client_id=client_id,
            client_secret_hash=client_secret_hash,
            name=client_data.name,
            description=client_data.description,
            client_type=client_data.client_type,
            is_active=client_data.is_active,
            is_trusted=client_data.is_trusted,
            contact_email=client_data.contact_email,
            website_url=client_data.website_url,
            access_token_lifetime=client_data.access_token_lifetime,
            refresh_token_lifetime=client_data.refresh_token_lifetime,
            rate_limit_per_minute=client_data.rate_limit_per_minute,
            rate_limit_per_hour=client_data.rate_limit_per_hour,
            allowed_ips=client_data.allowed_ips,
            webhook_url=client_data.webhook_url
        )
        
        db.add(client)
        await db.flush()  # Get client ID
        
        # Assign scopes if provided
        if client_data.scope_ids:
            scopes_result = await db.execute(
                select(Scope).where(Scope.id.in_(client_data.scope_ids))
            )
            scopes = scopes_result.scalars().all()
            client.scopes.extend(scopes)
        
        await db.commit()
        await db.refresh(client)
        
        return ServiceClientCreateResponse(
            client=ServiceClientResponse.from_orm(client),
            client_secret=client_secret
        )
        
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


@router.get("/{client_id}", response_model=ServiceClientResponse)
async def get_service_client(
    client_id: str,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Get service client by client ID.
    
    Requires admin role.
    """
    try:
        result = await db.execute(
            select(ServiceClient).options(selectinload(ServiceClient.scopes))
            .where(ServiceClient.client_id == client_id)
        )
        client = result.scalar_one_or_none()
        
        if not client:
            raise NotFoundError(f"Service client {client_id} not found")
        
        return ServiceClientResponse.from_orm(client)
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Service client not found"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.put("/{client_id}", response_model=ServiceClientResponse)
async def update_service_client(
    client_id: str,
    client_data: ServiceClientUpdate,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Update service client by client ID.
    
    Requires admin role.
    """
    try:
        # Get client
        result = await db.execute(
            select(ServiceClient).options(selectinload(ServiceClient.scopes))
            .where(ServiceClient.client_id == client_id)
        )
        client = result.scalar_one_or_none()
        
        if not client:
            raise NotFoundError(f"Service client {client_id} not found")
        
        # Update fields
        if client_data.name is not None:
            client.name = client_data.name
        if client_data.description is not None:
            client.description = client_data.description
        if client_data.is_active is not None:
            client.is_active = client_data.is_active
        if client_data.is_trusted is not None:
            client.is_trusted = client_data.is_trusted
        if client_data.contact_email is not None:
            client.contact_email = client_data.contact_email
        if client_data.website_url is not None:
            client.website_url = client_data.website_url
        if client_data.access_token_lifetime is not None:
            client.access_token_lifetime = client_data.access_token_lifetime
        if client_data.refresh_token_lifetime is not None:
            client.refresh_token_lifetime = client_data.refresh_token_lifetime
        if client_data.rate_limit_per_minute is not None:
            client.rate_limit_per_minute = client_data.rate_limit_per_minute
        if client_data.rate_limit_per_hour is not None:
            client.rate_limit_per_hour = client_data.rate_limit_per_hour
        if client_data.allowed_ips is not None:
            client.allowed_ips = client_data.allowed_ips
        if client_data.webhook_url is not None:
            client.webhook_url = client_data.webhook_url
        
        # Update scopes if provided
        if client_data.scope_ids is not None:
            scopes_result = await db.execute(
                select(Scope).where(Scope.id.in_(client_data.scope_ids))
            )
            scopes = scopes_result.scalars().all()
            client.scopes.clear()
            client.scopes.extend(scopes)
        
        await db.commit()
        await db.refresh(client)
        
        return ServiceClientResponse.from_orm(client)
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Service client not found"}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.delete("/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_service_client(
    client_id: str,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete service client by client ID.
    
    Requires admin role.
    """
    try:
        # Get client
        result = await db.execute(
            select(ServiceClient).where(ServiceClient.client_id == client_id)
        )
        client = result.scalar_one_or_none()
        
        if not client:
            raise NotFoundError(f"Service client {client_id} not found")
        
        # Delete client
        await db.delete(client)
        await db.commit()
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Service client not found"}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.post("/{client_id}/rotate-secret")
async def rotate_client_secret(
    client_id: str,
    rotation_data: ServiceClientSecretRotation,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Rotate service client secret.
    
    Requires admin role and current secret for verification.
    """
    try:
        # Get client
        result = await db.execute(
            select(ServiceClient).where(ServiceClient.client_id == client_id)
        )
        client = result.scalar_one_or_none()
        
        if not client:
            raise NotFoundError(f"Service client {client_id} not found")
        
        # Verify current secret
        if not verify_password(rotation_data.current_secret, client.client_secret_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_secret", "error_description": "Current secret is incorrect"}
            )
        
        # Generate new secret
        new_secret = secrets.token_urlsafe(32)
        client.client_secret_hash = hash_password(new_secret)
        
        await db.commit()
        
        return {
            "message": "Client secret rotated successfully",
            "client_secret": new_secret
        }
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Service client not found"}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.put("/{client_id}/scopes", response_model=ServiceClientResponse)
async def update_client_scopes(
    client_id: str,
    scope_data: ServiceClientScopeUpdate,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Update service client scopes.
    
    Requires admin role.
    """
    try:
        # Get client
        result = await db.execute(
            select(ServiceClient).options(selectinload(ServiceClient.scopes))
            .where(ServiceClient.client_id == client_id)
        )
        client = result.scalar_one_or_none()
        
        if not client:
            raise NotFoundError(f"Service client {client_id} not found")
        
        # Get scopes
        scopes_result = await db.execute(
            select(Scope).where(Scope.id.in_(scope_data.scope_ids))
        )
        scopes = scopes_result.scalars().all()
        
        # Update client scopes
        client.scopes.clear()
        client.scopes.extend(scopes)
        
        await db.commit()
        await db.refresh(client)
        
        return ServiceClientResponse.from_orm(client)
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Service client not found"}
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/{client_id}/permissions", response_model=ServiceClientPermissions)
async def get_client_permissions(
    client_id: str,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Get service client permissions.
    
    Requires admin role.
    """
    try:
        # Get client
        result = await db.execute(
            select(ServiceClient).options(selectinload(ServiceClient.scopes))
            .where(ServiceClient.client_id == client_id)
        )
        client = result.scalar_one_or_none()
        
        if not client:
            raise NotFoundError(f"Service client {client_id} not found")
        
        # Get client scopes
        client_scopes = client.get_scope_names()
        
        # Organize permissions by resource
        resources = {}
        for scope_name in client_scopes:
            if ":" in scope_name:
                action, resource = scope_name.split(":", 1)
                if resource not in resources:
                    resources[resource] = []
                resources[resource].append(action)
        
        # Check if client has admin access
        can_access_admin = client.has_scope("admin:system") or any(
            scope.startswith("admin:") for scope in client_scopes
        )
        
        return ServiceClientPermissions(
            client_id=client.client_id,
            scopes=client_scopes,
            resources=resources,
            can_access_admin=can_access_admin
        )
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Service client not found"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/{client_id}/rate-limit", response_model=ServiceClientRateLimit)
async def get_client_rate_limit(
    client_id: str,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Get service client rate limit status.
    
    Requires admin role.
    """
    try:
        # Get client
        result = await db.execute(
            select(ServiceClient).where(ServiceClient.client_id == client_id)
        )
        client = result.scalar_one_or_none()
        
        if not client:
            raise NotFoundError(f"Service client {client_id} not found")
        
        # TODO: Implement actual rate limit checking with Redis
        # For now, return mock data
        now = datetime.utcnow()
        
        return ServiceClientRateLimit(
            client_id=client.client_id,
            per_minute_limit=client.rate_limit_per_minute,
            per_minute_remaining=client.rate_limit_per_minute,  # Mock: full remaining
            per_minute_reset=now.replace(second=0, microsecond=0),
            per_hour_limit=client.rate_limit_per_hour,
            per_hour_remaining=client.rate_limit_per_hour,  # Mock: full remaining
            per_hour_reset=now.replace(minute=0, second=0, microsecond=0),
            is_rate_limited=False
        )
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Service client not found"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.post("/{client_id}/webhook/test", response_model=ServiceClientWebhookTestResponse)
async def test_client_webhook(
    client_id: str,
    test_data: ServiceClientWebhookTest,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Test service client webhook endpoint.
    
    Requires admin role.
    """
    try:
        # Get client
        result = await db.execute(
            select(ServiceClient).where(ServiceClient.client_id == client_id)
        )
        client = result.scalar_one_or_none()
        
        if not client:
            raise NotFoundError(f"Service client {client_id} not found")
        
        if not client.webhook_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "no_webhook", "error_description": "Client has no webhook URL configured"}
            )
        
        # TODO: Implement actual webhook testing with HTTP client
        # For now, return mock response
        import time
        start_time = time.time()
        
        # Simulate webhook call
        success = True  # Mock success
        status_code = 200
        response_body = '{"status": "ok", "message": "Test webhook received"}'
        response_time_ms = int((time.time() - start_time) * 1000)
        
        return ServiceClientWebhookTestResponse(
            success=success,
            status_code=status_code,
            response_body=response_body,
            response_time_ms=response_time_ms,
            error_message=None
        )
        
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Service client not found"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/stats/overview", response_model=ServiceClientStats)
async def get_service_client_stats(
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Get service client statistics overview.
    
    Requires admin role.
    """
    try:
        # Get total clients
        total_result = await db.execute(select(func.count(ServiceClient.id)))
        total_clients = total_result.scalar()
        
        # Get active clients
        active_result = await db.execute(
            select(func.count(ServiceClient.id)).where(ServiceClient.is_active == True)
        )
        active_clients = active_result.scalar()
        
        # Get trusted clients
        trusted_result = await db.execute(
            select(func.count(ServiceClient.id)).where(ServiceClient.is_trusted == True)
        )
        trusted_clients = trusted_result.scalar()
        
        # Get most active clients (mock data)
        most_active_clients = [
            {"client_id": "api-gateway", "requests": 1500},
            {"client_id": "mt5-service", "requests": 800},
            {"client_id": "mobile-app", "requests": 600}
        ]
        
        return ServiceClientStats(
            total_clients=total_clients,
            active_clients=active_clients,
            trusted_clients=trusted_clients,
            total_requests_today=2900,  # Mock data
            most_active_clients=most_active_clients
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )


@router.get("/health/check", response_model=ServiceClientHealthResponse)
async def check_service_clients_health(
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)
):
    """
    Check health status of all service clients.
    
    Requires admin role.
    """
    try:
        # Get all active clients
        result = await db.execute(
            select(ServiceClient).where(ServiceClient.is_active == True)
        )
        clients = result.scalars().all()
        
        health_checks = []
        healthy_count = 0
        
        for client in clients:
            # Mock health check data
            is_healthy = True  # Mock: assume all are healthy
            if is_healthy:
                healthy_count += 1
            
            health_check = ServiceClientHealthCheck(
                client_id=client.client_id,
                is_healthy=is_healthy,
                last_successful_request=client.last_used,
                consecutive_failures=0,  # Mock data
                webhook_status="ok" if client.webhook_url else None,
                response_time_avg_ms=150.0  # Mock data
            )
            health_checks.append(health_check)
        
        return ServiceClientHealthResponse(
            health_checks=health_checks,
            healthy_count=healthy_count,
            unhealthy_count=len(clients) - healthy_count,
            total_count=len(clients)
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error", "error_description": str(e)}
        )