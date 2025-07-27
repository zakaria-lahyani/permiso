# Code Examples and Best Practices

## Overview

This guide provides practical code examples and best practices for implementing secure authentication and authorization in applications using the permiso authentication system. It covers common patterns, security considerations, and production-ready implementations.

## Authentication Examples

### 1. Basic User Authentication

#### Simple Protected Endpoint

```python
from fastapi import FastAPI, Depends, HTTPException
from app.core.security import get_current_user
from app.models.user import User

app = FastAPI()

@app.get("/api/v1/profile")
async def get_user_profile(current_user: User = Depends(get_current_user)):
    """
    Get current user's profile.
    
    Requires valid user authentication token.
    """
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "email": current_user.email,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "is_active": current_user.is_active,
        "created_at": current_user.created_at.isoformat()
    }
```

#### Optional Authentication

```python
from typing import Optional
from app.core.security import get_optional_current_user

@app.get("/api/v1/public-content")
async def get_public_content(
    user: Optional[User] = Depends(get_optional_current_user)
):
    """
    Get content that works with or without authentication.
    
    Returns personalized content if user is authenticated,
    otherwise returns public content.
    """
    if user:
        return {
            "content": "Welcome back, personalized content here!",
            "user_id": str(user.id),
            "personalized": True
        }
    else:
        return {
            "content": "Public content available to everyone",
            "personalized": False
        }
```

### 2. Role-Based Access Control

#### Admin-Only Endpoints

```python
from app.core.security import AdminUser

@app.get("/api/v1/admin/users")
async def list_all_users(
    current_user: User = AdminUser,
    db: AsyncSession = Depends(get_db)
):
    """
    List all users in the system.
    
    Requires admin role.
    """
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    
    result = await db.execute(
        select(User)
        .options(selectinload(User.roles))
        .where(User.is_active == True)
        .order_by(User.created_at.desc())
    )
    users = result.scalars().all()
    
    return {
        "users": [
            {
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "roles": [role.name for role in user.roles],
                "created_at": user.created_at.isoformat()
            }
            for user in users
        ],
        "total": len(users)
    }
```

#### Multiple Role Requirements

```python
from app.core.security import require_roles

@app.post("/api/v1/system/maintenance")
async def system_maintenance(
    maintenance_data: dict,
    current_user: User = Depends(require_roles(["admin", "system_admin"]))
):
    """
    Perform system maintenance operations.
    
    Requires either 'admin' or 'system_admin' role.
    """
    return {
        "message": "Maintenance operation initiated",
        "initiated_by": current_user.username,
        "operation": maintenance_data.get("operation"),
        "timestamp": datetime.utcnow().isoformat()
    }
```

### 3. Scope-Based Authorization

#### Single Scope Requirement

```python
from app.core.security import require_scopes

@app.get("/api/v1/transactions")
async def get_transactions(
    payload: dict = Depends(require_scopes(["read:transactions"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Get user's transaction history.
    
    Requires 'read:transactions' scope.
    """
    user_id = payload.get("sub")
    
    # Fetch transactions for the authenticated user
    result = await db.execute(
        select(Transaction)
        .where(Transaction.user_id == user_id)
        .order_by(Transaction.created_at.desc())
        .limit(50)
    )
    transactions = result.scalars().all()
    
    return {
        "transactions": [
            {
                "id": str(tx.id),
                "amount": float(tx.amount),
                "type": tx.transaction_type,
                "status": tx.status,
                "created_at": tx.created_at.isoformat()
            }
            for tx in transactions
        ]
    }
```

#### Multiple Scope Requirements

```python
@app.post("/api/v1/admin/transactions")
async def create_admin_transaction(
    transaction_data: dict,
    payload: dict = Depends(require_scopes(["write:transactions", "admin:system"]))
):
    """
    Create transaction as admin.
    
    Requires both 'write:transactions' and 'admin:system' scopes.
    """
    return {
        "message": "Admin transaction created",
        "transaction_id": "txn_admin_123",
        "created_by": payload.get("sub")
    }
```

#### Flexible Scope Requirements

```python
from app.core.security import require_any_scope

@app.get("/api/v1/reports")
async def get_reports(
    payload: dict = Depends(require_any_scope([
        "read:reports", 
        "admin:reports", 
        "admin:system"
    ]))
):
    """
    Get reports.
    
    Requires any of: 'read:reports', 'admin:reports', or 'admin:system' scope.
    """
    scopes = payload.get("scopes", [])
    
    # Determine report level based on scopes
    if "admin:system" in scopes:
        report_level = "full_system"
    elif "admin:reports" in scopes:
        report_level = "admin"
    else:
        report_level = "basic"
    
    return {
        "reports": f"Reports for {report_level} level",
        "access_level": report_level
    }
```

### 4. Service-to-Service Authentication

#### Service Client Authentication

```python
from app.core.security import get_current_service_client
from app.models.service_client import ServiceClient

@app.post("/api/v1/internal/process-payment")
async def process_payment(
    payment_data: dict,
    service_client: ServiceClient = Depends(get_current_service_client)
):
    """
    Process payment - internal service endpoint.
    
    Requires valid service client authentication.
    """
    # Log service usage
    service_client.update_usage()
    
    return {
        "payment_id": "pay_123",
        "status": "processed",
        "processed_by": service_client.client_id,
        "trusted_client": service_client.is_trusted
    }
```

#### Mixed Authentication (User or Service)

```python
from app.core.security import require_user_or_service

@app.get("/api/v1/shared/data")
async def get_shared_data(
    payload: dict = Depends(require_user_or_service()),
    db: AsyncSession = Depends(get_db)
):
    """
    Get data accessible by both users and services.
    
    Accepts either user tokens or service tokens.
    """
    token_type = payload.get("type")
    
    if token_type == "access":  # User token
        user_id = payload.get("sub")
        return {
            "data": f"User-specific data for {user_id}",
            "access_type": "user"
        }
    elif token_type == "service":  # Service token
        client_id = payload.get("client_id")
        return {
            "data": f"Service data for {client_id}",
            "access_type": "service"
        }
```

## Advanced Authorization Patterns

### 1. Resource Ownership

```python
from fastapi import Request, Path

async def require_admin_or_owner(
    user_id: str = Path(...),
    current_user: User = Depends(get_current_user)
):
    """
    Allow access if user is admin or owns the resource.
    """
    # Check if user is admin
    user_roles = await current_user.get_role_names()
    if "admin" in user_roles:
        return current_user
    
    # Check if user owns the resource
    if str(current_user.id) == user_id:
        return current_user
    
    raise HTTPException(
        status_code=403,
        detail="Access denied. Must be admin or resource owner."
    )

@app.get("/api/v1/users/{user_id}/private-data")
async def get_private_data(
    user_id: str,
    current_user: User = Depends(require_admin_or_owner),
    db: AsyncSession = Depends(get_db)
):
    """
    Get private user data.
    
    Accessible by admin or the user themselves.
    """
    # Fetch private data
    result = await db.execute(
        select(UserPrivateData).where(UserPrivateData.user_id == user_id)
    )
    private_data = result.scalar_one_or_none()
    
    if not private_data:
        raise HTTPException(status_code=404, detail="Private data not found")
    
    return {
        "user_id": user_id,
        "private_info": private_data.sensitive_data,
        "accessed_by": current_user.username
    }
```

### 2. Dynamic Permission Checking

```python
async def check_document_permission(
    document_id: str = Path(...),
    action: str = "read",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Check if user has permission to perform action on document.
    """
    # Get document
    result = await db.execute(
        select(Document).where(Document.id == document_id)
    )
    document = result.scalar_one_or_none()
    
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Check permissions
    has_permission = False
    
    # Owner can do anything
    if document.owner_id == current_user.id:
        has_permission = True
    
    # Check role-based permissions
    user_roles = await current_user.get_role_names()
    if "admin" in user_roles:
        has_permission = True
    elif "editor" in user_roles and action in ["read", "write"]:
        has_permission = True
    elif "viewer" in user_roles and action == "read":
        has_permission = True
    
    # Check document-specific permissions
    if not has_permission:
        result = await db.execute(
            select(DocumentPermission).where(
                DocumentPermission.document_id == document_id,
                DocumentPermission.user_id == current_user.id,
                DocumentPermission.permission.contains(action)
            )
        )
        doc_permission = result.scalar_one_or_none()
        has_permission = doc_permission is not None
    
    if not has_permission:
        raise HTTPException(
            status_code=403,
            detail=f"No {action} permission for document {document_id}"
        )
    
    return {"user": current_user, "document": document}

@app.get("/api/v1/documents/{document_id}")
async def get_document(
    document_id: str,
    auth_info: dict = Depends(lambda doc_id=Path(...): check_document_permission(doc_id, "read"))
):
    """
    Get document with dynamic permission checking.
    """
    document = auth_info["document"]
    return {
        "id": str(document.id),
        "title": document.title,
        "content": document.content,
        "owner": document.owner_id
    }
```

### 3. Time-Based Access Control

```python
from datetime import datetime, time

async def require_business_hours(
    current_user: User = Depends(get_current_user)
):
    """
    Allow access only during business hours (9 AM - 5 PM UTC).
    """
    current_time = datetime.utcnow().time()
    business_start = time(9, 0)  # 9:00 AM
    business_end = time(17, 0)   # 5:00 PM
    
    if not (business_start <= current_time <= business_end):
        # Check if user has after-hours access
        user_roles = await current_user.get_role_names()
        if "admin" not in user_roles and "after_hours" not in user_roles:
            raise HTTPException(
                status_code=403,
                detail="Access restricted to business hours (9 AM - 5 PM UTC)"
            )
    
    return current_user

@app.post("/api/v1/sensitive-operation")
async def sensitive_operation(
    operation_data: dict,
    current_user: User = Depends(require_business_hours)
):
    """
    Perform sensitive operation.
    
    Restricted to business hours unless user has special permissions.
    """
    return {
        "operation": "completed",
        "timestamp": datetime.utcnow().isoformat(),
        "user": current_user.username
    }
```

## Error Handling Best Practices

### 1. Custom Exception Handlers

```python
from fastapi import Request
from fastapi.responses import JSONResponse
from app.core.exceptions import AuthenticationError, AuthorizationError

@app.exception_handler(AuthenticationError)
async def authentication_error_handler(request: Request, exc: AuthenticationError):
    """Handle authentication errors with consistent format."""
    return JSONResponse(
        status_code=401,
        content={
            "error": "authentication_error",
            "error_description": str(exc),
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url.path)
        },
        headers={"WWW-Authenticate": "Bearer"}
    )

@app.exception_handler(AuthorizationError)
async def authorization_error_handler(request: Request, exc: AuthorizationError):
    """Handle authorization errors with consistent format."""
    return JSONResponse(
        status_code=403,
        content={
            "error": "authorization_error",
            "error_description": str(exc),
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url.path)
        }
    )
```

### 2. Graceful Error Responses

```python
@app.get("/api/v1/protected-resource")
async def get_protected_resource(
    current_user: User = Depends(get_current_user)
):
    """
    Example of proper error handling in protected endpoints.
    """
    try:
        # Check if user has access to this specific resource
        if not await current_user.can_access_resource("protected_resource"):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "insufficient_permissions",
                    "error_description": "User does not have access to this resource",
                    "required_permissions": ["read:protected_resource"]
                }
            )
        
        # Fetch and return resource
        resource_data = await get_resource_data(current_user.id)
        
        return {
            "resource": resource_data,
            "accessed_by": current_user.username,
            "access_time": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log unexpected errors
        logger.error(f"Unexpected error in get_protected_resource: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "internal_error",
                "error_description": "An unexpected error occurred"
            }
        )
```

## Security Best Practices

### 1. Input Validation

```python
from pydantic import BaseModel, validator
from typing import Optional

class UserUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    
    @validator('email')
    def validate_email(cls, v):
        if v is not None:
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, v):
                raise ValueError('Invalid email format')
        return v
    
    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        if v is not None:
            if len(v.strip()) < 1:
                raise ValueError('Name cannot be empty')
            if len(v) > 50:
                raise ValueError('Name too long (max 50 characters)')
        return v.strip() if v else v

@app.put("/api/v1/users/{user_id}")
async def update_user(
    user_id: str,
    user_data: UserUpdateRequest,
    current_user: User = Depends(require_admin_or_owner),
    db: AsyncSession = Depends(get_db)
):
    """
    Update user information with proper validation.
    """
    # Additional business logic validation
    if user_data.email:
        # Check if email is already taken
        existing_user = await User.get_by_email(db, user_data.email)
        if existing_user and str(existing_user.id) != user_id:
            raise HTTPException(
                status_code=409,
                detail="Email already in use by another user"
            )
    
    # Update user
    user = await User.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Apply updates
    update_data = user_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)
    
    await db.commit()
    await db.refresh(user)
    
    return {
        "message": "User updated successfully",
        "user": {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name
        }
    }
```

### 2. Rate Limiting

```python
import redis
from fastapi import Request
from datetime import datetime, timedelta

redis_client = redis.from_url("redis://localhost:6379")

async def rate_limit(
    request: Request,
    max_requests: int = 100,
    window_minutes: int = 60
):
    """
    Rate limiting middleware.
    """
    # Get client identifier (IP or user ID if authenticated)
    client_ip = request.client.host
    user_id = None
    
    # Try to get user ID from token if present
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ")[1]
            payload = jwt_service.decode_token(token, verify_signature=False)
            user_id = payload.get("sub")
        except:
            pass
    
    # Use user ID if available, otherwise use IP
    client_key = f"rate_limit:{user_id or client_ip}"
    
    # Check current request count
    current_requests = redis_client.get(client_key)
    if current_requests is None:
        current_requests = 0
    else:
        current_requests = int(current_requests)
    
    if current_requests >= max_requests:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "error_description": f"Too many requests. Limit: {max_requests} per {window_minutes} minutes",
                "retry_after": window_minutes * 60
            },
            headers={"Retry-After": str(window_minutes * 60)}
        )
    
    # Increment counter
    pipe = redis_client.pipeline()
    pipe.incr(client_key)
    pipe.expire(client_key, window_minutes * 60)
    pipe.execute()

@app.get("/api/v1/rate-limited-endpoint")
async def rate_limited_endpoint(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """
    Endpoint with rate limiting.
    """
    await rate_limit(request, max_requests=10, window_minutes=1)
    
    return {
        "message": "Success",
        "user": current_user.username,
        "timestamp": datetime.utcnow().isoformat()
    }
```

### 3. Audit Logging

```python
import logging
from app.core.audit import audit_logger

async def log_sensitive_action(
    action: str,
    resource_id: str,
    current_user: User,
    request: Request,
    additional_data: dict = None
):
    """
    Log sensitive actions for audit trail.
    """
    audit_data = {
        "action": action,
        "resource_id": resource_id,
        "user_id": str(current_user.id),
        "username": current_user.username,
        "ip_address": request.client.host,
        "user_agent": request.headers.get("user-agent"),
        "timestamp": datetime.utcnow().isoformat(),
        "additional_data": additional_data or {}
    }
    
    audit_logger.log_security_event(
        event_type="sensitive_action",
        user_id=str(current_user.id),
        username=current_user.username,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
        details=audit_data
    )

@app.delete("/api/v1/users/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    current_user: User = AdminUser,
    db: AsyncSession = Depends(get_db)
):
    """
    Delete user with audit logging.
    """
    # Get user to delete
    user_to_delete = await User.get_by_id(db, user_id)
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent self-deletion
    if str(current_user.id) == user_id:
        raise HTTPException(
            status_code=403,
            detail="Cannot delete your own account"
        )
    
    # Log the action before deletion
    await log_sensitive_action(
        action="user_deletion",
        resource_id=user_id,
        current_user=current_user,
        request=request,
        additional_data={
            "deleted_username": user_to_delete.username,
            "deleted_email": user_to_delete.email
        }
    )
    
    # Perform deletion
    await db.delete(user_to_delete)
    await db.commit()
    
    return {
        "message": "User deleted successfully",
        "deleted_user_id": user_id,
        "deleted_by": current_user.username
    }
```

## Testing Best Practices

### 1. Test Utilities

```python
# tests/utils.py
import jwt
from datetime import datetime, timedelta
from app.core.jwt import JWTClaims, TokenType
from app.config.settings import settings

def create_test_token(
    user_id: str = "test-user-123",
    scopes: list = None,
    roles: list = None,
    token_type: str = TokenType.ACCESS,
    expires_in_minutes: int = 60
) -> str:
    """Create a test JWT token."""
    if scopes is None:
        scopes = ["read:profile"]
    if roles is None:
        roles = ["user"]
    
    payload = {
        JWTClaims.SUBJECT: user_id,
        JWTClaims.TOKEN_TYPE: token_type,
        JWTClaims.SCOPES: scopes,
        JWTClaims.ROLES: roles,
        JWTClaims.ISSUED_AT: datetime.utcnow(),
        JWTClaims.EXPIRATION: datetime.utcnow() + timedelta(minutes=expires_in_minutes),
        JWTClaims.ISSUER: settings.JWT_ISSUER,
        JWTClaims.AUDIENCE: [settings.JWT_ISSUER]
    }
    
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def create_test_headers(token: str = None) -> dict:
    """Create test headers with authorization."""
    if token is None:
        token = create_test_token()
    
    return {"Authorization": f"Bearer {token}"}
```

### 2. Test Examples

```python
# tests/test_auth_endpoints.py
import pytest
from fastapi.testclient import TestClient
from app.main import app
from tests.utils import create_test_token, create_test_headers

client = TestClient(app)

def test_protected_endpoint_without_token():
    """Test that protected endpoint requires authentication."""
    response = client.get("/api/v1/profile")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers

def test_protected_endpoint_with_valid_token():
    """Test protected endpoint with valid token."""
    token = create_test_token(scopes=["read:profile"])
    headers = create_test_headers(token)
    
    response = client.get("/api/v1/profile", headers=headers)
    assert response.status_code == 200

def test_admin_endpoint_with_user_token():
    """Test that admin endpoint rejects user tokens."""
    token = create_test_token(roles=["user"])
    headers = create_test_headers(token)
    
    response = client.get("/api/v1/admin/users", headers=headers)
    assert response.status_code == 403

def test_admin_endpoint_with_admin_token():
    """Test that admin endpoint accepts admin tokens."""
    token = create_test_token(roles=["admin"])
    headers = create_test_headers(token)
    
    response = client.get("/api/v1/admin/users", headers=headers)
    assert response.status_code == 200

def test_scope_based_endpoint():
    """Test scope-based authorization."""
    # Test with correct scope
    token = create_test_token(scopes=["write:transactions"])
    headers = create_test_headers(token)
    
    response = client.post(
        "/api/v1/transactions",
        headers=headers,
        json={"amount": 100, "type": "deposit"}
    )
    assert response.status_code == 200
    
    # Test with incorrect scope
    token = create_test_token(scopes=["read:profile"])
    headers = create_test_headers(token)
    
    response = client.post(
        "/api/v1/transactions",
        headers=headers,
        json={"amount": 100, "type": "deposit"}
    )
    assert response.status_code == 403

def test_expired_token():
    """Test that expired tokens are rejected."""
    token = create_test_token(expires_in_minutes=-10)  # Expired 10 minutes ago
    headers = create_test_headers(token)
    
    response = client.get("/api/v1/profile", headers=headers)
    assert response.status_code == 401
```

## Production Deployment Considerations

### 1. Environment Configuration

```python
# config/production.py
import os
from app.config.settings import Settings

class ProductionSettings(Settings):
    """Production-specific settings."""
    
    # Security
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY")  # Must be set
    CORS_ORIGINS: list = ["https://yourapp.com", "https://admin.yourapp.com"]
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL")
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 30
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL")
    REDIS_POOL_SIZE: int = 10
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    
    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    DEFAULT_RATE_LIMIT: int = 1000  # requests per hour
    
    class Config:
        env_file = ".env.production"
```

### 2. Health Checks

```python
@app.get("/health")
async def health_check(
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis)
):
    """
    Health check endpoint for load balancers.
    """
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "checks": {}
    }
    
    # Database check
    try:
        await db.execute("SELECT 1")
        health_status["checks"]["database"] = "healthy"
    except Exception as e:
        health_status["checks"]["database"] = f"unhealthy: {str(e)}"
        health_status["status"] = "unhealthy"
    
    # Redis check
    try:
        await redis.ping()
        health_status["checks"]["redis"] = "healthy"
    except Exception as e:
        health_status["checks"]["redis"] = f"unhealthy: {str(e)}"
        health_status["status"] = "unhealthy"
    
    status_code = 200 if health_status["status"] == "healthy" else 503
    return JSONResponse(content=health_status, status_code=status_code)
```

This comprehensive guide provides practical examples and best practices for implementing secure, production-ready authentication and authorization using the permiso authentication system.