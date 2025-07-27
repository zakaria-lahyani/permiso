# FastAPI Dependency Injection Patterns

## Overview

This guide documents the dependency injection patterns used in the permiso authentication system. FastAPI's dependency injection system is the backbone of our security architecture, providing clean, testable, and reusable authentication and authorization patterns.

## Core Dependency Patterns

### 1. Basic Authentication Dependencies

#### Token Extraction and Validation

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.security import SecurityUtils
from app.core.jwt import jwt_service

# HTTP Bearer token security scheme
security = HTTPBearer(auto_error=False)

async def get_current_token_payload(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    redis: RedisClient = Depends(get_redis),
) -> dict:
    """
    Extract and validate current token payload.
    
    This is the foundation dependency that all other auth dependencies build upon.
    """
    try:
        token = SecurityUtils.extract_bearer_token(credentials)
        payload = jwt_service.validate_token(token)
        
        # Check if token is revoked
        jti = payload.get(JWTClaims.JWT_ID)
        if jti and await SecurityUtils.is_token_revoked(jti, redis):
            raise RevokedTokenError("Token has been revoked")
        
        return payload
    
    except (AuthenticationError, AuthorizationError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
```

#### User Authentication

```python
async def get_current_user(
    payload: dict = Depends(get_current_token_payload),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Get current authenticated user from token payload.
    
    Validates token type and retrieves user from database.
    """
    try:
        # Ensure this is a user token (not service token)
        token_type = payload.get(JWTClaims.TOKEN_TYPE)
        if token_type == TokenType.SERVICE:
            raise AuthenticationError("Service tokens cannot be used for user authentication")
        
        user_id = payload.get(JWTClaims.SUBJECT)
        if not user_id:
            raise AuthenticationError("Invalid token: missing user ID")
        
        return await SecurityUtils.get_user_by_id(user_id, db)
    
    except (AuthenticationError, UserNotFoundError, UserDisabledError, UserLockedError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
```

#### Service Client Authentication

```python
async def get_current_service_client(
    payload: dict = Depends(get_current_token_payload),
    db: AsyncSession = Depends(get_db),
) -> ServiceClient:
    """
    Get current authenticated service client from token payload.
    
    Validates service token and retrieves client from database.
    """
    try:
        # Ensure this is a service token
        token_type = payload.get(JWTClaims.TOKEN_TYPE)
        if token_type != TokenType.SERVICE:
            raise AuthenticationError("Only service tokens can be used for service authentication")
        
        client_id = payload.get(JWTClaims.CLIENT_ID)
        if not client_id:
            raise AuthenticationError("Invalid token: missing client ID")
        
        return await SecurityUtils.get_service_client_by_id(client_id, db)
    
    except (AuthenticationError, ServiceClientNotFoundError, ServiceClientDisabledError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
```

### 2. Authorization Dependencies

#### Scope-Based Authorization

```python
def require_scopes(required_scopes: List[str]):
    """
    Dependency factory for scope-based authorization.
    
    Creates a dependency that validates token contains required scopes.
    Supports scope inheritance (admin scopes imply read/write scopes).
    """
    async def check_scopes(token_payload: dict = Depends(get_current_token_payload)) -> dict:
        try:
            token_scopes = token_payload.get(JWTClaims.SCOPES, [])
            
            # Parse scopes if they come as a string
            if isinstance(token_scopes, str):
                token_scopes = token_scopes.split()
            
            # Check for exact matches first
            missing_scopes = set(required_scopes) - set(token_scopes)
            
            # If there are missing scopes, check for implied scopes
            if missing_scopes:
                implied_scopes = _get_implied_scopes(token_scopes)
                missing_scopes = missing_scopes - set(implied_scopes)
            
            if missing_scopes:
                raise InsufficientScopeError(
                    f"Insufficient permissions. Missing scopes: {', '.join(missing_scopes)}",
                    required_scopes=list(missing_scopes),
                )
            
            return token_payload
        
        except InsufficientScopeError:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "scope_check_failed", "error_description": str(e)},
            )
    
    # Add wrapped function for testing
    def wrapped_check_scopes(token_payload: dict) -> dict:
        # Synchronous version for unit tests
        # ... implementation
        pass
    
    check_scopes.__wrapped__ = wrapped_check_scopes
    return check_scopes

# Usage examples
@app.get("/api/v1/profile")
async def get_profile(
    payload: dict = Depends(require_scopes(["read:profile"]))
):
    return {"profile": "data"}

@app.post("/api/v1/transactions")
async def create_transaction(
    payload: dict = Depends(require_scopes(["write:transactions"]))
):
    return {"transaction": "created"}
```

#### Role-Based Authorization

```python
def require_roles(required_roles: List[str]):
    """
    Dependency factory for role-based authorization.
    
    Creates a dependency that validates user has required roles.
    """
    async def check_roles(current_user: User = Depends(get_current_user)):
        try:
            user_roles = await current_user.get_role_names()
            if not any(role in user_roles for role in required_roles):
                raise AuthorizationError(
                    f"Insufficient permissions. Required roles: {', '.join(required_roles)}",
                    details={"required_roles": required_roles, "user_roles": user_roles},
                )
            
            return current_user
        
        except AuthorizationError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(e),
            )
    
    # Add wrapped function for testing
    async def wrapped_check_roles(current_user):
        # Implementation for unit tests
        # ... implementation
        pass
    
    check_roles.__wrapped__ = wrapped_check_roles
    return check_roles

# Usage examples
@app.get("/api/v1/admin/users")
async def list_users(
    current_user: User = Depends(require_roles(["admin"]))
):
    return {"users": [...]}

@app.post("/api/v1/admin/system")
async def system_action(
    current_user: User = Depends(require_roles(["admin", "system"]))
):
    return {"action": "completed"}
```

### 3. Convenience Dependencies

#### Pre-configured Dependencies

```python
# Convenience dependencies for common patterns
CurrentUser = Depends(get_current_user)
CurrentServiceClient = Depends(get_current_service_client)
OptionalCurrentUser = Depends(get_optional_current_user)

# Admin user dependency
async def get_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Get current authenticated admin user.
    
    Simple, direct admin dependency that works with both API endpoints
    and unit tests.
    """
    try:
        user_roles = await current_user.get_role_names()
        if "admin" not in user_roles:
            raise AuthorizationError(
                "Insufficient permissions. Required roles: admin",
                details={"required_roles": ["admin"], "user_roles": user_roles},
            )
        
        return current_user
    
    except AuthorizationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )

AdminUser = Depends(get_admin_user)

# Usage examples
@app.get("/api/v1/profile")
async def get_profile(user: User = CurrentUser):
    return UserResponse.from_orm(user)

@app.get("/api/v1/admin/stats")
async def get_stats(admin: User = AdminUser):
    return {"stats": "admin_data"}
```

#### Optional Authentication

```python
async def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis),
) -> Optional[User]:
    """
    Get current user if token is provided (optional authentication).
    
    Returns None if no token provided or token is invalid.
    Useful for endpoints that work with or without authentication.
    """
    if not credentials or not credentials.credentials:
        return None
    
    try:
        token = credentials.credentials
        payload = jwt_service.validate_token(token)
        
        # Check if token is revoked
        jti = payload.get(JWTClaims.JWT_ID)
        if jti and await SecurityUtils.is_token_revoked(jti, redis):
            return None
        
        # Ensure this is a user token
        token_type = payload.get(JWTClaims.TOKEN_TYPE)
        if token_type == TokenType.SERVICE:
            return None
        
        user_id = payload.get(JWTClaims.SUBJECT)
        if not user_id:
            return None
        
        return await SecurityUtils.get_user_by_id(user_id, db)
    
    except Exception:
        # If any error occurs, return None (optional auth)
        return None

# Usage example
@app.get("/api/v1/public-content")
async def get_content(user: Optional[User] = Depends(get_optional_current_user)):
    if user:
        return {"content": "personalized", "user": user.username}
    else:
        return {"content": "public"}
```

### 4. Composite Dependencies

#### Multi-Type Authentication

```python
def require_user_or_service():
    """
    Dependency that accepts either user or service tokens.
    
    Useful for endpoints that can be accessed by both users and services.
    """
    async def check_user_or_service(
        payload: dict = Depends(get_current_token_payload)
    ) -> dict:
        token_type = payload.get(JWTClaims.TOKEN_TYPE)
        if token_type not in [TokenType.ACCESS, TokenType.SERVICE]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "invalid_token_type", "error_description": "Invalid token type"},
            )
        return payload
    
    return check_user_or_service

# Usage example
@app.get("/api/v1/shared-resource")
async def get_shared_resource(
    payload: dict = Depends(require_user_or_service())
):
    token_type = payload.get(JWTClaims.TOKEN_TYPE)
    if token_type == TokenType.ACCESS:
        return {"data": "user_specific", "user_id": payload.get("sub")}
    else:
        return {"data": "service_specific", "client_id": payload.get("client_id")}
```

#### Flexible Scope Requirements

```python
def require_any_scope(allowed_scopes: List[str]):
    """
    Dependency factory for "any of" scope authorization.
    
    User needs at least one of the allowed scopes.
    """
    async def check_any_scope(payload: dict = Depends(get_current_token_payload)) -> dict:
        try:
            token_scopes = payload.get(JWTClaims.SCOPES, [])
            
            # Parse scopes if they come as a string
            if isinstance(token_scopes, str):
                token_scopes = token_scopes.split()
            
            # Check for direct matches first
            has_scope = any(scope in token_scopes for scope in allowed_scopes)
            
            # If no direct match, check implied scopes
            if not has_scope:
                implied_scopes = _get_implied_scopes(token_scopes)
                has_scope = any(scope in implied_scopes for scope in allowed_scopes)
            
            if not has_scope:
                raise InsufficientScopeError(
                    f"Insufficient permissions. Need at least one of: {', '.join(allowed_scopes)}",
                    required_scopes=allowed_scopes,
                )
            
            return payload
        
        except InsufficientScopeError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(e),
            )
    
    return check_any_scope

# Usage example
@app.get("/api/v1/flexible-endpoint")
async def flexible_endpoint(
    payload: dict = Depends(require_any_scope(["read:profile", "read:public", "admin:users"]))
):
    return {"data": "accessible_with_any_scope"}
```

## Advanced Patterns

### 1. Dependency Composition

```python
def require_admin_or_owner(resource_id_param: str = "user_id"):
    """
    Composite dependency that allows access if user is admin OR owns the resource.
    
    Args:
        resource_id_param: Name of the path parameter containing resource ID
    """
    async def check_admin_or_owner(
        request: Request,
        current_user: User = Depends(get_current_user)
    ):
        # Check if user is admin
        user_roles = await current_user.get_role_names()
        if "admin" in user_roles:
            return current_user
        
        # Check if user owns the resource
        resource_id = request.path_params.get(resource_id_param)
        if resource_id and str(current_user.id) == resource_id:
            return current_user
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Must be admin or resource owner."
        )
    
    return check_admin_or_owner

# Usage example
@app.get("/api/v1/users/{user_id}/profile")
async def get_user_profile(
    user_id: str,
    current_user: User = Depends(require_admin_or_owner("user_id"))
):
    return {"profile": f"data_for_{user_id}"}
```

### 2. Conditional Dependencies

```python
def require_scope_or_role(scopes: List[str], roles: List[str]):
    """
    Dependency that requires either specific scopes OR specific roles.
    
    Useful for endpoints that can be accessed via different permission models.
    """
    async def check_scope_or_role(
        payload: dict = Depends(get_current_token_payload),
        current_user: User = Depends(get_current_user)
    ):
        # Check scopes first
        token_scopes = payload.get(JWTClaims.SCOPES, [])
        if isinstance(token_scopes, str):
            token_scopes = token_scopes.split()
        
        has_scope = any(scope in token_scopes for scope in scopes)
        if has_scope:
            return {"auth_type": "scope", "user": current_user}
        
        # Check roles
        user_roles = await current_user.get_role_names()
        has_role = any(role in user_roles for role in roles)
        if has_role:
            return {"auth_type": "role", "user": current_user}
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient permissions. Need scopes {scopes} OR roles {roles}"
        )
    
    return check_scope_or_role

# Usage example
@app.post("/api/v1/special-action")
async def special_action(
    auth_info: dict = Depends(require_scope_or_role(
        scopes=["admin:system"],
        roles=["superuser", "system_admin"]
    ))
):
    return {"action": "completed", "auth_method": auth_info["auth_type"]}
```

### 3. Resource-Based Dependencies

```python
def require_resource_access(resource_type: str, permission: str = "read"):
    """
    Dependency factory for resource-based access control.
    
    Checks if user has permission to access a specific resource type.
    """
    async def check_resource_access(
        request: Request,
        current_user: User = Depends(get_current_user)
    ):
        # Get resource ID from path parameters
        resource_id = None
        for param_name in ["id", f"{resource_type}_id", "resource_id"]:
            if param_name in request.path_params:
                resource_id = request.path_params[param_name]
                break
        
        if not resource_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Resource ID not found in request"
            )
        
        # Check if user has permission for this resource
        has_permission = await current_user.can_access_resource(
            resource_type, resource_id, permission
        )
        
        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"No {permission} permission for {resource_type} {resource_id}"
            )
        
        return {"user": current_user, "resource_id": resource_id}
    
    return check_resource_access

# Usage examples
@app.get("/api/v1/documents/{document_id}")
async def get_document(
    document_id: str,
    auth_info: dict = Depends(require_resource_access("document", "read"))
):
    return {"document": f"content_for_{document_id}"}

@app.put("/api/v1/documents/{document_id}")
async def update_document(
    document_id: str,
    auth_info: dict = Depends(require_resource_access("document", "write"))
):
    return {"document": f"updated_{document_id}"}
```

## Testing Dependency Patterns

### 1. Unit Testing Dependencies

```python
import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import HTTPException
from app.core.security import get_current_user, require_scopes

@pytest.mark.asyncio
async def test_get_current_user_success():
    # Mock dependencies
    mock_payload = {
        "sub": "user123",
        "type": "access",
        "scopes": ["read:profile"]
    }
    mock_db = AsyncMock()
    mock_user = MagicMock()
    mock_user.id = "user123"
    
    # Mock SecurityUtils.get_user_by_id
    with patch('app.core.security.SecurityUtils.get_user_by_id', return_value=mock_user):
        result = await get_current_user(mock_payload, mock_db)
        assert result == mock_user

@pytest.mark.asyncio
async def test_get_current_user_service_token():
    # Test that service tokens are rejected
    mock_payload = {
        "sub": "client123",
        "type": "service",
        "client_id": "test-client"
    }
    mock_db = AsyncMock()
    
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(mock_payload, mock_db)
    
    assert exc_info.value.status_code == 401
    assert "Service tokens cannot be used" in str(exc_info.value.detail)

def test_require_scopes_factory():
    # Test the dependency factory
    check_scopes = require_scopes(["read:profile"])
    
    # Test with valid scopes
    mock_payload = {"scopes": ["read:profile", "write:profile"]}
    result = check_scopes.__wrapped__(mock_payload)
    assert result == mock_payload
    
    # Test with insufficient scopes
    mock_payload = {"scopes": ["write:other"]}
    with pytest.raises(HTTPException) as exc_info:
        check_scopes.__wrapped__(mock_payload)
    
    assert exc_info.value.status_code == 403
```

### 2. Integration Testing

```python
import pytest
from fastapi.testclient import TestClient
from app.main import app

def test_protected_endpoint_without_token():
    client = TestClient(app)
    response = client.get("/api/v1/profile")
    
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers

def test_protected_endpoint_with_valid_token():
    client = TestClient(app)
    
    # Create a valid token for testing
    token = create_test_token(user_id="test123", scopes=["read:profile"])
    
    response = client.get(
        "/api/v1/profile",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200

def test_admin_endpoint_with_user_token():
    client = TestClient(app)
    
    # Create a user token (not admin)
    token = create_test_token(user_id="test123", roles=["user"])
    
    response = client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 403

def test_scope_based_endpoint():
    client = TestClient(app)
    
    # Test with correct scope
    token = create_test_token(scopes=["write:transactions"])
    response = client.post(
        "/api/v1/transactions",
        headers={"Authorization": f"Bearer {token}"},
        json={"amount": 100}
    )
    assert response.status_code == 200
    
    # Test with incorrect scope
    token = create_test_token(scopes=["read:profile"])
    response = client.post(
        "/api/v1/transactions",
        headers={"Authorization": f"Bearer {token}"},
        json={"amount": 100}
    )
    assert response.status_code == 403
```

### 3. Dependency Override for Testing

```python
from fastapi import Depends
from app.core.security import get_current_user
from app.models.user import User

# Test user factory
def create_test_user(user_id: str = "test123", roles: List[str] = None) -> User:
    user = User(
        id=user_id,
        username="testuser",
        email="test@example.com",
        is_active=True
    )
    if roles:
        user.roles = [Role(name=role) for role in roles]
    return user

# Override dependency for testing
def override_get_current_user():
    return create_test_user(roles=["admin"])

# In test setup
app.dependency_overrides[get_current_user] = override_get_current_user

def test_admin_endpoint_with_override():
    client = TestClient(app)
    
    # No token needed due to override
    response = client.get("/api/v1/admin/users")
    assert response.status_code == 200

# Clean up after tests
app.dependency_overrides.clear()
```

## Best Practices

### 1. Dependency Design Principles

- **Single Responsibility**: Each dependency should have one clear purpose
- **Composability**: Dependencies should be easily combinable
- **Testability**: Always provide `__wrapped__` functions for unit testing
- **Error Handling**: Use appropriate HTTP status codes and clear error messages
- **Performance**: Cache expensive operations and avoid N+1 queries

### 2. Security Considerations

- **Fail Secure**: Default to denying access when in doubt
- **Clear Errors**: Provide helpful error messages without exposing sensitive information
- **Token Validation**: Always validate token type, expiration, and revocation status
- **Scope Inheritance**: Implement logical scope hierarchies (admin implies read/write)

### 3. Code Organization

```python
# Group related dependencies in modules
# app/core/security.py - Core authentication dependencies
# app/core/authorization.py - Authorization dependencies
# app/core/permissions.py - Resource-based permissions

# Use clear naming conventions
get_current_user          # Returns User object
get_current_token_payload # Returns token dict
require_scopes           # Factory returning dependency
require_admin           # Factory returning dependency
AdminUser              # Pre-configured dependency
```

### 4. Documentation

```python
async def get_current_user(
    payload: dict = Depends(get_current_token_payload),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Get current authenticated user from token payload.
    
    Args:
        payload: Validated JWT token payload
        db: Database session
        
    Returns:
        User: Current authenticated user
        
    Raises:
        HTTPException: 401 if token is invalid or user not found
        
    Example:
        @app.get("/profile")
        async def get_profile(user: User = Depends(get_current_user)):
            return {"username": user.username}
    """
```

This comprehensive guide covers all the dependency injection patterns used in the permiso authentication system, providing both implementation details and best practices for building secure, maintainable FastAPI applications.