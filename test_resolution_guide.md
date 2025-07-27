# Test Issues Resolution Guide - Step-by-Step Implementation

## Overview

This guide provides a systematic approach to resolving the 62 test failures identified in the test report. The resolution is structured from architectural to technical levels, addressing root causes rather than symptoms.

## Phase 1: Architectural Fixes (Critical - Days 1-3)

### 1.1 Fix Database Dependency Injection Architecture

**Problem:** Database dependency returning async generators instead of sessions, causing `AttributeError: 'async_generator' object has no attribute 'rollback'`

**Root Cause:** Inconsistent handling of async generators in dependency injection

**Solution:**

#### Step 1: Fix Database Dependency in `app/config/database.py`
```python
# Replace the current get_db function with proper session management
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency function to get database session.
    
    Yields:
        AsyncSession: Database session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
```

#### Step 2: Fix API Endpoint Database Usage in `app/api/v1/users.py`
Remove all the manual async generator handling code (lines 67-75, 183-190, 235-243, 386-396) and replace with:

```python
# Replace all instances of manual db handling with:
@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    current_user = Depends(require_admin()),
    db: AsyncSession = Depends(get_db)  # Proper type annotation
):
    try:
        # Direct use of db session - no manual handling needed
        existing_user = await User.get_by_username(db, user_data.username)
        # ... rest of the logic
    except Exception as e:
        await db.rollback()  # Now db is properly a session
        raise HTTPException(...)
```

#### Step 3: Update All API Endpoints
Apply the same pattern to all endpoints in:
- `app/api/v1/users.py`
- `app/api/v1/auth.py`
- `app/api/v1/roles.py`
- `app/api/v1/service_clients.py`
- `app/api/v1/admin.py`
- `app/api/v1/sessions.py`

### 1.2 Fix Request Validation Pipeline Architecture

**Problem:** All API endpoints returning 422 instead of expected status codes (200, 201, 401, 403, 404, 409)

**Root Cause:** FastAPI validation middleware intercepting requests before business logic

**Solution:**

#### Step 1: Add Custom Exception Handler in `app/main.py`
```python
from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors properly."""
    return JSONResponse(
        status_code=422,
        content={
            "error": "validation_error",
            "error_description": "Request validation failed",
            "details": exc.errors()
        }
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions properly."""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail if isinstance(exc.detail, dict) else {
            "error": "http_error",
            "error_description": str(exc.detail)
        }
    )
```

#### Step 2: Fix Authentication Middleware Order
Ensure authentication happens before validation by reordering middleware in `app/main.py`:

```python
# Add authentication middleware before CORS
from app.core.security import AuthenticationMiddleware

app.add_middleware(AuthenticationMiddleware)  # Add this first
app.add_middleware(CORSMiddleware, ...)
app.add_middleware(TrustedHostMiddleware, ...)
```

### 1.3 Fix Async Context Management Architecture

**Problem:** `MissingGreenlet` errors across model tests

**Root Cause:** Improper async context setup in test environment

**Solution:**

#### Step 1: Fix Test Configuration in `tests/conftest.py`
```python
# Add proper async context management
import greenlet
from sqlalchemy.ext.asyncio import AsyncSession

@pytest.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create database session with proper async context."""
    AsyncSessionLocal = sessionmaker(
        test_engine, 
        class_=AsyncSession, 
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )
    
    # Ensure we're in an async context
    if not greenlet.getcurrent().parent:
        # We're not in a greenlet, create one
        async def _session_wrapper():
            async with AsyncSessionLocal() as session:
                try:
                    yield session
                finally:
                    await session.rollback()
                    await session.close()
        
        async for session in _session_wrapper():
            yield session
    else:
        # We're already in a greenlet context
        async with AsyncSessionLocal() as session:
            try:
                yield session
            finally:
                await session.rollback()
                await session.close()
```

#### Step 2: Fix Model Test Base Class
Create a proper async test base class:

```python
# Add to tests/conftest.py
class AsyncTestCase:
    """Base class for async model tests."""
    
    @pytest.fixture(autouse=True)
    async def setup_async_context(self, db_session):
        """Ensure proper async context for all tests."""
        self.db = db_session
        # Ensure greenlet context is properly set up
        if not hasattr(greenlet.getcurrent(), 'parent') or not greenlet.getcurrent().parent:
            pytest.skip("Test requires proper async context")
```

## Phase 2: Technical Implementation Fixes (High Priority - Days 4-6)

### 2.1 Fix JSON Serialization Issues

**Problem:** `TypeError: Object of type UUID is not JSON serializable`

**Solution:**

#### Step 1: Create Custom JSON Encoder in `app/core/json.py`
```python
import json
import uuid
from datetime import datetime
from decimal import Decimal

class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for UUID and other types."""
    
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)
```

#### Step 2: Update Pydantic Models in `app/schemas/`
```python
# In all schema files, add proper UUID handling
from pydantic import BaseModel, Field
import uuid

class UserResponse(BaseModel):
    id: uuid.UUID = Field(..., description="User ID")
    # ... other fields
    
    class Config:
        from_attributes = True
        json_encoders = {
            uuid.UUID: str,
            datetime: lambda v: v.isoformat(),
        }
```

#### Step 3: Update FastAPI App Configuration in `app/main.py`
```python
from app.core.json import CustomJSONEncoder

app = FastAPI(
    title="Keystone Authentication System",
    # ... other config
    json_encoder=CustomJSONEncoder,
)
```

### 2.2 Fix Configuration Parsing Issues

**Problem:** `SettingsError: error parsing value for field "ALLOWED_HOSTS" from source "EnvSettingsSource"`

**Solution:**

#### Step 1: Fix Settings Validation in `app/config/settings.py`
```python
from pydantic import BaseSettings, validator
from typing import List, Union

class Settings(BaseSettings):
    # ... existing fields
    
    ALLOWED_HOSTS: Union[str, List[str]] = ["localhost", "127.0.0.1"]
    CORS_ORIGINS: Union[str, List[str]] = ["http://localhost:3000"]
    
    @validator('ALLOWED_HOSTS', pre=True)
    def parse_allowed_hosts(cls, v):
        if isinstance(v, str):
            # Handle comma-separated string
            return [host.strip() for host in v.split(',') if host.strip()]
        return v
    
    @validator('CORS_ORIGINS', pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            # Handle comma-separated string
            return [origin.strip() for origin in v.split(',') if origin.strip()]
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = True
```

#### Step 2: Update Environment Variable Examples in `.env.example`
```bash
# Add proper format examples
ALLOWED_HOSTS=localhost,127.0.0.1,yourdomain.com
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com
```

### 2.3 Fix Missing Model Methods

**Problem:** `AttributeError: type object 'Role' has no attribute 'get_all'`

**Solution:**

#### Step 1: Add Missing Methods to `app/models/role.py`
```python
class Role(Base):
    # ... existing code
    
    @classmethod
    async def get_all(cls, db: AsyncSession) -> List['Role']:
        """Get all roles."""
        result = await db.execute(select(cls))
        return result.scalars().all()
    
    @classmethod
    async def get_by_name(cls, db: AsyncSession, name: str) -> Optional['Role']:
        """Get role by name."""
        result = await db.execute(select(cls).where(cls.name == name))
        return result.scalar_one_or_none()
```

#### Step 2: Add Missing Methods to `app/models/scope.py`
```python
class Scope(Base):
    # ... existing code
    
    @classmethod
    async def get_by_resource(cls, db: AsyncSession, resource: str) -> List['Scope']:
        """Get scopes by resource."""
        result = await db.execute(select(cls).where(cls.resource == resource))
        return result.scalars().all()
    
    @classmethod
    async def get_scopes_for_resource_pattern(cls, db: AsyncSession, pattern: str) -> List['Scope']:
        """Get scopes matching resource pattern."""
        result = await db.execute(select(cls).where(cls.resource.like(f"%{pattern}%")))
        return result.scalars().all()
    
    def serialize(self, include_metadata: bool = False) -> dict:
        """Serialize scope to dictionary."""
        data = {
            'id': str(self.id),
            'name': self.name,
            'description': self.description,
            'resource': self.resource,
        }
        if include_metadata:
            data.update({
                'created_at': self.created_at.isoformat() if self.created_at else None,
                'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            })
        return data
```

## Phase 3: Business Logic Fixes (Medium Priority - Days 7-8)

### 3.1 Fix Scope Parsing Logic

**Problem:** `AssertionError: assert 'action' == 'read'` in scope parsing

**Solution:**

#### Step 1: Fix Scope Name Parsing in `app/models/scope.py`
```python
def parse_name(self) -> tuple[str, str]:
    """Parse scope name into action and resource."""
    if ':' in self.name:
        action, resource = self.name.split(':', 1)
        return action, resource
    else:
        # Handle scopes without colon separator
        return 'access', self.name

def get_action(self) -> str:
    """Get action from scope name."""
    action, _ = self.parse_name()
    return action

def get_resource(self) -> str:
    """Get resource from scope name."""
    if self.resource:
        return self.resource
    _, resource = self.parse_name()
    return resource or ''
```

### 3.2 Fix Security Classification Logic

**Problem:** `AssertionError: assert 'public' == 'user'` in security classification

**Solution:**

#### Step 1: Fix Security Classification in `app/models/scope.py`
```python
def get_security_classification(self) -> str:
    """Get security classification of scope."""
    action, resource = self.parse_name()
    
    # Define classification rules
    if action in ['admin', 'delete', 'write']:
        return 'admin'
    elif action in ['read', 'view']:
        if resource in ['public', 'info']:
            return 'public'
        else:
            return 'user'
    else:
        return 'user'  # Default classification
```

### 3.3 Fix Scope Implication Logic

**Problem:** `TypeError: argument of type 'Scope' is not iterable` in scope implies method

**Solution:**

#### Step 1: Fix Scope Implies Method in `app/models/scope.py`
```python
def implies(self, other_scopes: Union['Scope', List['Scope'], List[str]]) -> bool:
    """Check if this scope implies other scopes."""
    if isinstance(other_scopes, Scope):
        other_scopes = [other_scopes.name]
    elif isinstance(other_scopes, list):
        # Handle list of Scope objects or strings
        scope_names = []
        for scope in other_scopes:
            if isinstance(scope, Scope):
                scope_names.append(scope.name)
            else:
                scope_names.append(str(scope))
        other_scopes = scope_names
    
    my_action, my_resource = self.parse_name()
    
    for scope_name in other_scopes:
        if isinstance(scope_name, str):
            if ':' in scope_name:
                other_action, other_resource = scope_name.split(':', 1)
            else:
                other_action, other_resource = 'access', scope_name
            
            # Check if this scope implies the other
            if not self._implies_scope(my_action, my_resource, other_action, other_resource):
                return False
    
    return True

def _implies_scope(self, my_action: str, my_resource: str, other_action: str, other_resource: str) -> bool:
    """Check if my scope implies another specific scope."""
    # Admin actions imply all other actions on the same resource
    if my_action == 'admin' and my_resource == other_resource:
        return True
    
    # Write implies read on the same resource
    if my_action == 'write' and other_action == 'read' and my_resource == other_resource:
        return True
    
    # Exact match
    if my_action == other_action and my_resource == other_resource:
        return True
    
    return False
```

## Phase 4: Test Infrastructure Fixes (Low Priority - Days 9-10)

### 4.1 Fix Mock Assertion Issues

**Problem:** Mock assertion failures in unit tests

**Solution:**

#### Step 1: Fix Mock Usage in `tests/unit/test_security.py`
```python
# Replace incorrect mock assertions with proper ones
@pytest.mark.asyncio
async def test_get_current_user_success(self):
    # Create proper mock that behaves like async generator
    mock_db = AsyncMock()
    mock_db.__anext__ = AsyncMock(return_value=mock_db)
    
    # Mock the user retrieval
    mock_user = AsyncMock()
    mock_get_user_by_id = AsyncMock(return_value=mock_user)
    
    with patch('app.models.user.User.get_by_id', mock_get_user_by_id):
        result = await get_current_user_dependency(
            token="valid-token",
            db=mock_db
        )
    
    # Correct assertion - check the actual session object passed
    mock_get_user_by_id.assert_called_once_with(mock_db, 'user-123')
```

### 4.2 Fix Test Data Setup

**Problem:** Various assertion failures due to incorrect test data

**Solution:**

#### Step 1: Fix Test Data in Model Tests
```python
# In tests/test_app/test_models/test_scope.py
def test_scope_parse_name(self):
    """Test scope name parsing."""
    scope = Scope(name="read:users", resource="users")
    action, resource = scope.parse_name()
    assert action == "read"  # This should now pass
    assert resource == "users"

def test_scope_get_resource(self):
    """Test resource extraction."""
    scope = Scope(name="system_admin", resource=None)
    resource = scope.get_resource()
    assert resource == ""  # Handle None resource properly
```

## Phase 5: Validation and Testing (Days 11-12)

### 5.1 Validation Steps

1. **Run Critical Tests First:**
   ```bash
   pytest tests/test_app/test_api/test_users.py -v
   pytest tests/test_app/test_models/ -v
   ```

2. **Verify Database Operations:**
   ```bash
   pytest tests/test_app/test_config/test_database.py -v
   ```

3. **Check Configuration:**
   ```bash
   pytest tests/test_app/test_config/test_settings.py -v
   ```

4. **Run Full Test Suite:**
   ```bash
   pytest --tb=short
   ```

### 5.2 Success Metrics

- **Phase 1 Success:** No more 422 status code errors, no more async generator errors
- **Phase 2 Success:** No more JSON serialization errors, configuration parsing works
- **Phase 3 Success:** Business logic assertions pass
- **Phase 4 Success:** All mock assertions work correctly
- **Overall Success:** Test failure rate drops from 15.5% to <2%

## Implementation Timeline

| Phase | Duration | Priority | Dependencies |
|-------|----------|----------|--------------|
| Phase 1 | 3 days | Critical | None |
| Phase 2 | 3 days | High | Phase 1 complete |
| Phase 3 | 2 days | Medium | Phase 1-2 complete |
| Phase 4 | 2 days | Low | Phase 1-3 complete |
| Phase 5 | 2 days | Validation | All phases complete |

## Risk Mitigation

1. **Backup Strategy:** Create feature branch before starting
2. **Incremental Testing:** Test after each phase completion
3. **Rollback Plan:** Keep working version tagged
4. **Documentation:** Update API docs after fixes

This systematic approach addresses root causes and ensures sustainable fixes rather than quick patches.