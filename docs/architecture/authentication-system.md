# Authentication System Architecture

## Overview

The permiso authentication system is a comprehensive, production-ready authentication and authorization solution built with FastAPI, SQLAlchemy 2.0, and JWT tokens. It supports both user authentication and service-to-service authentication with fine-grained permission control through roles and scopes.

## Core Components

### 1. Authentication Flow Architecture

```mermaid
graph TB
    A[Client Request] --> B{Token Present?}
    B -->|No| C[401 Unauthorized]
    B -->|Yes| D[Extract Bearer Token]
    D --> E[JWT Validation]
    E -->|Invalid| F[401 Unauthorized]
    E -->|Valid| G{Token Type?}
    G -->|User Token| H[Get Current User]
    G -->|Service Token| I[Get Service Client]
    H --> J[Check User Status]
    I --> K[Check Client Status]
    J -->|Active| L[Authorization Check]
    K -->|Active| L
    J -->|Inactive/Locked| M[401/403 Error]
    K -->|Disabled| M
    L --> N{Has Required Permissions?}
    N -->|Yes| O[Allow Access]
    N -->|No| P[403 Forbidden]
```

### 2. Token Types and Lifecycle

#### Access Tokens
- **Purpose**: Short-lived tokens for API access
- **Lifetime**: 60 minutes (configurable)
- **Contains**: User/client ID, scopes, roles, metadata
- **Usage**: Bearer token in Authorization header

#### Refresh Tokens
- **Purpose**: Long-lived tokens for obtaining new access tokens
- **Lifetime**: 30 days (configurable)
- **Storage**: Hashed in database
- **Usage**: Token rotation for security

#### Service Tokens
- **Purpose**: Service-to-service authentication
- **Lifetime**: 2 hours (configurable per client)
- **Contains**: Client ID, scopes, trust level
- **Usage**: OAuth2 client credentials flow

### 3. Security Layers

#### Layer 1: Token Validation
- JWT signature verification
- Expiration time checking
- Token revocation blacklist (Redis)
- Issuer and audience validation

#### Layer 2: Entity Validation
- User account status (active, locked, disabled)
- Service client status (enabled, trusted)
- Rate limiting and IP restrictions

#### Layer 3: Authorization
- Role-based access control (RBAC)
- Scope-based permissions
- Resource-level access control
- Hierarchical permission inheritance

## Key Security Features

### 1. FastAPI Dependency Injection

The system uses FastAPI's dependency injection for clean, testable security:

```python
# Basic authentication
async def protected_endpoint(
    current_user: User = Depends(get_current_user)
):
    return {"user_id": current_user.id}

# Role-based protection
async def admin_endpoint(
    current_user: User = Depends(AdminUser)
):
    return {"admin_action": "completed"}

# Scope-based protection
async def scoped_endpoint(
    payload: dict = Depends(require_scopes(["read:profile"]))
):
    return {"data": "protected"}
```

### 2. Scope Hierarchy and Inheritance

Scopes follow a hierarchical pattern with automatic inheritance:

- `admin:resource` → implies `read:resource` + `write:resource`
- `admin:system` → implies all resource permissions
- Custom scopes for specific business logic

### 3. Multi-Tenant Security

- User-based authentication for web applications
- Service client authentication for microservices
- Flexible scope assignment per client/user
- IP-based access restrictions

## Database Schema

### Core Tables

#### Users
- Authentication credentials
- Profile information
- Account status and security settings
- Role assignments

#### Service Clients
- OAuth2 client credentials
- Scope assignments
- Rate limiting configuration
- Trust levels and restrictions

#### Roles & Scopes
- Hierarchical role system
- Fine-grained scope permissions
- Many-to-many relationships
- Inheritance patterns

#### Sessions & Tokens
- Active session tracking
- Refresh token storage
- Token revocation blacklist
- Audit trail

## Performance Considerations

### 1. Caching Strategy
- Redis for token blacklists
- Session state caching
- Rate limiting counters
- Failed login attempt tracking

### 2. Database Optimization
- Proper indexing on lookup fields
- Relationship eager loading
- Connection pooling
- Query optimization

### 3. Scalability Features
- Stateless JWT tokens
- Horizontal scaling support
- Load balancer compatibility
- Microservice-ready architecture

## Security Best Practices

### 1. Token Security
- Short-lived access tokens
- Secure token storage
- Token rotation
- Revocation support

### 2. Password Security
- Bcrypt hashing
- Salt generation
- Failed attempt tracking
- Account lockout protection

### 3. API Security
- HTTPS enforcement
- CORS configuration
- Rate limiting
- Input validation

### 4. Audit and Monitoring
- Security event logging
- Failed authentication tracking
- Session monitoring
- Anomaly detection

## Configuration

### Environment Variables

```bash
# JWT Configuration
JWT_SECRET_KEY=your-secret-key-32-chars-min
JWT_ALGORITHM=HS256
JWT_ISSUER=permiso-auth
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=30
SERVICE_TOKEN_EXPIRE_MINUTES=120

# Database
DATABASE_URL=postgresql+asyncpg://user:pass@host:port/db

# Redis
REDIS_URL=redis://host:port/db

# Security
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_MINUTES=30
```

### Security Headers

The system automatically applies security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`

## Error Handling

### Authentication Errors
- `401 Unauthorized`: Invalid or missing token
- `403 Forbidden`: Valid token, insufficient permissions
- `423 Locked`: Account temporarily locked

### Authorization Errors
- Detailed error messages for debugging
- OAuth2-compliant error responses
- Security event logging

## Testing Strategy

### Unit Tests
- Security utility functions
- JWT token validation
- Permission checking logic
- Database model methods

### Integration Tests
- API endpoint security
- Authentication flows
- Authorization scenarios
- Error handling

### Security Tests
- Token manipulation attempts
- Permission bypass attempts
- Rate limiting validation
- Input validation testing

## Deployment Considerations

### Production Setup
- Use strong JWT secrets
- Enable HTTPS only
- Configure proper CORS
- Set up monitoring

### High Availability
- Multiple Redis instances
- Database clustering
- Load balancer configuration
- Health check endpoints

### Monitoring
- Authentication metrics
- Failed login tracking
- Token usage statistics
- Performance monitoring

This architecture provides a robust, scalable, and secure foundation for authentication and authorization in modern web applications and microservice architectures.