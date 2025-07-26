# Keystone Authentication System - Architecture Overview

## 🏗️ System Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        WEB[Web Application]
        MOBILE[Mobile App]
        SERVICE[Internal Services]
    end
    
    subgraph "Keystone Auth System"
        API[Spring Boot API]
        SECURITY[Spring Security]
        JWT[JWT Service]
        CACHE[Redis Cache]
    end
    
    subgraph "Data Layer"
        DB[(PostgreSQL)]
        REDIS[(Redis)]
    end
    
    WEB --> API
    MOBILE --> API
    SERVICE --> API
    
    API --> SECURITY
    SECURITY --> JWT
    API --> CACHE
    API --> DB
    CACHE --> REDIS
```

## 🎯 Core Components

### 1. Authentication Layer
- **User Authentication**: Username/password with OAuth2 flows
- **Service Authentication**: Client credentials flow for service-to-service
- **Token Management**: JWT access/refresh tokens with JTI support

### 2. Authorization Layer
- **RBAC**: Role-based access control
- **Scope-based**: OAuth2-style scope validation
- **Audience Validation**: Service-specific token validation

### 3. Security Features
- **Password Policies**: Entropy, length, reuse prevention
- **Rate Limiting**: Brute-force protection
- **Token Security**: Secure signing, expiration, revocation

## 📊 Database Schema Design

### Core Entities

```mermaid
erDiagram
    USER {
        uuid id PK
        string username UK
        string email UK
        string password_hash
        boolean enabled
        timestamp created_at
        timestamp updated_at
        timestamp last_login
    }
    
    ROLE {
        uuid id PK
        string name UK
        string description
        timestamp created_at
    }
    
    SCOPE {
        uuid id PK
        string name UK
        string description
        string resource
        timestamp created_at
    }
    
    SERVICE_CLIENT {
        uuid id PK
        string client_id UK
        string client_secret_hash
        string name
        boolean enabled
        timestamp created_at
        timestamp updated_at
    }
    
    REFRESH_TOKEN {
        uuid id PK
        string jti UK
        uuid user_id FK
        uuid client_id FK
        timestamp expires_at
        boolean revoked
        timestamp created_at
    }
    
    USER_ROLE {
        uuid user_id FK
        uuid role_id FK
    }
    
    ROLE_SCOPE {
        uuid role_id FK
        uuid scope_id FK
    }
    
    CLIENT_SCOPE {
        uuid client_id FK
        uuid scope_id FK
    }
    
    USER ||--o{ USER_ROLE : has
    ROLE ||--o{ USER_ROLE : assigned_to
    ROLE ||--o{ ROLE_SCOPE : has
    SCOPE ||--o{ ROLE_SCOPE : granted_to
    SERVICE_CLIENT ||--o{ CLIENT_SCOPE : has
    SCOPE ||--o{ CLIENT_SCOPE : granted_to
    USER ||--o{ REFRESH_TOKEN : owns
    SERVICE_CLIENT ||--o{ REFRESH_TOKEN : issued_for
```

## 🔐 Token Strategy

### Token Types & Lifetimes

| Token Type | Lifetime | Audience | Use Case |
|------------|----------|----------|----------|
| Access Token | 15 minutes | Target Service | API calls |
| Refresh Token | 7-30 days | Auth Server | Refresh access tokens |
| Service Token | 5-15 minutes | Target Service | Service-to-service |

### JWT Claims Structure

```json
{
  "iss": "keystone-auth",
  "aud": ["trading-api", "mt5-api"],
  "sub": "user-uuid-or-client-id",
  "exp": 1234567890,
  "iat": 1234567890,
  "nbf": 1234567890,
  "jti": "unique-token-id",
  "type": "access|refresh|service",
  "roles": ["user", "trader"],
  "scopes": ["read:profile", "write:trades"],
  "client_id": "service-client-id"
}
```

## 🛠️ Technology Stack

### Core Framework
- **Spring Boot 3.x**: Main application framework
- **Spring Security 6.x**: Authentication and authorization
- **Spring Data JPA**: Database access layer
- **Spring Boot Actuator**: Health checks and metrics

### Database & Caching
- **PostgreSQL 15+**: Primary database
- **Redis 7+**: Token caching and session storage
- **HikariCP**: Connection pooling

### Security & JWT
- **jjwt**: JWT library for token handling
- **Argon2**: Password hashing
- **Bouncy Castle**: Cryptographic operations

### Testing & Documentation
- **JUnit 5**: Unit testing
- **Testcontainers**: Integration testing
- **OpenAPI 3**: API documentation
- **WireMock**: External service mocking

### Deployment
- **Docker**: Containerization
- **Docker Compose**: Multi-container orchestration

## 🔄 API Endpoints Design

### Authentication Endpoints
```
POST /auth/token          # User login (password grant)
POST /auth/refresh        # Refresh access token
POST /auth/service-token  # Service client credentials
POST /auth/revoke         # Revoke tokens
POST /auth/introspect     # Token introspection (optional)
```

### User Management
```
POST /users/register      # User registration
GET  /users/profile       # Get user profile
PUT  /users/profile       # Update user profile
POST /users/change-password # Change password
```

### Admin Endpoints
```
GET    /admin/users       # List users
POST   /admin/users       # Create user
PUT    /admin/users/{id}  # Update user
DELETE /admin/users/{id}  # Delete user

GET    /admin/clients     # List service clients
POST   /admin/clients     # Create service client
PUT    /admin/clients/{id} # Update service client
DELETE /admin/clients/{id} # Delete service client
```

## 🚀 Deployment Architecture

### Docker Compose Services
```yaml
services:
  keystone-app:
    # Spring Boot application
  postgres:
    # PostgreSQL database
  redis:
    # Redis cache
  nginx:
    # Reverse proxy (optional)
```

### Environment Configuration
- **Development**: H2 in-memory + embedded Redis
- **Production**: PostgreSQL + Redis cluster
- **Testing**: Testcontainers for integration tests

## 📈 Performance Considerations

### Caching Strategy
- **Redis**: Token blacklist, user sessions, rate limiting
- **Application**: Role/scope mappings, public keys
- **Database**: Connection pooling, query optimization

### Security Measures
- **Rate Limiting**: Per IP, per user, per endpoint
- **Token Rotation**: Automatic refresh token rotation
- **Audit Logging**: All authentication events
- **Monitoring**: Failed login attempts, token usage

## 🧪 Testing Strategy

### Unit Tests
- Token generation and validation
- Password policy enforcement
- Role and scope authorization
- Error handling scenarios

### Integration Tests
- End-to-end authentication flows
- Database operations
- Redis caching
- API endpoint testing

### Security Tests
- Token tampering attempts
- Brute force protection
- SQL injection prevention
- XSS protection