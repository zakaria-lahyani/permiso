# Keystone API Specification

## 🌐 Base URL
```
Development: http://localhost:8080/api/v1
Production: https://auth.yourdomain.com/api/v1
```

## 🔐 Authentication Endpoints

### POST /auth/token
**Purpose**: User login with username/password (OAuth2 Password Grant)

**Request Body**:
```json
{
  "username": "john.doe@example.com",
  "password": "SecurePassword123!",
  "grant_type": "password",
  "client_id": "web-client",
  "scope": "read:profile write:profile"
}
```

**Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read:profile write:profile",
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Error Responses**:
```json
// 401 Unauthorized
{
  "error": "invalid_grant",
  "error_description": "Invalid username or password",
  "timestamp": "2024-01-15T10:30:00Z"
}

// 429 Too Many Requests
{
  "error": "rate_limit_exceeded",
  "error_description": "Too many login attempts. Try again in 5 minutes",
  "retry_after": 300
}
```

### POST /auth/refresh
**Purpose**: Refresh access token using refresh token

**Request Body**:
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "grant_type": "refresh_token",
  "client_id": "web-client"
}
```

**Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read:profile write:profile"
}
```

### POST /auth/service-token
**Purpose**: Service-to-service authentication (OAuth2 Client Credentials)

**Request Body**:
```json
{
  "client_id": "trading-service",
  "client_secret": "super-secret-key",
  "grant_type": "client_credentials",
  "scope": "read:trades write:trades",
  "audience": ["mt5-api", "trading-api"]
}
```

**Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read:trades write:trades"
}
```

### POST /auth/revoke
**Purpose**: Revoke access or refresh tokens

**Headers**:
```
Authorization: Bearer <access_token>
```

**Request Body**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type_hint": "refresh_token"
}
```

**Response (200 OK)**:
```json
{
  "message": "Token revoked successfully"
}
```

### POST /auth/introspect
**Purpose**: Token introspection (RFC 7662)

**Headers**:
```
Authorization: Bearer <service_token>
```

**Request Body**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK)**:
```json
{
  "active": true,
  "client_id": "web-client",
  "username": "john.doe@example.com",
  "scope": "read:profile write:profile",
  "exp": 1642248600,
  "iat": 1642247700,
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": ["trading-api"],
  "iss": "keystone-auth",
  "token_type": "Bearer"
}
```

## 👤 User Management Endpoints

### POST /users/register
**Purpose**: User registration

**Request Body**:
```json
{
  "username": "john.doe",
  "email": "john.doe@example.com",
  "password": "SecurePassword123!",
  "firstName": "John",
  "lastName": "Doe"
}
```

**Response (201 Created)**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "john.doe",
  "email": "john.doe@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "enabled": true,
  "roles": ["user"],
  "createdAt": "2024-01-15T10:30:00Z"
}
```

**Error Response (400 Bad Request)**:
```json
{
  "error": "validation_failed",
  "error_description": "Password does not meet policy requirements",
  "details": [
    "Password must contain at least one uppercase letter",
    "Password must be at least 8 characters long"
  ]
}
```

### GET /users/profile
**Purpose**: Get current user profile

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response (200 OK)**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "john.doe",
  "email": "john.doe@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "roles": ["user", "trader"],
  "scopes": ["read:profile", "write:profile", "read:trades"],
  "lastLogin": "2024-01-15T09:30:00Z",
  "createdAt": "2024-01-10T10:30:00Z"
}
```

### PUT /users/profile
**Purpose**: Update user profile

**Headers**:
```
Authorization: Bearer <access_token>
```

**Request Body**:
```json
{
  "firstName": "John",
  "lastName": "Smith",
  "email": "john.smith@example.com"
}
```

**Response (200 OK)**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "john.doe",
  "email": "john.smith@example.com",
  "firstName": "John",
  "lastName": "Smith",
  "updatedAt": "2024-01-15T10:30:00Z"
}
```

### POST /users/change-password
**Purpose**: Change user password

**Headers**:
```
Authorization: Bearer <access_token>
```

**Request Body**:
```json
{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewSecurePassword456!",
  "confirmPassword": "NewSecurePassword456!"
}
```

**Response (200 OK)**:
```json
{
  "message": "Password changed successfully"
}
```

## 🛡️ Admin Endpoints

### GET /admin/users
**Purpose**: List all users (Admin only)

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Query Parameters**:
```
?page=0&size=20&sort=createdAt,desc&search=john&role=trader
```

**Response (200 OK)**:
```json
{
  "content": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "username": "john.doe",
      "email": "john.doe@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "enabled": true,
      "roles": ["user", "trader"],
      "lastLogin": "2024-01-15T09:30:00Z",
      "createdAt": "2024-01-10T10:30:00Z"
    }
  ],
  "pageable": {
    "page": 0,
    "size": 20,
    "totalElements": 1,
    "totalPages": 1
  }
}
```

### POST /admin/users
**Purpose**: Create user (Admin only)

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Request Body**:
```json
{
  "username": "jane.doe",
  "email": "jane.doe@example.com",
  "password": "TempPassword123!",
  "firstName": "Jane",
  "lastName": "Doe",
  "roles": ["user", "trader"],
  "enabled": true
}
```

### PUT /admin/users/{userId}
**Purpose**: Update user (Admin only)

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Request Body**:
```json
{
  "firstName": "Jane",
  "lastName": "Smith",
  "roles": ["user", "trader", "admin"],
  "enabled": false
}
```

### DELETE /admin/users/{userId}
**Purpose**: Delete user (Admin only)

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Response (204 No Content)**

### GET /admin/clients
**Purpose**: List service clients (Admin only)

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Response (200 OK)**:
```json
{
  "content": [
    {
      "id": "client-uuid",
      "clientId": "trading-service",
      "name": "Trading Service",
      "enabled": true,
      "scopes": ["read:trades", "write:trades"],
      "audiences": ["mt5-api", "trading-api"],
      "createdAt": "2024-01-10T10:30:00Z"
    }
  ]
}
```

### POST /admin/clients
**Purpose**: Create service client (Admin only)

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Request Body**:
```json
{
  "clientId": "new-service",
  "name": "New Service",
  "scopes": ["read:data"],
  "audiences": ["data-api"],
  "enabled": true
}
```

**Response (201 Created)**:
```json
{
  "id": "new-client-uuid",
  "clientId": "new-service",
  "clientSecret": "generated-secret-key",
  "name": "New Service",
  "scopes": ["read:data"],
  "audiences": ["data-api"],
  "enabled": true,
  "createdAt": "2024-01-15T10:30:00Z"
}
```

## 📊 Health & Monitoring Endpoints

### GET /actuator/health
**Purpose**: Application health check

**Response (200 OK)**:
```json
{
  "status": "UP",
  "components": {
    "db": {
      "status": "UP",
      "details": {
        "database": "PostgreSQL",
        "validationQuery": "isValid()"
      }
    },
    "redis": {
      "status": "UP",
      "details": {
        "version": "7.0.0"
      }
    }
  }
}
```

### GET /actuator/metrics
**Purpose**: Application metrics

**Response (200 OK)**:
```json
{
  "names": [
    "jvm.memory.used",
    "jvm.memory.max",
    "http.server.requests",
    "keystone.auth.login.attempts",
    "keystone.auth.token.generated",
    "keystone.auth.token.validated"
  ]
}
```

## 🔒 Security Headers

All API responses include security headers:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

## 📝 Error Response Format

All error responses follow this format:
```json
{
  "error": "error_code",
  "error_description": "Human readable error description",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/v1/auth/token",
  "details": ["Additional error details if applicable"]
}
```

## 🔑 JWT Token Structure

### Access Token Claims
```json
{
  "iss": "keystone-auth",
  "aud": ["trading-api", "mt5-api"],
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1642248600,
  "iat": 1642247700,
  "nbf": 1642247700,
  "jti": "token-unique-id",
  "type": "access",
  "roles": ["user", "trader"],
  "scopes": ["read:profile", "write:trades"],
  "client_id": "web-client"
}
```

### Refresh Token Claims
```json
{
  "iss": "keystone-auth",
  "aud": ["keystone-auth"],
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1644839700,
  "iat": 1642247700,
  "jti": "refresh-token-unique-id",
  "type": "refresh",
  "client_id": "web-client"
}
```

### Service Token Claims
```json
{
  "iss": "keystone-auth",
  "aud": ["mt5-api", "trading-api"],
  "sub": "trading-service",
  "exp": 1642248600,
  "iat": 1642247700,
  "jti": "service-token-unique-id",
  "type": "service",
  "scopes": ["read:trades", "write:trades"],
  "client_id": "trading-service"
}
```

## 🚦 Rate Limiting

Rate limits are applied per endpoint:

| Endpoint | Limit | Window |
|----------|-------|--------|
| POST /auth/token | 5 requests | 5 minutes |
| POST /auth/refresh | 10 requests | 1 minute |
| POST /auth/service-token | 20 requests | 1 minute |
| POST /users/register | 3 requests | 1 hour |
| All other endpoints | 100 requests | 1 minute |

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 3
X-RateLimit-Reset: 1642248600