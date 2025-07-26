# 🔐 Authentication API

The Authentication API provides endpoints for user login, token management, and service-to-service authentication using OAuth2 and JWT tokens.

## 📋 Overview

### Authentication Flows

| Flow Type | Grant Type | Use Case | Token Lifetime |
|-----------|------------|----------|----------------|
| User Authentication | `password` | Web/Mobile apps | 15 minutes |
| Service Authentication | `client_credentials` | Service-to-service | 15 minutes |
| Token Refresh | `refresh_token` | Token renewal | 30 days |

### Base URL

```
http://localhost:8000/api/v1/auth
```

## 🔑 User Authentication

### POST /token

Authenticate a user and receive access and refresh tokens.

**Request:**
```http
POST /api/v1/auth/token
Content-Type: application/x-www-form-urlencoded

username=testuser&password=SecurePassword123!
```

**Parameters:**
- `username` (string, required): Username or email address
- `password` (string, required): User password
- `scope` (string, optional): Requested scopes (space-separated)

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read:profile write:profile",
  "user_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

**Error Responses:**
```json
// 401 Unauthorized - Invalid credentials
{
  "error": "invalid_grant",
  "error_description": "Invalid username or password"
}

// 423 Locked - Account locked
{
  "error": "account_locked",
  "error_description": "Account locked due to too many failed attempts",
  "locked_until": "2024-01-15T10:30:00Z"
}

// 429 Too Many Requests - Rate limited
{
  "error": "rate_limit_exceeded",
  "error_description": "Too many login attempts. Try again later."
}
```

**cURL Example:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=SecurePassword123!"
```

## 🔄 Token Refresh

### POST /refresh

Refresh an access token using a refresh token.

**Request:**
```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Parameters:**
- `refresh_token` (string, required): Valid refresh token

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read:profile write:profile"
}
```

**Error Responses:**
```json
// 401 Unauthorized - Invalid refresh token
{
  "error": "invalid_grant",
  "error_description": "Invalid or expired refresh token"
}
```

**cURL Example:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
```

## 🏢 Service Authentication

### POST /service-token

Authenticate a service client and receive a service token.

**Request:**
```http
POST /api/v1/auth/service-token
Content-Type: application/x-www-form-urlencoded

client_id=my-service&client_secret=service-secret&scope=service:api
```

**Parameters:**
- `client_id` (string, required): Service client identifier
- `client_secret` (string, required): Service client secret
- `scope` (string, optional): Requested scopes (space-separated)

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "service:api"
}
```

**Error Responses:**
```json
// 401 Unauthorized - Invalid client credentials
{
  "error": "invalid_client",
  "error_description": "Invalid client credentials"
}

// 403 Forbidden - Client disabled
{
  "error": "client_disabled",
  "error_description": "Service client is disabled"
}
```

**cURL Example:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=my-service&client_secret=service-secret&scope=service:api"
```

## 🚫 Token Revocation

### POST /revoke

Revoke access or refresh tokens.

**Request:**
```http
POST /api/v1/auth/revoke
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type_hint": "access_token"
}
```

**Parameters:**
- `token` (string, required): Token to revoke
- `token_type_hint` (string, optional): `access_token` or `refresh_token`

**Response (200 OK):**
```json
{
  "message": "Token revoked successfully"
}
```

**cURL Example:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/revoke" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"token": "TOKEN_TO_REVOKE", "token_type_hint": "access_token"}'
```

## 🔍 Token Introspection

### POST /introspect

Inspect a token to get information about its validity and claims.

**Request:**
```http
POST /api/v1/auth/introspect
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Parameters:**
- `token` (string, required): Token to introspect

**Response (200 OK) - Active Token:**
```json
{
  "active": true,
  "sub": "123e4567-e89b-12d3-a456-426614174000",
  "username": "testuser",
  "email": "test@example.com",
  "scope": "read:profile write:profile",
  "client_id": "web-client",
  "token_type": "access",
  "exp": 1640995200,
  "iat": 1640994300,
  "iss": "keystone-auth",
  "aud": ["api-server"]
}
```

**Response (200 OK) - Inactive Token:**
```json
{
  "active": false
}
```

**cURL Example:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/introspect" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"token": "TOKEN_TO_INTROSPECT"}'
```

## 🚪 Logout

### POST /logout

Logout a user by revoking their tokens.

**Request:**
```http
POST /api/v1/auth/logout
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**
```json
{
  "message": "Logged out successfully"
}
```

**cURL Example:**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/logout" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 🔐 JWT Token Structure

### Access Token Claims

```json
{
  "iss": "keystone-auth",
  "aud": ["api-server"],
  "sub": "123e4567-e89b-12d3-a456-426614174000",
  "exp": 1640995200,
  "iat": 1640994300,
  "nbf": 1640994300,
  "jti": "unique-token-id",
  "type": "access",
  "username": "testuser",
  "email": "test@example.com",
  "roles": ["user"],
  "scopes": ["read:profile", "write:profile"],
  "client_id": "web-client"
}
```

### Refresh Token Claims

```json
{
  "iss": "keystone-auth",
  "aud": ["keystone-auth"],
  "sub": "123e4567-e89b-12d3-a456-426614174000",
  "exp": 1643586300,
  "iat": 1640994300,
  "jti": "unique-refresh-token-id",
  "type": "refresh",
  "username": "testuser",
  "client_id": "web-client"
}
```

### Service Token Claims

```json
{
  "iss": "keystone-auth",
  "aud": ["internal-api"],
  "sub": "my-service",
  "exp": 1640995200,
  "iat": 1640994300,
  "jti": "unique-service-token-id",
  "type": "service",
  "client_id": "my-service",
  "scopes": ["service:api"]
}
```

## 🛡️ Security Considerations

### Rate Limiting

All authentication endpoints are rate-limited:

- **Login**: 5 attempts per minute per IP
- **Refresh**: 10 attempts per minute per IP
- **Service Token**: 20 attempts per minute per IP

### Account Lockout

User accounts are locked after 5 consecutive failed login attempts for 15 minutes.

### Token Security

- **Access tokens** expire after 15 minutes
- **Refresh tokens** expire after 30 days
- **Service tokens** expire after 15 minutes
- All tokens use secure random JTI for uniqueness
- Tokens can be revoked and are checked against a blacklist

### HTTPS Requirements

In production, all authentication endpoints **must** be accessed over HTTPS to protect credentials and tokens in transit.

## 📝 Integration Examples

### Web Application (JavaScript)

```javascript
class AuthService {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.accessToken = localStorage.getItem('access_token');
    this.refreshToken = localStorage.getItem('refresh_token');
  }

  async login(username, password) {
    const response = await fetch(`${this.baseUrl}/api/v1/auth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
    });

    if (response.ok) {
      const tokens = await response.json();
      this.accessToken = tokens.access_token;
      this.refreshToken = tokens.refresh_token;
      localStorage.setItem('access_token', this.accessToken);
      localStorage.setItem('refresh_token', this.refreshToken);
      return tokens;
    } else {
      throw new Error('Login failed');
    }
  }

  async refreshAccessToken() {
    const response = await fetch(`${this.baseUrl}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refresh_token: this.refreshToken })
    });

    if (response.ok) {
      const tokens = await response.json();
      this.accessToken = tokens.access_token;
      this.refreshToken = tokens.refresh_token;
      localStorage.setItem('access_token', this.accessToken);
      localStorage.setItem('refresh_token', this.refreshToken);
      return tokens;
    } else {
      this.logout();
      throw new Error('Token refresh failed');
    }
  }

  async logout() {
    if (this.accessToken) {
      await fetch(`${this.baseUrl}/api/v1/auth/logout`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`
        }
      });
    }
    
    this.accessToken = null;
    this.refreshToken = null;
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  }

  getAuthHeaders() {
    return this.accessToken ? {
      'Authorization': `Bearer ${this.accessToken}`
    } : {};
  }
}
```

### Python Service Client

```python
import httpx
import asyncio
from datetime import datetime, timedelta

class KeystoneClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.token_expires_at = None

    async def get_service_token(self):
        """Get a service access token."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/auth/service-token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "service:api"
                }
            )
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data["access_token"]
            self.token_expires_at = datetime.utcnow() + timedelta(
                seconds=token_data["expires_in"] - 60  # Refresh 1 minute early
            )
            
            return self.access_token

    async def ensure_valid_token(self):
        """Ensure we have a valid access token."""
        if not self.access_token or datetime.utcnow() >= self.token_expires_at:
            await self.get_service_token()

    async def make_authenticated_request(self, method: str, url: str, **kwargs):
        """Make an authenticated request to the API."""
        await self.ensure_valid_token()
        
        headers = kwargs.get("headers", {})
        headers["Authorization"] = f"Bearer {self.access_token}"
        kwargs["headers"] = headers
        
        async with httpx.AsyncClient() as client:
            response = await client.request(method, url, **kwargs)
            return response

# Usage
async def main():
    client = KeystoneClient(
        base_url="http://localhost:8000",
        client_id="my-service",
        client_secret="service-secret"
    )
    
    response = await client.make_authenticated_request(
        "GET", 
        "http://localhost:8000/api/v1/users/profile"
    )
    print(response.json())

asyncio.run(main())
```

## 🚨 Error Handling

### Standard Error Response Format

```json
{
  "error": "error_code",
  "error_description": "Human readable error description",
  "error_uri": "https://docs.keystone.com/errors/error_code",
  "details": {
    "field": "Additional error details"
  }
}
```

### Common Error Codes

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `invalid_request` | 400 | Malformed request |
| `invalid_client` | 401 | Invalid client credentials |
| `invalid_grant` | 401 | Invalid username/password or refresh token |
| `unauthorized_client` | 401 | Client not authorized for this grant type |
| `unsupported_grant_type` | 400 | Grant type not supported |
| `invalid_scope` | 400 | Requested scope is invalid |
| `account_locked` | 423 | User account is locked |
| `rate_limit_exceeded` | 429 | Too many requests |
| `server_error` | 500 | Internal server error |

## 📚 Related Documentation

- [User Management API](users.md) - User CRUD operations
- [Admin API](admin.md) - Administrative functions
- [Security Guide](../security/security-guide.md) - Security best practices
- [Configuration Guide](../getting-started/configuration.md) - JWT and security settings

---

**Ready to authenticate! 🔐 Build secure applications with Keystone's robust authentication system.**