# Permiso API Complete Client Test Suite

This directory contains comprehensive client tests for all 67 API endpoints in the Permiso authentication system, including curl commands, Python examples, and service-to-service integration patterns.

## 📋 Overview

The Permiso API provides a complete authentication and authorization system with the following capabilities:

- **User Authentication**: OAuth2 password flow for regular users
- **Service Client Authentication**: OAuth2 client credentials flow for service-to-service communication
- **Role-Based Access Control**: Comprehensive permission management system
- **Session Management**: Advanced session tracking and management
- **Administrative Functions**: System monitoring, audit logging, and maintenance

## 📁 Documentation Structure

### Core Documentation
- [`COMPLETE_API_CLIENT_TESTS.md`](./COMPLETE_API_CLIENT_TESTS.md) - Complete curl examples for all 67 endpoints
- [`COMPLETE_API_CLIENT_TESTS_PART2.md`](./COMPLETE_API_CLIENT_TESTS_PART2.md) - Service integration patterns and advanced scenarios

### Quick Reference
- [API Endpoint Summary](#api-endpoint-summary)
- [Authentication Quick Start](#authentication-quick-start)
- [Common Use Cases](#common-use-cases)

## 🚀 Quick Start

### Prerequisites

```bash
# Required tools
- curl
- jq (for JSON processing)
- Python 3.8+ (for Python examples)
- requests library (pip install requests)

# Environment setup
export BASE_URL="https://localhost:443"
export API_BASE="/api/v1"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="ProductionPassword123!"
```

### Basic Authentication Test

```bash
# Test user login
curl -k -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${ADMIN_USERNAME}&password=${ADMIN_PASSWORD}&grant_type=password"
```

Expected response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "scope": "admin:system admin:users admin:roles",
  "session_id": "sess_abc123def456"
}
```

## 📊 API Endpoint Summary

### Authentication Endpoints (6)
- `POST /auth/token` - User login
- `POST /auth/service-token` - Service client authentication
- `POST /auth/refresh` - Token refresh
- `POST /auth/introspect` - Token introspection
- `POST /auth/revoke` - Token revocation
- `POST /auth/logout` - User logout

### User Management Endpoints (15)
- `POST /users/register` - Public user registration
- `GET /users/me` - Get current user profile
- `PUT /users/me` - Update current user profile
- `GET /users` - List users (admin)
- `POST /users` - Create user (admin)
- `GET /users/{id}` - Get user by ID
- `PUT /users/{id}` - Update user by ID
- `DELETE /users/{id}` - Delete user
- `PUT /users/{id}/password` - Update user password
- `PUT /users/{id}/roles` - Update user roles
- `GET /users/stats/overview` - User statistics
- `POST /users/password-reset/request` - Request password reset
- `POST /users/password-reset/confirm` - Confirm password reset
- `POST /users/email-verification/request` - Request email verification
- `POST /users/email-verification/confirm` - Confirm email verification

### Role & Permission Management Endpoints (16)
- `GET /roles` - List roles
- `POST /roles` - Create role
- `GET /roles/{id}` - Get role by ID
- `PUT /roles/{id}` - Update role
- `DELETE /roles/{id}` - Delete role
- `PUT /roles/{id}/scopes` - Update role scopes
- `GET /roles/scopes` - List scopes
- `POST /roles/scopes` - Create scope
- `GET /roles/scopes/{id}` - Get scope by ID
- `PUT /roles/scopes/{id}` - Update scope
- `DELETE /roles/scopes/{id}` - Delete scope
- `POST /roles/permissions/check` - Check permission
- `POST /roles/permissions/check-bulk` - Bulk permission check
- `GET /roles/permissions/user/{id}` - Get user permissions
- `GET /roles/stats` - Role statistics
- `GET /roles/defaults` - Default roles

### Service Client Management Endpoints (12)
- `GET /service-clients` - List service clients
- `POST /service-clients` - Create service client
- `GET /service-clients/{id}` - Get service client
- `PUT /service-clients/{id}` - Update service client
- `DELETE /service-clients/{id}` - Delete service client
- `POST /service-clients/{id}/rotate-secret` - Rotate client secret
- `PUT /service-clients/{id}/scopes` - Update client scopes
- `GET /service-clients/{id}/permissions` - Get client permissions
- `GET /service-clients/{id}/rate-limit` - Get client rate limit
- `POST /service-clients/{id}/webhook/test` - Test client webhook
- `GET /service-clients/stats/overview` - Service client statistics
- `GET /service-clients/health/check` - Service clients health check

### Session Management Endpoints (6)
- `GET /sessions` - Get user sessions
- `POST /sessions/{id}/renew` - Renew session
- `DELETE /sessions/{id}` - Invalidate session
- `DELETE /sessions` - Invalidate all sessions
- `GET /sessions/stats` - Session statistics
- `POST /sessions/cleanup` - Cleanup expired sessions

### Administrative Endpoints (9)
- `GET /admin/dashboard/stats` - Dashboard statistics
- `GET /admin/system/health` - System health
- `GET /admin/security/events` - Security events
- `POST /admin/maintenance/cleanup` - Maintenance cleanup
- `POST /admin/maintenance/backup` - System backup
- `GET /admin/audit/activity` - Audit activity
- `GET /admin/reports/usage` - Usage report
- `POST /admin/config/reload` - Reload configuration
- `GET /admin/logs/errors` - Error logs

### System Endpoints (3)
- `GET /health` - Health check (public)
- `GET /` - Root information (public)

**Total: 67 Endpoints**

## 🔐 Authentication Quick Start

### 1. User Authentication

```bash
# Get user token
USER_TOKEN=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=UserPass123!&grant_type=password" \
  | jq -r '.access_token')

# Use token for API calls
curl -k -X GET "${BASE_URL}${API_BASE}/users/me" \
  -H "Authorization: Bearer ${USER_TOKEN}"
```

### 2. Service Client Authentication

```bash
# Get service token
SERVICE_TOKEN=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=test-client-001&client_secret=test-secret-123456789&grant_type=client_credentials" \
  | jq -r '.access_token')

# Use service token for API calls
curl -k -X GET "${BASE_URL}${API_BASE}/users" \
  -H "Authorization: Bearer ${SERVICE_TOKEN}"
```

### 3. Admin Authentication

```bash
# Get admin token
ADMIN_TOKEN=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=ProductionPassword123!&grant_type=password" \
  | jq -r '.access_token')

# Use admin token for administrative operations
curl -k -X GET "${BASE_URL}${API_BASE}/admin/dashboard/stats" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

## 💡 Common Use Cases

### User Registration and Login Flow

```bash
# 1. Register new user
curl -k -X POST "${BASE_URL}${API_BASE}/users/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser123",
    "email": "newuser@example.com",
    "password": "SecurePass123!",
    "first_name": "New",
    "last_name": "User"
  }'

# 2. Login with new user
TOKEN_RESPONSE=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=newuser123&password=SecurePass123!&grant_type=password")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')
REFRESH_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.refresh_token')

# 3. Get user profile
curl -k -X GET "${BASE_URL}${API_BASE}/users/me" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"

# 4. Update profile
curl -k -X PUT "${BASE_URL}${API_BASE}/users/me" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Updated",
    "bio": "Updated bio information"
  }'
```

### Service-to-Service Integration

```bash
# 1. Authenticate as service
SERVICE_TOKEN=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=api-gateway&client_secret=gateway-secret&grant_type=client_credentials" \
  | jq -r '.access_token')

# 2. Create user via service
curl -k -X POST "${BASE_URL}${API_BASE}/users" \
  -H "Authorization: Bearer ${SERVICE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "serviceuser",
    "email": "service@example.com",
    "password": "ServicePass123!",
    "is_active": true,
    "is_verified": true
  }'

# 3. Check user permissions
curl -k -X POST "${BASE_URL}${API_BASE}/roles/permissions/check" \
  -H "Authorization: Bearer ${SERVICE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-uuid-here",
    "resource": "posts",
    "action": "read"
  }'
```

### Admin User Management

```bash
# 1. Get admin token
ADMIN_TOKEN=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=ProductionPassword123!&grant_type=password" \
  | jq -r '.access_token')

# 2. List all users
curl -k -X GET "${BASE_URL}${API_BASE}/users?page=1&per_page=10" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# 3. Create role
ROLE_RESPONSE=$(curl -k -s -X POST "${BASE_URL}${API_BASE}/roles" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "content_moderator",
    "description": "Content moderation role"
  }')

ROLE_ID=$(echo $ROLE_RESPONSE | jq -r '.id')

# 4. Assign role to user
curl -k -X PUT "${BASE_URL}${API_BASE}/users/user-uuid-here/roles" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"role_ids\": [\"${ROLE_ID}\"]}"
```

## 🧪 Running Tests

### Individual Endpoint Tests

```bash
# Test specific endpoint
curl -k -X GET "${BASE_URL}${API_BASE}/health"

# Test with authentication
curl -k -X GET "${BASE_URL}${API_BASE}/users/me" \
  -H "Authorization: Bearer ${USER_TOKEN}"
```

### Complete Test Scenarios

```bash
# Run complete user flow test
bash ./scenario_1_user_flow.sh

# Run admin management test
bash ./scenario_2_admin_management.sh

# Run service client integration test
bash ./scenario_3_service_client.sh
```

### Python Integration Example

```python
from permiso_client import PermisoServiceClient

# Initialize client
client = PermisoServiceClient(
    base_url="https://localhost:443",
    client_id="your-client-id",
    client_secret="your-client-secret",
    verify_ssl=False
)

# Authenticate
if client.authenticate():
    # Create user
    user = client.create_user({
        "username": "pythonuser",
        "email": "python@example.com",
        "password": "PythonPass123!",
        "first_name": "Python",
        "last_name": "User"
    })
    
    if user:
        print(f"Created user: {user['id']}")
        
        # Check permissions
        has_permission = client.check_user_permission(
            user['id'], 'posts', 'read'
        )
        print(f"Has read permission: {has_permission}")
```

## 🔧 Configuration

### Environment Variables

```bash
# API Configuration
export BASE_URL="https://localhost:443"
export API_BASE="/api/v1"

# Authentication
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="ProductionPassword123!"
export USER_USERNAME="testuser"
export USER_PASSWORD="UserPass123!"
export CLIENT_ID="test-client-001"
export CLIENT_SECRET="test-secret-123456789"

# SSL Configuration (for testing)
export VERIFY_SSL="false"
```

### Test Configuration File

Create `test_config.sh`:

```bash
#!/bin/bash
# Test configuration

# API Settings
BASE_URL="https://localhost:443"
API_BASE="/api/v1"

# Credentials
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="ProductionPassword123!"
USER_USERNAME="testuser"
USER_PASSWORD="UserPass123!"
CLIENT_ID="test-client-001"
CLIENT_SECRET="test-secret-123456789"

# Test Settings
VERIFY_SSL=false
TIMEOUT=30
RETRY_COUNT=3
```

## 📝 Error Handling

### Common HTTP Status Codes

- **200 OK**: Request successful
- **201 Created**: Resource created successfully
- **204 No Content**: Request successful, no content returned
- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Authentication required or invalid
- **403 Forbidden**: Access denied
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource conflict (e.g., duplicate username)
- **422 Unprocessable Entity**: Validation error
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error

### Error Response Format

```json
{
  "error": "error_code",
  "error_description": "Human-readable error description",
  "details": {
    "additional": "error details"
  }
}
```

## 🔍 Troubleshooting

### Common Issues

1. **SSL Certificate Errors**
   ```bash
   # Use -k flag for curl to ignore SSL certificates
   curl -k -X GET "${BASE_URL}/health"
   ```

2. **Authentication Failures**
   ```bash
   # Check credentials and token expiry
   # Verify token format: should start with "eyJ"
   echo $ACCESS_TOKEN | cut -c1-10
   ```

3. **Permission Denied**
   ```bash
   # Check user roles and scopes
   curl -k -X GET "${BASE_URL}${API_BASE}/users/me" \
     -H "Authorization: Bearer ${TOKEN}"
   ```

4. **Rate Limiting**
   ```bash
   # Wait for rate limit reset or use different credentials
   # Check Retry-After header in response
   ```

### Debug Mode

```bash
# Enable verbose curl output
curl -k -v -X GET "${BASE_URL}${API_BASE}/health"

# Save response headers
curl -k -D headers.txt -X GET "${BASE_URL}${API_BASE}/health"

# Time the request
curl -k -w "Time: %{time_total}s\n" -X GET "${BASE_URL}${API_BASE}/health"
```

## 📚 Additional Resources

- [API Documentation](../docs/api/)
- [Authentication Guide](../docs/api/authentication.md)
- [Integration Examples](../docs/developer-portal/integrations/)
- [Security Best Practices](../docs/security/security-guide.md)

## 🤝 Contributing

When adding new tests:

1. Follow the existing naming convention
2. Include both success and error scenarios
3. Add proper error handling
4. Update this README with new endpoints
5. Test against the running API

## 📄 License

This test suite is part of the Permiso authentication system project.