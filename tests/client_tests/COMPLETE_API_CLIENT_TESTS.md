# Complete API Client Tests for Permiso Authentication System

This document provides comprehensive client tests for all 67 API endpoints in the Permiso authentication system, including curl commands, Python examples, and service-to-service integration patterns.

## Table of Contents

1. [Authentication Overview](#authentication-overview)
2. [Environment Setup](#environment-setup)
3. [Authentication Endpoints](#authentication-endpoints)
4. [User Management Endpoints](#user-management-endpoints)
5. [Role & Permission Management](#role--permission-management)
6. [Service Client Management](#service-client-management)
7. [Session Management](#session-management)
8. [Administrative Endpoints](#administrative-endpoints)
9. [Service-to-Service Integration](#service-to-service-integration)
10. [Error Handling](#error-handling)
11. [Complete Test Scenarios](#complete-test-scenarios)

## Authentication Overview

The Permiso API supports three authentication methods:

1. **User Authentication**: OAuth2 password flow for regular users
2. **Service Client Authentication**: OAuth2 client credentials flow for service-to-service
3. **Admin Authentication**: Enhanced user authentication with admin privileges

### Token Types

- **Access Token**: Short-lived (15-30 minutes) for API access
- **Refresh Token**: Long-lived (7-30 days) for token renewal
- **Service Token**: Medium-lived (15 minutes) for service clients

## Environment Setup

```bash
# Base configuration
export BASE_URL="https://localhost:443"
export API_BASE="/api/v1"

# Test credentials (configure these in your environment)
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="ProductionPassword123!"
export USER_USERNAME="testuser"
export USER_PASSWORD="UserPass123!"
export CLIENT_ID="test-client-001"
export CLIENT_SECRET="test-secret-123456789"

# SSL settings for testing
export CURL_OPTS="-k -s -w \"\nHTTP Status: %{http_code}\nResponse Time: %{time_total}s\n\""
```

## Authentication Endpoints

### 1. User Login (OAuth2 Password Flow)

**Endpoint**: `POST /api/v1/auth/token`

```bash
# Basic user login
curl -k -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${USER_USERNAME}&password=${USER_PASSWORD}&grant_type=password"

# Login with specific scopes
curl -k -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${USER_USERNAME}&password=${USER_PASSWORD}&grant_type=password&scope=read:profile write:profile"

# Admin login
curl -k -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${ADMIN_USERNAME}&password=${ADMIN_PASSWORD}&grant_type=password"
```

**Expected Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "scope": "read:profile write:profile admin:users",
  "session_id": "sess_abc123def456"
}
```

### 2. Service Client Authentication

**Endpoint**: `POST /api/v1/auth/service-token`

```bash
# Service client login
curl -k -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&grant_type=client_credentials"

# Service client with specific scopes
curl -k -X POST "${BASE_URL}${API_BASE}/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&grant_type=client_credentials&scope=api:read api:write"
```

### 3. Token Refresh

**Endpoint**: `POST /api/v1/auth/refresh`

```bash
# First, get tokens
TOKENS=$(curl -k -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${USER_USERNAME}&password=${USER_PASSWORD}&grant_type=password")

REFRESH_TOKEN=$(echo $TOKENS | jq -r '.refresh_token')

# Refresh the access token
curl -k -X POST "${BASE_URL}${API_BASE}/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"${REFRESH_TOKEN}\"}"
```

### 4. Token Introspection

**Endpoint**: `POST /api/v1/auth/introspect`

```bash
# Get admin token first
ADMIN_TOKEN=$(curl -k -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${ADMIN_USERNAME}&password=${ADMIN_PASSWORD}&grant_type=password" | jq -r '.access_token')

# Get user token to introspect
USER_TOKEN=$(curl -k -X POST "${BASE_URL}${API_BASE}/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${USER_USERNAME}&password=${USER_PASSWORD}&grant_type=password" | jq -r '.access_token')

# Introspect the user token using admin privileges
curl -k -X POST "${BASE_URL}${API_BASE}/auth/introspect" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"${USER_TOKEN}\"}"
```

### 5. Token Revocation

**Endpoint**: `POST /api/v1/auth/revoke`

```bash
# Revoke a token
curl -k -X POST "${BASE_URL}${API_BASE}/auth/revoke" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"${USER_TOKEN}\"}"
```

### 6. User Logout

**Endpoint**: `POST /api/v1/auth/logout`

```bash
# Logout current user
curl -k -X POST "${BASE_URL}${API_BASE}/auth/logout" \
  -H "Authorization: Bearer ${USER_TOKEN}"
```

## User Management Endpoints

### 7. User Registration

**Endpoint**: `POST /api/v1/users/register`

```bash
# Public user registration
curl -k -X POST "${BASE_URL}${API_BASE}/users/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser123",
    "email": "newuser@example.com",
    "password": "SecurePass123!",
    "first_name": "New",
    "last_name": "User",
    "display_name": "New User",
    "bio": "Test user account"
  }'
```

### 8. Get Current User Profile

**Endpoint**: `GET /api/v1/users/me`

```bash
# Get current user profile
curl -k -X GET "${BASE_URL}${API_BASE}/users/me" \
  -H "Authorization: Bearer ${USER_TOKEN}"

# Alternative endpoint
curl -k -X GET "${BASE_URL}${API_BASE}/users/profile" \
  -H "Authorization: Bearer ${USER_TOKEN}"
```

### 9. Update Current User Profile

**Endpoint**: `PUT /api/v1/users/me`

```bash
# Update current user profile
curl -k -X PUT "${BASE_URL}${API_BASE}/users/me" \
  -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Updated",
    "last_name": "Name",
    "display_name": "Updated Display Name",
    "bio": "Updated bio information"
  }'
```

### 10. List Users (Admin)

**Endpoint**: `GET /api/v1/users`

```bash
# List all users
curl -k -X GET "${BASE_URL}${API_BASE}/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# List users with pagination
curl -k -X GET "${BASE_URL}${API_BASE}/users?page=1&per_page=10" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Search users
curl -k -X GET "${BASE_URL}${API_BASE}/users?search=john&is_active=true" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Filter by role
curl -k -X GET "${BASE_URL}${API_BASE}/users?role_id=role-uuid-here" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 11. Create User (Admin)

**Endpoint**: `POST /api/v1/users`

```bash
# Admin create user
curl -k -X POST "${BASE_URL}${API_BASE}/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "adminuser123",
    "email": "adminuser@example.com",
    "password": "AdminPass123!",
    "first_name": "Admin",
    "last_name": "User",
    "is_active": true,
    "is_verified": true,
    "role_ids": ["role-uuid-1", "role-uuid-2"]
  }'
```

### 12. Get User by ID

**Endpoint**: `GET /api/v1/users/{user_id}`

```bash
# Get specific user (admin or own profile)
USER_ID="user-uuid-here"
curl -k -X GET "${BASE_URL}${API_BASE}/users/${USER_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 13. Update User by ID

**Endpoint**: `PUT /api/v1/users/{user_id}`

```bash
# Update user (admin or own profile)
curl -k -X PUT "${BASE_URL}${API_BASE}/users/${USER_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Updated",
    "last_name": "User",
    "is_active": true,
    "is_verified": true,
    "role_ids": ["new-role-uuid"]
  }'
```

### 14. Delete User

**Endpoint**: `DELETE /api/v1/users/{user_id}`

```bash
# Delete user (admin only)
curl -k -X DELETE "${BASE_URL}${API_BASE}/users/${USER_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 15. Update User Password

**Endpoint**: `PUT /api/v1/users/{user_id}/password`

```bash
# Update password (own account)
curl -k -X PUT "${BASE_URL}${API_BASE}/users/${USER_ID}/password" \
  -H "Authorization: Bearer ${USER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "OldPass123!",
    "new_password": "NewPass123!"
  }'
```

### 16. Update User Roles

**Endpoint**: `PUT /api/v1/users/{user_id}/roles`

```bash
# Update user roles (admin only)
curl -k -X PUT "${BASE_URL}${API_BASE}/users/${USER_ID}/roles" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "role_ids": ["role-uuid-1", "role-uuid-2"]
  }'
```

### 17. User Statistics

**Endpoint**: `GET /api/v1/users/stats/overview`

```bash
# Get user statistics (admin only)
curl -k -X GET "${BASE_URL}${API_BASE}/users/stats/overview" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 18. Password Reset Request

**Endpoint**: `POST /api/v1/users/password-reset/request`

```bash
# Request password reset
curl -k -X POST "${BASE_URL}${API_BASE}/users/password-reset/request" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

### 19. Password Reset Confirm

**Endpoint**: `POST /api/v1/users/password-reset/confirm`

```bash
# Confirm password reset
curl -k -X POST "${BASE_URL}${API_BASE}/users/password-reset/confirm" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset-token-here",
    "new_password": "NewSecurePass123!"
  }'
```

### 20. Email Verification Request

**Endpoint**: `POST /api/v1/users/email-verification/request`

```bash
# Request email verification
curl -k -X POST "${BASE_URL}${API_BASE}/users/email-verification/request" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

### 21. Email Verification Confirm

**Endpoint**: `POST /api/v1/users/email-verification/confirm`

```bash
# Confirm email verification
curl -k -X POST "${BASE_URL}${API_BASE}/users/email-verification/confirm" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "verification-token-here"
  }'
```

## Role & Permission Management

### 22. List Roles

**Endpoint**: `GET /api/v1/roles`

```bash
# List all roles
curl -k -X GET "${BASE_URL}${API_BASE}/roles" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# List roles with search and pagination
curl -k -X GET "${BASE_URL}${API_BASE}/roles?search=admin&page=1&per_page=10" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Filter by scope
curl -k -X GET "${BASE_URL}${API_BASE}/roles?scope_id=1" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 23. Create Role

**Endpoint**: `POST /api/v1/roles`

```bash
# Create new role
curl -k -X POST "${BASE_URL}${API_BASE}/roles" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "moderator",
    "description": "Content moderation role",
    "scope_ids": [1, 2, 3]
  }'
```

### 24. Get Role by ID

**Endpoint**: `GET /api/v1/roles/{role_id}`

```bash
# Get specific role
ROLE_ID=1
curl -k -X GET "${BASE_URL}${API_BASE}/roles/${ROLE_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 25. Update Role

**Endpoint**: `PUT /api/v1/roles/{role_id}`

```bash
# Update role
curl -k -X PUT "${BASE_URL}${API_BASE}/roles/${ROLE_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "senior_moderator",
    "description": "Senior content moderation role",
    "scope_ids": [1, 2, 3, 4]
  }'
```

### 26. Delete Role

**Endpoint**: `DELETE /api/v1/roles/{role_id}`

```bash
# Delete role
curl -k -X DELETE "${BASE_URL}${API_BASE}/roles/${ROLE_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 27. Update Role Scopes

**Endpoint**: `PUT /api/v1/roles/{role_id}/scopes`

```bash
# Update role scopes
curl -k -X PUT "${BASE_URL}${API_BASE}/roles/${ROLE_ID}/scopes" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "scope_ids": [1, 2, 5, 6]
  }'
```

### 28. List Scopes

**Endpoint**: `GET /api/v1/roles/scopes`

```bash
# List all scopes
curl -k -X GET "${BASE_URL}${API_BASE}/roles/scopes" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Filter scopes
curl -k -X GET "${BASE_URL}${API_BASE}/roles/scopes?resource=users&action=read" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 29. Create Scope

**Endpoint**: `POST /api/v1/roles/scopes`

```bash
# Create new scope
curl -k -X POST "${BASE_URL}${API_BASE}/roles/scopes" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "read:posts",
    "description": "Read blog posts",
    "resource": "posts",
    "action": "read"
  }'
```

### 30. Get Scope by ID

**Endpoint**: `GET /api/v1/roles/scopes/{scope_id}`

```bash
# Get specific scope
SCOPE_ID=1
curl -k -X GET "${BASE_URL}${API_BASE}/roles/scopes/${SCOPE_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 31. Update Scope

**Endpoint**: `PUT /api/v1/roles/scopes/{scope_id}`

```bash
# Update scope
curl -k -X PUT "${BASE_URL}${API_BASE}/roles/scopes/${SCOPE_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "write:posts",
    "description": "Create and edit blog posts",
    "resource": "posts",
    "action": "write"
  }'
```

### 32. Delete Scope

**Endpoint**: `DELETE /api/v1/roles/scopes/{scope_id}`

```bash
# Delete scope
curl -k -X DELETE "${BASE_URL}${API_BASE}/roles/scopes/${SCOPE_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 33. Check Permission

**Endpoint**: `POST /api/v1/roles/permissions/check`

```bash
# Check user permission
curl -k -X POST "${BASE_URL}${API_BASE}/roles/permissions/check" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-uuid-here",
    "resource": "posts",
    "action": "read"
  }'
```

### 34. Bulk Permission Check

**Endpoint**: `POST /api/v1/roles/permissions/check-bulk`

```bash
# Check multiple permissions
curl -k -X POST "${BASE_URL}${API_BASE}/roles/permissions/check-bulk" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-uuid-here",
    "permissions": [
      {"resource": "posts", "action": "read"},
      {"resource": "posts", "action": "write"},
      {"resource": "users", "action": "read"}
    ]
  }'
```

### 35. Get User Permissions

**Endpoint**: `GET /api/v1/roles/permissions/user/{user_id}`

```bash
# Get all permissions for a user
curl -k -X GET "${BASE_URL}${API_BASE}/roles/permissions/user/${USER_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 36. Role Statistics

**Endpoint**: `GET /api/v1/roles/stats`

```bash
# Get role and permission statistics
curl -k -X GET "${BASE_URL}${API_BASE}/roles/stats" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 37. Default Roles

**Endpoint**: `GET /api/v1/roles/defaults`

```bash
# Get default role definitions
curl -k -X GET "${BASE_URL}${API_BASE}/roles/defaults" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

## Service Client Management

### 38. List Service Clients

**Endpoint**: `GET /api/v1/service-clients`

```bash
# List all service clients
curl -k -X GET "${BASE_URL}${API_BASE}/service-clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Filter service clients
curl -k -X GET "${BASE_URL}${API_BASE}/service-clients?is_active=true&client_type=confidential" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 39. Create Service Client

**Endpoint**: `POST /api/v1/service-clients`

```bash
# Create new service client
curl -k -X POST "${BASE_URL}${API_BASE}/service-clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "API Gateway Client",
    "description": "Main API gateway service client",
    "client_type": "confidential",
    "is_active": true,
    "is_trusted": true,
    "contact_email": "admin@example.com",
    "scope_ids": [1, 2, 3]
  }'
```

### 40. Get Service Client

**Endpoint**: `GET /api/v1/service-clients/{client_id}`

```bash
# Get specific service client
curl -k -X GET "${BASE_URL}${API_BASE}/service-clients/${CLIENT_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 41. Update Service Client

**Endpoint**: `PUT /api/v1/service-clients/{client_id}`

```bash
# Update service client
curl -k -X PUT "${BASE_URL}${API_BASE}/service-clients/${CLIENT_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated API Gateway",
    "description": "Updated description",
    "is_active": true,
    "scope_ids": [1, 2, 3, 4]
  }'
```

### 42. Delete Service Client

**Endpoint**: `DELETE /api/v1/service-clients/{client_id}`

```bash
# Delete service client
curl -k -X DELETE "${BASE_URL}${API_BASE}/service-clients/${CLIENT_ID}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 43. Rotate Client Secret

**Endpoint**: `POST /api/v1/service-clients/{client_id}/rotate-secret`

```bash
# Rotate client secret
curl -k -X POST "${BASE_URL}${API_BASE}/service-clients/${CLIENT_ID}/rotate-secret" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "current_secret": "current-secret-here"
  }'
```

### 44. Update Client Scopes

**Endpoint**: `PUT /api/v1/service-clients/{client_id}/scopes`

```bash
# Update client scopes
curl -k -X PUT "${BASE_URL}${API_BASE}/service-clients/${CLIENT_ID}/scopes" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "scope_ids": [1, 2, 5, 6]
  }'
```

### 45. Get Client Permissions

**Endpoint**: `GET /api/v1/service-clients/{client_id}/permissions`

```bash
# Get client permissions
curl -k -X GET "${BASE_URL}${API_BASE}/service-clients/${CLIENT_ID}/permissions" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 46. Get Client Rate Limit

**Endpoint**: `GET /api/v1/service-clients/{client_id}/rate-limit`

```bash
# Get client rate limit status
curl -k -X GET "${BASE_URL}${API_BASE}/service-clients/${CLIENT_ID}/rate-limit" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 47. Test Client Webhook

**Endpoint**: `POST /api/v1/service-clients/{client_id}/webhook/test`

```bash
# Test client webhook
curl -k -X POST "${BASE_URL}${API_BASE}/service-clients/${CLIENT_ID}/webhook/test" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "test_data": {"message": "test webhook"}
  }'
```

### 48. Service Client Statistics

**Endpoint**: `GET /api/v1/service-clients/stats/overview`

```bash
# Get service client statistics
curl -k -X GET "${BASE_URL}${API_BASE}/service-clients/stats/overview" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 49. Service Clients Health Check

**Endpoint**: `GET /api/v1/service-clients/health/check`

```bash
# Check service clients health
curl -k -X GET "${BASE_URL}${API_BASE}/service-clients/health/check" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

## Session Management

### 50. Get User Sessions

**Endpoint**: `GET /api/v1/sessions`

```bash
# Get current user's sessions
curl -k -X GET "${BASE_URL}${API_BASE}/sessions" \
  -H "Authorization: Bearer ${USER_TOKEN}"
```

### 51. Renew Session

**Endpoint**: `POST /api/v1/sessions/{session_id}/renew`

```bash
# Renew specific session
SESSION_ID="session-id-here"
curl -k -X POST "${BASE_URL}${API_BASE}/sessions/${SESSION_ID}/renew" \
  -H "Authorization: Bearer ${USER_TOKEN}"
```

### 52. Invalidate Session

**Endpoint**: `DELETE /api/v1/sessions/{session_id}`

```bash
# Invalidate specific session
curl -k -X DELETE "${BASE_URL}${API_BASE}/sessions/${SESSION_ID}" \
  -H "Authorization: Bearer ${USER_TOKEN}"
```

### 53. Invalidate All Sessions

**Endpoint**: `DELETE /api/v1/sessions`

```bash
# Invalidate all user sessions
curl -k -X DELETE "${BASE_URL}${API_BASE}/sessions" \
  -H "Authorization: Bearer ${USER_TOKEN}"
```

### 54. Session Statistics

**Endpoint**: `GET /api/v1/sessions/stats`

```bash
# Get session statistics (admin only)
curl -k -X GET "${BASE_URL}${API_BASE}/sessions/stats" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 55. Cleanup Expired Sessions

**Endpoint**: `POST /api/v1/sessions/cleanup`

```bash
# Cleanup expired sessions (admin only)
curl -k -X POST "${BASE_URL}${API_BASE}/sessions/cleanup" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

## Administrative Endpoints

### 56. Dashboard Statistics

**Endpoint**: `GET /api/v1/admin/dashboard/stats`

```bash
# Get comprehensive dashboard statistics
curl -k -X GET "${BASE_URL}${API_BASE}/admin/dashboard/stats" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 57. System Health

**Endpoint**: `GET /api/v1/admin/system/health`

```bash
# Get system health status
curl -k -X GET "${BASE_URL}${API_BASE}/admin/system/health" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 58. Security Events

**Endpoint**: `GET /api/v1/admin/security/events`

```bash
# Get security events
curl -k -X GET "${BASE_URL}${API_BASE}/admin/security/events" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Filter security events
curl -k -X GET "${BASE_URL}${API_BASE}/admin/security/events?event_type=failed_login&severity=high&hours=24" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 59. Maintenance Cleanup

**Endpoint**: `POST /api/v1/admin/maintenance/cleanup`

```bash
# Run maintenance cleanup
curl -k -X POST "${BASE_URL}${API_BASE}/admin/maintenance/cleanup" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 60. System Backup

**Endpoint**: `POST /api/v1/admin/maintenance/backup`

```bash
# Create system backup
curl -k -X POST "${BASE_URL}${API_BASE}/admin/maintenance/backup" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 61. Audit Activity

**Endpoint**: `GET /api/v1/admin/audit/activity`

```bash
# Get audit activity
curl -k -X GET "${BASE_URL}${API_BASE}/admin/audit/activity" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Filter audit activity
curl -k -X GET "${BASE_URL}${API_BASE}/admin/audit/activity?user_id=123&action=user_created&hours=48" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 62. Usage Report

**Endpoint**: `GET /api/v1/admin/reports/usage`

```bash
# Get usage report
curl -k -X GET "${BASE_URL}${API_BASE}/admin/reports/usage" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Usage report for specific period
curl -k -X GET "${BASE_URL}${API_BASE}/admin/reports/usage?days=30" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 63. Reload Configuration

**Endpoint**: `POST /api/v1/admin/config/reload`

```bash
# Reload system configuration
curl -k -X POST "${BASE_URL}${API_BASE}/admin/config/reload" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 64. Error Logs

**Endpoint**: `GET /api/v1/admin/logs/errors`

```bash
# Get error logs
curl -k -X GET "${BASE_URL}${API_BASE}/admin/