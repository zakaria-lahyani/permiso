# Roles and Permissions API Reference

This document provides comprehensive API reference for role and permission management endpoints in the Keystone Authentication System.

## Base URL

```
/api/v1/roles
```

## Authentication

All role management endpoints require authentication via Bearer token in the Authorization header:

```
Authorization: Bearer <access_token>
```

## Endpoints

### Create Role

Create a new role with specified permissions.

**Endpoint:** `POST /api/v1/roles`

**Required Scopes:** `admin:roles` or `write:roles`

**Request Body:**
```json
{
  "name": "string",
  "description": "string",
  "scopes": ["read:profile", "write:profile"],
  "is_default": false
}
```

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "is_default": false,
  "created_at": "2025-01-26T17:22:00Z",
  "updated_at": "2025-01-26T17:22:00Z",
  "scopes": [
    {
      "id": "uuid",
      "name": "read:profile",
      "description": "Read user profile",
      "resource": "profile",
      "action": "read"
    }
  ],
  "user_count": 0
}
```

### List Roles

List all available roles.

**Endpoint:** `GET /api/v1/roles`

**Required Scopes:** `admin:roles` or `read:roles`

**Query Parameters:**
- `page` (integer): Page number (default: 1)
- `per_page` (integer): Items per page (default: 20, max: 100)
- `search` (string): Search term for role name or description
- `include_scopes` (boolean): Include scope details (default: false)

**Response:** `200 OK`
```json
{
  "roles": [
    {
      "id": "uuid",
      "name": "user",
      "description": "Standard user role",
      "is_default": true,
      "created_at": "2025-01-26T17:22:00Z",
      "updated_at": "2025-01-26T17:22:00Z",
      "user_count": 150,
      "scope_count": 5
    },
    {
      "id": "uuid",
      "name": "admin",
      "description": "Administrator role",
      "is_default": false,
      "created_at": "2025-01-26T17:22:00Z",
      "updated_at": "2025-01-26T17:22:00Z",
      "user_count": 3,
      "scope_count": 25
    }
  ],
  "total": 2,
  "page": 1,
  "per_page": 20,
  "pages": 1
}
```

### Get Role by ID

Get a specific role by ID.

**Endpoint:** `GET /api/v1/roles/{role_id}`

**Required Scopes:** `admin:roles` or `read:roles`

**Path Parameters:**
- `role_id` (UUID): Role ID

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "name": "user",
  "description": "Standard user role",
  "is_default": true,
  "created_at": "2025-01-26T17:22:00Z",
  "updated_at": "2025-01-26T17:22:00Z",
  "scopes": [
    {
      "id": "uuid",
      "name": "read:profile",
      "description": "Read user profile",
      "resource": "profile",
      "action": "read"
    },
    {
      "id": "uuid",
      "name": "write:profile",
      "description": "Write user profile",
      "resource": "profile",
      "action": "write"
    }
  ],
  "user_count": 150
}
```

### Update Role

Update a specific role.

**Endpoint:** `PUT /api/v1/roles/{role_id}`

**Required Scopes:** `admin:roles` or `write:roles`

**Path Parameters:**
- `role_id` (UUID): Role ID

**Request Body:**
```json
{
  "description": "Updated role description",
  "scopes": ["read:profile", "write:profile", "read:settings"]
}
```

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "name": "user",
  "description": "Updated role description",
  "is_default": true,
  "created_at": "2025-01-26T17:22:00Z",
  "updated_at": "2025-01-26T17:22:30Z",
  "scopes": [
    {
      "id": "uuid",
      "name": "read:profile",
      "description": "Read user profile",
      "resource": "profile",
      "action": "read"
    },
    {
      "id": "uuid",
      "name": "write:profile",
      "description": "Write user profile",
      "resource": "profile",
      "action": "write"
    },
    {
      "id": "uuid",
      "name": "read:settings",
      "description": "Read user settings",
      "resource": "settings",
      "action": "read"
    }
  ],
  "user_count": 150
}
```

### Delete Role

Delete a specific role.

**Endpoint:** `DELETE /api/v1/roles/{role_id}`

**Required Scopes:** `admin:roles`

**Path Parameters:**
- `role_id` (UUID): Role ID

**Response:** `200 OK`
```json
{
  "message": "Role deleted successfully"
}
```

### Assign Scope to Role

Assign a scope (permission) to a role.

**Endpoint:** `POST /api/v1/roles/{role_id}/scopes`

**Required Scopes:** `admin:roles`

**Path Parameters:**
- `role_id` (UUID): Role ID

**Request Body:**
```json
{
  "scope_name": "read:analytics"
}
```

**Response:** `200 OK`
```json
{
  "message": "Scope assigned to role successfully",
  "role_id": "uuid",
  "scope_name": "read:analytics"
}
```

### Remove Scope from Role

Remove a scope (permission) from a role.

**Endpoint:** `DELETE /api/v1/roles/{role_id}/scopes/{scope_name}`

**Required Scopes:** `admin:roles`

**Path Parameters:**
- `role_id` (UUID): Role ID
- `scope_name` (string): Scope name

**Response:** `200 OK`
```json
{
  "message": "Scope removed from role successfully",
  "role_id": "uuid",
  "scope_name": "read:analytics"
}
```

### Get Role Statistics

Get statistics for a specific role.

**Endpoint:** `GET /api/v1/roles/{role_id}/stats`

**Required Scopes:** `admin:roles`

**Path Parameters:**
- `role_id` (UUID): Role ID

**Response:** `200 OK`
```json
{
  "role_id": "uuid",
  "role_name": "user",
  "user_count": 150,
  "scope_count": 5,
  "active_users": 142,
  "recent_assignments": 12,
  "created_at": "2025-01-26T17:22:00Z"
}
```

## Scope Management

### List Available Scopes

List all available scopes (permissions).

**Endpoint:** `GET /api/v1/roles/scopes`

**Required Scopes:** `admin:roles` or `read:roles`

**Query Parameters:**
- `page` (integer): Page number (default: 1)
- `per_page` (integer): Items per page (default: 20, max: 100)
- `resource` (string): Filter by resource name
- `action` (string): Filter by action type

**Response:** `200 OK`
```json
{
  "scopes": [
    {
      "id": "uuid",
      "name": "read:profile",
      "description": "Read user profile",
      "resource": "profile",
      "action": "read",
      "created_at": "2025-01-26T17:22:00Z",
      "role_count": 2
    },
    {
      "id": "uuid",
      "name": "write:profile",
      "description": "Write user profile",
      "resource": "profile",
      "action": "write",
      "created_at": "2025-01-26T17:22:00Z",
      "role_count": 1
    }
  ],
  "total": 2,
  "page": 1,
  "per_page": 20,
  "pages": 1
}
```

### Create Scope

Create a new scope (permission).

**Endpoint:** `POST /api/v1/roles/scopes`

**Required Scopes:** `admin:roles`

**Request Body:**
```json
{
  "name": "read:analytics",
  "description": "Read analytics data",
  "resource": "analytics",
  "action": "read"
}
```

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "name": "read:analytics",
  "description": "Read analytics data",
  "resource": "analytics",
  "action": "read",
  "created_at": "2025-01-26T17:22:00Z",
  "updated_at": "2025-01-26T17:22:00Z",
  "role_count": 0
}
```

### Get Scope by Name

Get a specific scope by name.

**Endpoint:** `GET /api/v1/roles/scopes/{scope_name}`

**Required Scopes:** `admin:roles` or `read:roles`

**Path Parameters:**
- `scope_name` (string): Scope name

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "name": "read:profile",
  "description": "Read user profile",
  "resource": "profile",
  "action": "read",
  "created_at": "2025-01-26T17:22:00Z",
  "updated_at": "2025-01-26T17:22:00Z",
  "roles": [
    {
      "id": "uuid",
      "name": "user",
      "description": "Standard user role"
    },
    {
      "id": "uuid",
      "name": "admin",
      "description": "Administrator role"
    }
  ],
  "role_count": 2
}
```

### Update Scope

Update a specific scope.

**Endpoint:** `PUT /api/v1/roles/scopes/{scope_name}`

**Required Scopes:** `admin:roles`

**Path Parameters:**
- `scope_name` (string): Scope name

**Request Body:**
```json
{
  "description": "Updated scope description"
}
```

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "name": "read:profile",
  "description": "Updated scope description",
  "resource": "profile",
  "action": "read",
  "created_at": "2025-01-26T17:22:00Z",
  "updated_at": "2025-01-26T17:22:30Z",
  "role_count": 2
}
```

### Delete Scope

Delete a specific scope.

**Endpoint:** `DELETE /api/v1/roles/scopes/{scope_name}`

**Required Scopes:** `admin:roles`

**Path Parameters:**
- `scope_name` (string): Scope name

**Response:** `200 OK`
```json
{
  "message": "Scope deleted successfully"
}
```

## Permission Checking

### Check User Permission

Check if a user has a specific permission.

**Endpoint:** `POST /api/v1/roles/check-permission`

**Required Scopes:** `admin:roles` or `read:roles`

**Request Body:**
```json
{
  "user_id": "uuid",
  "scope_name": "read:profile"
}
```

**Response:** `200 OK`
```json
{
  "user_id": "uuid",
  "scope_name": "read:profile",
  "has_permission": true,
  "granted_via": ["user", "admin"]
}
```

## Error Responses

### 400 Bad Request
```json
{
  "error": "validation_error",
  "error_description": "Invalid input data",
  "details": {
    "field": "error message"
  }
}
```

### 401 Unauthorized
```json
{
  "error": "unauthorized",
  "error_description": "Authentication required"
}
```

### 403 Forbidden
```json
{
  "error": "insufficient_permissions",
  "error_description": "Insufficient permissions for this operation"
}
```

### 404 Not Found
```json
{
  "error": "role_not_found",
  "error_description": "Role not found"
}
```

### 409 Conflict
```json
{
  "error": "role_exists",
  "error_description": "Role with this name already exists"
}
```

## Examples

### Creating a New Role

```bash
curl -X POST "https://api.example.com/api/v1/roles" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "moderator",
    "description": "Content moderator role",
    "scopes": ["read:content", "write:content", "moderate:content"],
    "is_default": false
  }'
```

### Listing All Roles

```bash
curl -X GET "https://api.example.com/api/v1/roles?include_scopes=true" \
  -H "Authorization: Bearer <access_token>"
```

### Assigning a Scope to a Role

```bash
curl -X POST "https://api.example.com/api/v1/roles/{role_id}/scopes" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "scope_name": "admin:users"
  }'
```

### Checking User Permission

```bash
curl -X POST "https://api.example.com/api/v1/roles/check-permission" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "uuid",
    "scope_name": "read:analytics"
  }'
```

## Common Scopes

Here are some common scopes used in the system:

### Profile Management
- `read:profile` - Read user profile
- `write:profile` - Update user profile
- `admin:profile` - Full profile management

### User Management
- `read:users` - List and view users
- `write:users` - Create and update users
- `admin:users` - Full user management including deletion

### Role Management
- `read:roles` - View roles and permissions
- `write:roles` - Create and update roles
- `admin:roles` - Full role management

### System Administration
- `admin:system` - System-wide administration
- `read:analytics` - View system analytics
- `admin:tokens` - Token management and introspection

### Session Management
- `read:sessions` - View user sessions
- `admin:sessions` - Manage all user sessions