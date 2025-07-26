# User Management API Reference

This document provides comprehensive API reference for user management endpoints in the Keystone Authentication System.

## Base URL

```
/api/v1/users
```

## Authentication

All user management endpoints require authentication via Bearer token in the Authorization header:

```
Authorization: Bearer <access_token>
```

## Endpoints

### Create User

Create a new user account.

**Endpoint:** `POST /api/v1/users`

**Required Scopes:** `admin:users` or `write:users`

**Request Body:**
```json
{
  "username": "string",
  "email": "string",
  "password": "string",
  "first_name": "string",
  "last_name": "string",
  "display_name": "string",
  "bio": "string",
  "is_active": true,
  "is_verified": false,
  "roles": ["user"]
}
```

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "first_name": "string",
  "last_name": "string",
  "display_name": "string",
  "bio": "string",
  "is_active": true,
  "is_verified": false,
  "is_superuser": false,
  "created_at": "2025-01-26T17:21:00Z",
  "updated_at": "2025-01-26T17:21:00Z",
  "last_login": null,
  "role_names": ["user"],
  "scope_names": ["read:profile"]
}
```

### Get Current User

Get the current authenticated user's profile.

**Endpoint:** `GET /api/v1/users/me`

**Required Scopes:** `read:profile`

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "first_name": "string",
  "last_name": "string",
  "display_name": "string",
  "bio": "string",
  "is_active": true,
  "is_verified": true,
  "is_superuser": false,
  "created_at": "2025-01-26T17:21:00Z",
  "updated_at": "2025-01-26T17:21:00Z",
  "last_login": "2025-01-26T17:21:00Z",
  "role_names": ["user"],
  "scope_names": ["read:profile", "write:profile"]
}
```

### Update Current User

Update the current authenticated user's profile.

**Endpoint:** `PUT /api/v1/users/me`

**Required Scopes:** `write:profile`

**Request Body:**
```json
{
  "first_name": "string",
  "last_name": "string",
  "display_name": "string",
  "bio": "string"
}
```

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "first_name": "Updated Name",
  "last_name": "string",
  "display_name": "string",
  "bio": "Updated bio",
  "is_active": true,
  "is_verified": true,
  "is_superuser": false,
  "created_at": "2025-01-26T17:21:00Z",
  "updated_at": "2025-01-26T17:21:30Z",
  "last_login": "2025-01-26T17:21:00Z",
  "role_names": ["user"],
  "scope_names": ["read:profile", "write:profile"]
}
```

### Change Password

Change the current user's password.

**Endpoint:** `POST /api/v1/users/me/change-password`

**Required Scopes:** `write:profile`

**Request Body:**
```json
{
  "current_password": "string",
  "new_password": "string"
}
```

**Response:** `200 OK`
```json
{
  "message": "Password changed successfully"
}
```

### List Users

List all users (admin only).

**Endpoint:** `GET /api/v1/users`

**Required Scopes:** `admin:users` or `read:users`

**Query Parameters:**
- `page` (integer): Page number (default: 1)
- `per_page` (integer): Items per page (default: 20, max: 100)
- `search` (string): Search term for username or email
- `is_active` (boolean): Filter by active status
- `role` (string): Filter by role name

**Response:** `200 OK`
```json
{
  "users": [
    {
      "id": "uuid",
      "username": "string",
      "email": "string",
      "first_name": "string",
      "last_name": "string",
      "display_name": "string",
      "is_active": true,
      "is_verified": true,
      "is_superuser": false,
      "created_at": "2025-01-26T17:21:00Z",
      "updated_at": "2025-01-26T17:21:00Z",
      "last_login": "2025-01-26T17:21:00Z",
      "role_names": ["user"]
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 20,
  "pages": 1
}
```

### Get User by ID

Get a specific user by ID (admin only).

**Endpoint:** `GET /api/v1/users/{user_id}`

**Required Scopes:** `admin:users` or `read:users`

**Path Parameters:**
- `user_id` (UUID): User ID

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "first_name": "string",
  "last_name": "string",
  "display_name": "string",
  "bio": "string",
  "is_active": true,
  "is_verified": true,
  "is_superuser": false,
  "created_at": "2025-01-26T17:21:00Z",
  "updated_at": "2025-01-26T17:21:00Z",
  "last_login": "2025-01-26T17:21:00Z",
  "role_names": ["user"],
  "scope_names": ["read:profile", "write:profile"]
}
```

### Update User

Update a specific user (admin only).

**Endpoint:** `PUT /api/v1/users/{user_id}`

**Required Scopes:** `admin:users` or `write:users`

**Path Parameters:**
- `user_id` (UUID): User ID

**Request Body:**
```json
{
  "first_name": "string",
  "last_name": "string",
  "display_name": "string",
  "bio": "string",
  "is_active": true,
  "is_verified": true
}
```

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "first_name": "Updated Name",
  "last_name": "string",
  "display_name": "string",
  "bio": "Updated bio",
  "is_active": true,
  "is_verified": true,
  "is_superuser": false,
  "created_at": "2025-01-26T17:21:00Z",
  "updated_at": "2025-01-26T17:21:30Z",
  "last_login": "2025-01-26T17:21:00Z",
  "role_names": ["user"],
  "scope_names": ["read:profile", "write:profile"]
}
```

### Delete User

Delete a specific user (admin only).

**Endpoint:** `DELETE /api/v1/users/{user_id}`

**Required Scopes:** `admin:users`

**Path Parameters:**
- `user_id` (UUID): User ID

**Response:** `200 OK`
```json
{
  "message": "User deleted successfully"
}
```

### Assign Role to User

Assign a role to a user (admin only).

**Endpoint:** `POST /api/v1/users/{user_id}/roles`

**Required Scopes:** `admin:users`

**Path Parameters:**
- `user_id` (UUID): User ID

**Request Body:**
```json
{
  "role_name": "string"
}
```

**Response:** `200 OK`
```json
{
  "message": "Role assigned successfully",
  "user_id": "uuid",
  "role_name": "string"
}
```

### Remove Role from User

Remove a role from a user (admin only).

**Endpoint:** `DELETE /api/v1/users/{user_id}/roles/{role_name}`

**Required Scopes:** `admin:users`

**Path Parameters:**
- `user_id` (UUID): User ID
- `role_name` (string): Role name

**Response:** `200 OK`
```json
{
  "message": "Role removed successfully",
  "user_id": "uuid",
  "role_name": "string"
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
  "error": "user_not_found",
  "error_description": "User not found"
}
```

### 409 Conflict
```json
{
  "error": "user_exists",
  "error_description": "User with this username or email already exists"
}
```

## Examples

### Creating a New User

```bash
curl -X POST "https://api.example.com/api/v1/users" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "SecurePassword123!",
    "first_name": "John",
    "last_name": "Doe",
    "roles": ["user"]
  }'
```

### Getting Current User Profile

```bash
curl -X GET "https://api.example.com/api/v1/users/me" \
  -H "Authorization: Bearer <access_token>"
```

### Updating User Profile

```bash
curl -X PUT "https://api.example.com/api/v1/users/me" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Smith",
    "bio": "Updated biography"
  }'
```

### Changing Password

```bash
curl -X POST "https://api.example.com/api/v1/users/me/change-password" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "OldPassword123!",
    "new_password": "NewSecurePassword123!"
  }'