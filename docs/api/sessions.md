# Session Management API Reference

This document provides comprehensive API reference for session management endpoints in the Keystone Authentication System.

## Base URL

```
/api/v1/sessions
```

## Authentication

All session management endpoints require authentication via Bearer token in the Authorization header:

```
Authorization: Bearer <access_token>
```

## Overview

The session management system provides basic session persistence, renewal, and tracking capabilities. Sessions are created automatically during login and can be managed through these endpoints.

## Endpoints

### Get User Sessions

Get all active sessions for the current authenticated user.

**Endpoint:** `GET /api/v1/sessions`

**Required Scopes:** `read:profile` (user's own sessions)

**Response:** `200 OK`
```json
{
  "sessions": [
    {
      "session_id": "uuid",
      "user_id": 123,
      "username": "johndoe",
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "created_at": "2025-01-26T17:23:00Z",
      "last_activity": "2025-01-26T17:23:00Z",
      "expires_at": "2025-01-26T18:23:00Z"
    },
    {
      "session_id": "uuid",
      "user_id": 123,
      "username": "johndoe",
      "ip_address": "10.0.0.50",
      "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
      "created_at": "2025-01-26T16:30:00Z",
      "last_activity": "2025-01-26T17:20:00Z",
      "expires_at": "2025-01-26T18:30:00Z"
    }
  ],
  "total": 2
}
```

### Renew Session

Renew a specific session to extend its expiry time.

**Endpoint:** `POST /api/v1/sessions/{session_id}/renew`

**Required Scopes:** `read:profile` (user's own sessions)

**Path Parameters:**
- `session_id` (string): Session ID to renew

**Response:** `200 OK`
```json
{
  "message": "Session renewed successfully",
  "session_id": "uuid",
  "expires_at": "2025-01-26T19:23:00Z"
}
```

**Error Responses:**

**404 Not Found**
```json
{
  "error": "session_not_found",
  "error_description": "Session not found"
}
```

**403 Forbidden**
```json
{
  "error": "access_denied",
  "error_description": "Access denied to this session"
}
```

**400 Bad Request**
```json
{
  "error": "renewal_failed",
  "error_description": "Session renewal failed"
}
```

### Invalidate Session

Invalidate (terminate) a specific session immediately.

**Endpoint:** `DELETE /api/v1/sessions/{session_id}`

**Required Scopes:** `read:profile` (user's own sessions)

**Path Parameters:**
- `session_id` (string): Session ID to invalidate

**Response:** `200 OK`
```json
{
  "message": "Session invalidated successfully",
  "session_id": "uuid"
}
```

**Error Responses:**

**404 Not Found**
```json
{
  "error": "session_not_found",
  "error_description": "Session not found"
}
```

**403 Forbidden**
```json
{
  "error": "access_denied",
  "error_description": "Access denied to this session"
}
```

### Invalidate All Sessions

Invalidate all sessions for the current authenticated user.

**Endpoint:** `DELETE /api/v1/sessions`

**Required Scopes:** `read:profile`

**Response:** `200 OK`
```json
{
  "message": "All sessions invalidated successfully",
  "sessions_terminated": 3
}
```

### Get Session Statistics (Admin)

Get session statistics across the system.

**Endpoint:** `GET /api/v1/sessions/stats`

**Required Scopes:** `admin:sessions`

**Response:** `200 OK`
```json
{
  "active_sessions": 1250,
  "sessions_created_today": 340,
  "expired_sessions": 45,
  "total_sessions": 1295
}
```

### Cleanup Expired Sessions (Admin)

Clean up expired sessions from the system.

**Endpoint:** `POST /api/v1/sessions/cleanup`

**Required Scopes:** `admin:sessions`

**Response:** `200 OK`
```json
{
  "message": "Expired sessions cleaned up successfully",
  "sessions_cleaned": 45
}
```

## Session Creation

Sessions are automatically created during the login process. When a user successfully authenticates via the `/api/v1/auth/token` endpoint, a session is created and the `session_id` is returned in the token response:

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "scope": "read:profile write:profile",
  "session_id": "uuid"
}
```

## Session Properties

Each session contains the following information:

- **session_id**: Unique identifier for the session
- **user_id**: ID of the user who owns the session
- **username**: Username of the session owner
- **ip_address**: IP address where the session was created
- **user_agent**: Browser/client user agent string
- **created_at**: When the session was created
- **last_activity**: Last time the session was used
- **expires_at**: When the session expires
- **is_active**: Whether the session is currently active
- **access_token_jti**: JWT ID of the associated access token
- **refresh_token_jti**: JWT ID of the associated refresh token

## Session Lifecycle

1. **Creation**: Sessions are created automatically during login
2. **Activity Tracking**: Session activity is updated when tokens are used
3. **Renewal**: Sessions can be renewed to extend their lifetime
4. **Expiration**: Sessions automatically expire after the configured duration
5. **Invalidation**: Sessions can be manually invalidated by the user or admin
6. **Cleanup**: Expired sessions are periodically cleaned up

## Security Considerations

- Sessions are tied to specific IP addresses and user agents for security
- Users can only manage their own sessions (unless they have admin privileges)
- Session invalidation also revokes associated tokens
- Expired sessions are automatically cleaned up to prevent database bloat

## Examples

### Getting Current User's Sessions

```bash
curl -X GET "https://api.example.com/api/v1/sessions" \
  -H "Authorization: Bearer <access_token>"
```

### Renewing a Session

```bash
curl -X POST "https://api.example.com/api/v1/sessions/uuid/renew" \
  -H "Authorization: Bearer <access_token>"
```

### Invalidating a Specific Session

```bash
curl -X DELETE "https://api.example.com/api/v1/sessions/uuid" \
  -H "Authorization: Bearer <access_token>"
```

### Invalidating All Sessions (Logout from all devices)

```bash
curl -X DELETE "https://api.example.com/api/v1/sessions" \
  -H "Authorization: Bearer <access_token>"
```

### Getting Session Statistics (Admin)

```bash
curl -X GET "https://api.example.com/api/v1/sessions/stats" \
  -H "Authorization: Bearer <admin_access_token>"
```

### Cleaning Up Expired Sessions (Admin)

```bash
curl -X POST "https://api.example.com/api/v1/sessions/cleanup" \
  -H "Authorization: Bearer <admin_access_token>"
```

## Integration with Authentication

Sessions work seamlessly with the authentication system:

1. **Login**: Creates a new session and returns session_id
2. **Token Refresh**: Updates session activity timestamp
3. **Logout**: Invalidates the current session and associated tokens
4. **Token Revocation**: Can invalidate associated sessions

## Configuration

Session behavior can be configured through environment variables:

- `ACCESS_TOKEN_EXPIRE_MINUTES`: Default session duration (matches access token lifetime)
- `CACHE_SESSION_PREFIX`: Redis prefix for session caching
- `CACHE_DEFAULT_TTL`: Default cache TTL for sessions

## Best Practices

1. **Monitor Active Sessions**: Regularly check active sessions for suspicious activity
2. **Implement Session Limits**: Consider implementing maximum concurrent session limits per user
3. **Regular Cleanup**: Run session cleanup periodically to maintain database performance
4. **Security Monitoring**: Monitor sessions for unusual IP addresses or user agents
5. **User Education**: Educate users about managing their active sessions

## Error Handling

All session endpoints return appropriate HTTP status codes and error messages:

- `200 OK`: Successful operation
- `400 Bad Request`: Invalid request or operation failed
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions or access denied
- `404 Not Found`: Session not found
- `500 Internal Server Error`: Server error

Error responses follow the standard format:
```json
{
  "error": "error_code",
  "error_description": "Human-readable error description"
}