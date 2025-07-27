# 🚀 Quick Start Guide

Get up and running with Keystone Authentication System in minutes! This guide assumes you've completed the [installation](installation.md).

## 🎯 Overview

Keystone provides:
- **User Authentication**: Login/logout with JWT tokens
- **Role-Based Access Control**: Flexible permissions system
- **Service-to-Service Auth**: Client credentials flow
- **Token Management**: Secure token generation and validation

## ⚡ 5-Minute Setup

### 1. Start the System

```bash
# Using Docker Compose (recommended)
docker-compose up -d

# Or locally
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Verify Health

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "keystone-auth",
  "version": "1.0.0",
  "environment": "development"
}
```

### 3. Access API Documentation

Open your browser to:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🔐 Basic Authentication Flow

### Step 1: Create a User Account

```bash
curl -X POST "http://localhost:8000/api/v1/users/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePassword123!",
    "first_name": "Test",
    "last_name": "User"
  }'
```

### Step 2: Login and Get Tokens

```bash
curl -X POST "http://localhost:8000/api/v1/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=SecurePassword123!"
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read:profile"
}
```

### Step 3: Use Access Token

```bash
# Get user profile
curl -X GET "http://localhost:8000/api/v1/users/profile" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Step 4: Refresh Token

```bash
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN"
  }'
```

## 🏢 Service-to-Service Authentication

### Create Service Client

```bash
curl -X POST "http://localhost:8000/api/v1/admin/clients" \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-service",
    "name": "My Service",
    "description": "Internal service client",
    "scopes": ["service:api"]
  }'
```

### Get Service Token

```bash
curl -X POST "http://localhost:8000/api/v1/auth/service-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=my-service&client_secret=generated-secret&scope=service:api"
```

## 🎭 Role-Based Access Control

### Default Roles

Keystone comes with these default roles:

| Role | Description | Default Scopes |
|------|-------------|----------------|
| `user` | Basic user access | `read:profile`, `write:profile` |
| `admin` | Administrative access | `admin:users`, `admin:clients` |
| `service` | Service-to-service | `service:api` |

### Assign Role to User

```bash
curl -X POST "http://localhost:8000/api/v1/admin/users/{user_id}/roles" \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role_name": "admin"
  }'
```

## 🔧 Configuration Examples

### Environment Variables

```bash
# Development
export ENVIRONMENT=development
export DEBUG=true
export JWT_SECRET_KEY=dev-secret-key
export ACCESS_TOKEN_EXPIRE_MINUTES=15

# Production
export ENVIRONMENT=production
export DEBUG=false
export JWT_SECRET_KEY=super-secure-production-key
export DATABASE_URL=postgresql+asyncpg://user:pass@prod-db:5432/keystone
```

### Custom Password Policy

```python
# In your .env file
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGITS=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_PREVENT_REUSE_COUNT=5
```

## 🧪 Testing Your Setup

### Run Unit Tests

```bash
# All tests
pytest

# Specific test categories
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
pytest -m security      # Security tests only
```

### Test Authentication Flow

```bash
# Run the test script
python scripts/test_auth_flow.py
```

### Load Testing

```bash
# Install locust
pip install locust

# Run load test
locust -f tests/load/test_auth_load.py --host=http://localhost:8000
```

## 📊 Monitoring and Health Checks

### Health Endpoints

```bash
# Basic health check
curl http://localhost:8000/health

# Detailed health (requires authentication)
curl -H "Authorization: Bearer TOKEN" http://localhost:8000/health/detailed
```

### Metrics

```bash
# Prometheus metrics
curl http://localhost:8000/metrics
```

### Logs

```bash
# View application logs
docker-compose logs -f keystone-app

# View database logs
docker-compose logs -f postgres

# View Redis logs
docker-compose logs -f redis
```

## 🔍 Common Use Cases

### Web Application Integration

```javascript
// Frontend JavaScript example
const response = await fetch('http://localhost:8000/api/v1/auth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: 'username=user&password=pass'
});

const tokens = await response.json();
localStorage.setItem('access_token', tokens.access_token);
```

### Mobile App Integration

```swift
// iOS Swift example
let url = URL(string: "http://localhost:8000/api/v1/auth/token")!
var request = URLRequest(url: url)
request.httpMethod = "POST"
request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
request.httpBody = "username=user&password=pass".data(using: .utf8)
```

### Microservice Integration

```python
# Python service example
import httpx

async def get_service_token():
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://keystone:8000/api/v1/auth/service-token",
            data={
                "client_id": "my-service",
                "client_secret": "secret",
                "scope": "service:api"
            }
        )
        return response.json()["access_token"]
```

## 🚨 Troubleshooting

### Common Issues

#### "Token has expired"
```bash
# Use refresh token to get new access token
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
```

#### "Invalid credentials"
- Check username/password are correct
- Ensure user account is active
- Verify account is not locked

#### "Insufficient permissions"
- Check user has required roles/scopes
- Verify token contains correct claims
- Ensure token is not expired

#### Connection refused
```bash
# Check if services are running
docker-compose ps

# Restart services
docker-compose restart
```

## 📚 Next Steps

Now that you have Keystone running:

1. **[Configuration Guide](configuration.md)** - Customize settings for your needs
2. **[API Documentation](../api/authentication.md)** - Explore all available endpoints
3. **[Architecture Overview](../architecture/overview.md)** - Understand the system design
4. **[Security Guide](../security/security-guide.md)** - Learn about security features
5. **[Testing Guide](../development/testing.md)** - Write tests for your integration

## 🎉 Success!

You now have a fully functional authentication system! 

Key achievements:
- ✅ System is running and healthy
- ✅ User registration and login working
- ✅ JWT tokens being generated and validated
- ✅ Role-based access control configured
- ✅ Service-to-service authentication enabled

Ready to integrate with your applications and build secure, scalable systems!

---

**Need help?** Check the [troubleshooting guide](../development/troubleshooting.md) or [create an issue](https://github.com/your-org/keystone/issues).