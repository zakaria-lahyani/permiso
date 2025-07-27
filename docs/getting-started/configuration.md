# ⚙️ Configuration Guide

This guide covers all configuration options for the Keystone Authentication System, from basic setup to advanced production configurations.

## 📋 Configuration Overview

Keystone uses a hierarchical configuration system:

1. **Default values** - Built-in sensible defaults
2. **Environment variables** - Override defaults via `.env` file or system env vars
3. **Runtime configuration** - Dynamic configuration through admin API

## 🔧 Environment Variables

### Application Settings

```bash
# Application Identity
APP_NAME="Keystone Authentication API"
VERSION="1.0.0"
ENVIRONMENT=development  # development, testing, production
DEBUG=true              # Enable debug mode (disable in production)

# Server Configuration
HOST=0.0.0.0           # Bind address
PORT=8000              # Port number
```

### Database Configuration

```bash
# PostgreSQL Connection
DATABASE_URL=postgresql+asyncpg://keystone:password@localhost:5432/keystone
DATABASE_POOL_SIZE=20          # Connection pool size
DATABASE_MAX_OVERFLOW=0        # Max overflow connections
DATABASE_ECHO=false           # Log SQL queries (debug only)

# Connection Examples
# Local: postgresql+asyncpg://user:pass@localhost:5432/keystone
# Docker: postgresql+asyncpg://user:pass@postgres:5432/keystone
# Cloud: postgresql+asyncpg://user:pass@cloud-host:5432/keystone?sslmode=require
```

### Redis Configuration

```bash
# Redis Connection
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=                # Optional password
REDIS_DECODE_RESPONSES=true   # Decode responses to strings

# Redis Examples
# Local: redis://localhost:6379/0
# With auth: redis://:password@localhost:6379/0
# Cloud: rediss://user:pass@cloud-redis:6380/0
```

### JWT Security Settings

```bash
# JWT Configuration
JWT_SECRET_KEY=your-super-secret-256-bit-key  # CHANGE IN PRODUCTION!
JWT_ALGORITHM=HS256                           # Signing algorithm
JWT_ISSUER=keystone-auth                      # Token issuer

# Token Lifetimes (in minutes/days)
ACCESS_TOKEN_EXPIRE_MINUTES=15    # Access token lifetime
REFRESH_TOKEN_EXPIRE_DAYS=30      # Refresh token lifetime
SERVICE_TOKEN_EXPIRE_MINUTES=15   # Service token lifetime
```

### Password Policy

```bash
# Password Requirements
PASSWORD_MIN_LENGTH=8              # Minimum password length
PASSWORD_MAX_LENGTH=128            # Maximum password length
PASSWORD_REQUIRE_UPPERCASE=true    # Require uppercase letters
PASSWORD_REQUIRE_LOWERCASE=true    # Require lowercase letters
PASSWORD_REQUIRE_DIGITS=true       # Require numbers
PASSWORD_REQUIRE_SPECIAL=true      # Require special characters
PASSWORD_PREVENT_REUSE_COUNT=5     # Prevent reusing last N passwords
PASSWORD_MAX_AGE_DAYS=90          # Force password change after N days
```

### Rate Limiting

```bash
# Rate Limiting Rules
RATE_LIMIT_LOGIN=5/minute         # Login attempts per minute
RATE_LIMIT_REGISTER=3/hour        # Registration attempts per hour
RATE_LIMIT_API=100/minute         # General API calls per minute
RATE_LIMIT_REFRESH=10/minute      # Token refresh per minute
RATE_LIMIT_SERVICE_TOKEN=20/minute # Service token requests per minute

# Account Lockout
MAX_LOGIN_ATTEMPTS=5              # Failed attempts before lockout
LOCKOUT_DURATION_MINUTES=15       # Lockout duration
```

### CORS and Security

```bash
# CORS Configuration
ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:8080"]
ALLOWED_METHODS=["GET","POST","PUT","DELETE","OPTIONS"]
ALLOWED_HEADERS=["*"]
ALLOW_CREDENTIALS=true
ALLOWED_HOSTS=["localhost","127.0.0.1","*"]

# Production CORS Example
# ALLOWED_ORIGINS=["https://myapp.com","https://admin.myapp.com"]
# ALLOWED_HOSTS=["myapp.com","admin.myapp.com"]
```

### Logging and Monitoring

```bash
# Logging Configuration
LOG_LEVEL=INFO                    # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT=json                   # json or text
LOG_FILE=                         # Optional log file path

# Monitoring
ENABLE_METRICS=true               # Enable Prometheus metrics
METRICS_PATH=/metrics             # Metrics endpoint path
```

### Cache Settings

```bash
# Cache Prefixes and TTL
CACHE_TOKEN_PREFIX=keystone:token:
CACHE_SESSION_PREFIX=keystone:session:
CACHE_RATE_LIMIT_PREFIX=keystone:rate:
CACHE_USER_PREFIX=keystone:user:
CACHE_DEFAULT_TTL=3600           # Default cache TTL in seconds
```

### API Configuration

```bash
# API Settings
API_V1_PREFIX=/api/v1            # API version prefix
DOCS_URL=/docs                   # Swagger UI URL (null to disable)
REDOC_URL=/redoc                 # ReDoc URL (null to disable)
OPENAPI_URL=/openapi.json        # OpenAPI spec URL (null to disable)
```

## 🏗️ Configuration Profiles

### Development Profile

```bash
# .env.development
ENVIRONMENT=development
DEBUG=true
DATABASE_ECHO=true
LOG_LEVEL=DEBUG
DOCS_URL=/docs
REDOC_URL=/redoc

# Relaxed security for development
JWT_SECRET_KEY=dev-secret-key-not-for-production
PASSWORD_MIN_LENGTH=6
RATE_LIMIT_LOGIN=100/minute
```

### Testing Profile

```bash
# .env.testing
ENVIRONMENT=testing
DEBUG=true
DATABASE_URL=postgresql+asyncpg://test:test@localhost:5432/keystone_test
REDIS_URL=redis://localhost:6379/1
JWT_SECRET_KEY=test-secret-key
ACCESS_TOKEN_EXPIRE_MINUTES=1    # Short expiry for testing
```

### Production Profile

```bash
# .env.production
ENVIRONMENT=production
DEBUG=false
DATABASE_ECHO=false
LOG_LEVEL=INFO
DOCS_URL=                        # Disable docs in production
REDOC_URL=
OPENAPI_URL=

# Strong security for production
JWT_SECRET_KEY=<generate-strong-256-bit-key>
PASSWORD_MIN_LENGTH=12
RATE_LIMIT_LOGIN=5/minute
ALLOWED_ORIGINS=["https://yourdomain.com"]
ALLOWED_HOSTS=["yourdomain.com"]

# Production database with SSL
DATABASE_URL=postgresql+asyncpg://user:pass@prod-db:5432/keystone?sslmode=require

# Production Redis with auth
REDIS_URL=rediss://:password@prod-redis:6380/0
```

## 🔐 Security Configuration

### JWT Security Best Practices

```bash
# Generate strong JWT secret (256-bit)
openssl rand -base64 32

# Use RS256 for distributed systems
JWT_ALGORITHM=RS256
JWT_PUBLIC_KEY_PATH=/path/to/public.pem
JWT_PRIVATE_KEY_PATH=/path/to/private.pem
```

### Database Security

```bash
# Use connection pooling
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10

# Enable SSL for production
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db?sslmode=require

# Use read replicas for scaling
DATABASE_READ_URL=postgresql+asyncpg://user:pass@read-replica:5432/db
```

### Redis Security

```bash
# Use authentication
REDIS_PASSWORD=strong-redis-password

# Use SSL/TLS
REDIS_URL=rediss://:password@redis-host:6380/0

# Configure Redis ACL (Redis 6+)
REDIS_USERNAME=keystone-user
```

## 🌍 Environment-Specific Settings

### Docker Configuration

```yaml
# docker-compose.yml
version: '3.8'
services:
  keystone-app:
    environment:
      - ENVIRONMENT=production
      - DATABASE_URL=postgresql+asyncpg://keystone:${DB_PASSWORD}@postgres:5432/keystone
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
```

### Kubernetes Configuration

```yaml
# k8s-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: keystone-config
data:
  ENVIRONMENT: "production"
  LOG_LEVEL: "INFO"
  API_V1_PREFIX: "/api/v1"
---
apiVersion: v1
kind: Secret
metadata:
  name: keystone-secrets
type: Opaque
stringData:
  JWT_SECRET_KEY: "your-secret-key"
  DATABASE_URL: "postgresql+asyncpg://..."
  REDIS_URL: "redis://..."
```

### Cloud Provider Examples

#### AWS Configuration

```bash
# Using AWS RDS and ElastiCache
DATABASE_URL=postgresql+asyncpg://user:pass@keystone.cluster-xxx.us-east-1.rds.amazonaws.com:5432/keystone?sslmode=require
REDIS_URL=rediss://keystone.cache.amazonaws.com:6380/0

# Using AWS Secrets Manager
JWT_SECRET_KEY=${aws:secretsmanager:keystone-jwt-secret:SecretString:key}
```

#### Google Cloud Configuration

```bash
# Using Cloud SQL and Memorystore
DATABASE_URL=postgresql+asyncpg://user:pass@/keystone?host=/cloudsql/project:region:instance
REDIS_URL=redis://10.0.0.1:6379/0
```

#### Azure Configuration

```bash
# Using Azure Database and Redis Cache
DATABASE_URL=postgresql+asyncpg://user@server:pass@server.postgres.database.azure.com:5432/keystone?sslmode=require
REDIS_URL=rediss://cache.redis.cache.windows.net:6380/0
```

## 🔧 Advanced Configuration

### Custom Settings Class

```python
# app/config/custom_settings.py
from app.config.settings import Settings

class CustomSettings(Settings):
    # Custom business logic settings
    COMPANY_NAME: str = "My Company"
    FEATURE_FLAGS: dict = {
        "enable_2fa": True,
        "enable_social_login": False,
        "enable_audit_log": True
    }
    
    # Custom integrations
    SLACK_WEBHOOK_URL: Optional[str] = None
    EMAIL_PROVIDER: str = "sendgrid"
    SMS_PROVIDER: str = "twilio"

# Use custom settings
settings = CustomSettings()
```

### Dynamic Configuration

```python
# Runtime configuration updates
from app.config.settings import settings

# Update rate limits dynamically
settings.RATE_LIMIT_LOGIN = "10/minute"

# Feature flags
if settings.FEATURE_FLAGS.get("enable_2fa"):
    # Enable 2FA functionality
    pass
```

### Configuration Validation

```python
# app/config/validation.py
from pydantic import validator

class ValidatedSettings(Settings):
    @validator('JWT_SECRET_KEY')
    def validate_jwt_secret(cls, v):
        if len(v) < 32:
            raise ValueError('JWT secret must be at least 32 characters')
        return v
    
    @validator('DATABASE_URL')
    def validate_database_url(cls, v):
        if not v.startswith('postgresql'):
            raise ValueError('Only PostgreSQL databases are supported')
        return v
```

## 📊 Configuration Monitoring

### Health Checks

```python
# Check configuration health
GET /health/config

# Response
{
  "database": "connected",
  "redis": "connected",
  "jwt_secret": "configured",
  "environment": "production"
}
```

### Configuration Endpoints

```python
# Get current configuration (admin only)
GET /api/v1/admin/config

# Update configuration (admin only)
PUT /api/v1/admin/config
{
  "rate_limit_login": "10/minute",
  "password_min_length": 10
}
```

## 🚨 Configuration Troubleshooting

### Common Issues

#### Invalid JWT Secret
```bash
# Error: JWT secret too short
# Solution: Generate proper secret
openssl rand -base64 32
```

#### Database Connection Failed
```bash
# Error: could not connect to server
# Check: DATABASE_URL format and credentials
# Test: psql "postgresql://user:pass@host:5432/db"
```

#### Redis Connection Failed
```bash
# Error: Connection refused
# Check: REDIS_URL and Redis server status
# Test: redis-cli -u "redis://localhost:6379" ping
```

#### CORS Issues
```bash
# Error: CORS policy blocked
# Solution: Add your domain to ALLOWED_ORIGINS
ALLOWED_ORIGINS=["https://yourdomain.com"]
```

### Configuration Validation

```bash
# Validate configuration
python -c "from app.config.settings import settings; print('Config valid!')"

# Test database connection
python -c "from app.config.database import test_connection; import asyncio; asyncio.run(test_connection())"

# Test Redis connection
python -c "from app.config.redis import test_connection; import asyncio; asyncio.run(test_connection())"
```

## 📚 Next Steps

After configuring Keystone:

1. **[Quick Start Guide](quick-start.md)** - Test your configuration
2. **[API Documentation](../api/authentication.md)** - Explore the endpoints
3. **[Security Guide](../security/security-guide.md)** - Secure your deployment
4. **[Deployment Guide](../architecture/deployment.md)** - Deploy to production

---

**Configuration complete! 🎉 Your Keystone system is ready for secure authentication.**