# 🔒 Security Guide

This comprehensive security guide covers all security aspects of the permiso Authentication System, including best practices, threat mitigation, and security configuration.

## 🎯 Security Overview

permiso implements defense-in-depth security with multiple layers of protection:

- **Authentication Security**: Strong password policies, account lockout, MFA support
- **Authorization Security**: Role-based access control, scope-based permissions
- **Token Security**: JWT with secure signing, token revocation, short lifetimes
- **Transport Security**: HTTPS enforcement, secure headers
- **Input Security**: Validation, sanitization, injection prevention
- **Infrastructure Security**: Rate limiting, monitoring, audit logging

## 🔐 Authentication Security

### Password Security

#### Password Policy Configuration

```bash
# Strong password requirements
PASSWORD_MIN_LENGTH=12
PASSWORD_MAX_LENGTH=128
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGITS=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_PREVENT_REUSE_COUNT=10
PASSWORD_MAX_AGE_DAYS=90
```

#### Password Hashing

permiso uses **Argon2id** for password hashing:

```python
# Argon2 configuration
ARGON2_TIME_COST = 3      # Number of iterations
ARGON2_MEMORY_COST = 65536 # Memory usage in KB (64MB)
ARGON2_PARALLELISM = 1    # Number of parallel threads
ARGON2_HASH_LENGTH = 32   # Hash output length
ARGON2_SALT_LENGTH = 16   # Salt length
```

**Why Argon2?**
- Winner of the Password Hashing Competition
- Resistant to GPU and ASIC attacks
- Memory-hard function
- Configurable time/memory trade-offs

#### Account Lockout Protection

```python
# Account lockout configuration
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30
PROGRESSIVE_LOCKOUT = True  # Increase lockout time with repeated failures

# Progressive lockout schedule
LOCKOUT_SCHEDULE = {
    1: 5,    # 5 minutes after 1st lockout
    2: 15,   # 15 minutes after 2nd lockout
    3: 60,   # 1 hour after 3rd lockout
    4: 240,  # 4 hours after 4th lockout
    5: 1440  # 24 hours after 5th lockout
}
```

### Multi-Factor Authentication (MFA)

#### TOTP (Time-based One-Time Password)

```python
# MFA configuration
MFA_ENABLED = True
MFA_ISSUER = "permiso Auth"
MFA_ALGORITHM = "SHA1"
MFA_DIGITS = 6
MFA_PERIOD = 30  # seconds
MFA_WINDOW = 1   # Allow 1 period before/after
```

#### Backup Codes

```python
# Backup codes for MFA recovery
BACKUP_CODES_COUNT = 10
BACKUP_CODES_LENGTH = 8
BACKUP_CODES_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
```

## 🎫 Token Security

### JWT Configuration

#### Secure JWT Settings

```bash
# Production JWT configuration
JWT_ALGORITHM=RS256  # Use RSA signatures for distributed systems
JWT_ISSUER=permiso-auth
JWT_AUDIENCE=["api-server", "web-app"]

# Token lifetimes (keep short)
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7  # Shorter than default 30 days
SERVICE_TOKEN_EXPIRE_MINUTES=5

# Key rotation
JWT_KEY_ROTATION_ENABLED=true
JWT_KEY_ROTATION_INTERVAL_DAYS=90
```

#### RSA Key Generation

```bash
# Generate RSA key pair for JWT signing
openssl genrsa -out private_key.pem 4096
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Secure key storage
chmod 600 private_key.pem
chmod 644 public_key.pem
```

### Token Validation

#### Comprehensive Token Validation

```python
class TokenValidator:
    def validate_token(self, token: str) -> TokenPayload:
        # 1. Signature validation
        payload = jwt.decode(token, self.public_key, algorithms=[self.algorithm])
        
        # 2. Expiration check
        if datetime.utcnow() > datetime.fromtimestamp(payload['exp']):
            raise TokenExpiredError()
        
        # 3. Not before check
        if datetime.utcnow() < datetime.fromtimestamp(payload.get('nbf', 0)):
            raise TokenNotYetValidError()
        
        # 4. Issuer validation
        if payload.get('iss') != self.issuer:
            raise InvalidIssuerError()
        
        # 5. Audience validation
        if not self.validate_audience(payload.get('aud', [])):
            raise InvalidAudienceError()
        
        # 6. Revocation check
        if await self.is_token_revoked(payload.get('jti')):
            raise TokenRevokedError()
        
        # 7. User status check
        if payload.get('type') == 'access':
            user = await self.get_user(payload['sub'])
            if not user.is_active or user.is_locked:
                raise UserInactiveError()
        
        return TokenPayload(**payload)
```

### Token Revocation

#### Redis-based Token Blacklist

```python
class TokenBlacklist:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.prefix = "revoked_token:"
    
    async def revoke_token(self, jti: str, ttl: int):
        """Add token to blacklist with TTL matching token expiration."""
        await self.redis.set(f"{self.prefix}{jti}", "1", expire=ttl)
    
    async def is_revoked(self, jti: str) -> bool:
        """Check if token is revoked."""
        return await self.redis.exists(f"{self.prefix}{jti}")
    
    async def revoke_all_user_tokens(self, user_id: str):
        """Revoke all tokens for a user."""
        # Implementation depends on token storage strategy
        pass
```

## 🛡️ Authorization Security

### Role-Based Access Control (RBAC)

#### Role Hierarchy

```python
# Role hierarchy definition
ROLE_HIERARCHY = {
    "superuser": ["admin", "user", "service"],
    "admin": ["user"],
    "user": [],
    "service": []
}

def has_role_or_higher(user_roles: List[str], required_role: str) -> bool:
    """Check if user has required role or higher in hierarchy."""
    for user_role in user_roles:
        if required_role in ROLE_HIERARCHY.get(user_role, []):
            return True
        if user_role == required_role:
            return True
    return False
```

#### Scope-Based Permissions

```python
# Scope naming convention: action:resource
SCOPES = {
    # User management
    "read:profile": "Read user profile",
    "write:profile": "Update user profile",
    "delete:profile": "Delete user account",
    
    # Admin operations
    "admin:users": "Manage all users",
    "admin:roles": "Manage roles and permissions",
    "admin:clients": "Manage service clients",
    "admin:system": "System administration",
    
    # Service operations
    "service:api": "Service-to-service API access",
    "service:internal": "Internal service operations"
}
```

### Permission Checking

```python
class AuthorizationService:
    async def check_permission(
        self, 
        user: User, 
        resource: str, 
        action: str,
        context: dict = None
    ) -> bool:
        """Comprehensive permission checking."""
        
        # 1. Superuser bypass
        if user.is_superuser:
            return True
        
        # 2. Check direct scope
        required_scope = f"{action}:{resource}"
        user_scopes = await user.get_scopes()
        if required_scope in user_scopes:
            return True
        
        # 3. Check admin scope
        admin_scope = f"admin:{resource}"
        if admin_scope in user_scopes:
            return True
        
        # 4. Check system admin
        if "admin:system" in user_scopes and action != "delete":
            return True
        
        # 5. Context-based permissions
        if context:
            return await self.check_context_permission(
                user, resource, action, context
            )
        
        return False
    
    async def check_context_permission(
        self, 
        user: User, 
        resource: str, 
        action: str, 
        context: dict
    ) -> bool:
        """Context-aware permission checking."""
        
        # Resource ownership check
        if resource == "profile" and context.get("user_id") == str(user.id):
            return True
        
        # Team-based permissions
        if context.get("team_id") in await user.get_team_ids():
            return True
        
        # Time-based permissions
        if not self.is_within_allowed_hours(context.get("timestamp")):
            return False
        
        return False
```

## 🌐 Transport Security

### HTTPS Configuration

#### Nginx SSL Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;
    
    # SSL certificates
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    
    # SSL security settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" always;
    
    location / {
        proxy_pass http://permiso-backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name auth.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### Security Headers

```python
# FastAPI security headers middleware
from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Trusted hosts
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["auth.yourdomain.com", "*.yourdomain.com"]
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Custom security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    
    return response
```

## 🚫 Input Security

### Input Validation

#### Pydantic Schema Validation

```python
from pydantic import BaseModel, validator, EmailStr
from typing import Optional
import re

class UserRegistration(BaseModel):
    username: str
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    
    @validator('username')
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]{3,50}$', v):
            raise ValueError('Username must be 3-50 characters, alphanumeric, underscore, or dash only')
        return v.lower()
    
    @validator('password')
    def validate_password(cls, v):
        errors = validate_password(v)
        if errors:
            raise ValueError(f"Password validation failed: {', '.join(errors)}")
        return v
    
    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        if v and not re.match(r'^[a-zA-Z\s\'-]{1,100}$', v):
            raise ValueError('Name contains invalid characters')
        return v
```

#### SQL Injection Prevention

```python
# Always use parameterized queries with SQLAlchemy
from sqlalchemy import select, text

# GOOD: Parameterized query
async def get_user_by_username(username: str):
    stmt = select(User).where(User.username == username)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()

# GOOD: Named parameters with text()
async def complex_query(user_id: str, status: str):
    stmt = text("""
        SELECT * FROM users 
        WHERE id = :user_id AND status = :status
    """)
    result = await session.execute(stmt, {"user_id": user_id, "status": status})
    return result.fetchall()

# BAD: String concatenation (vulnerable to SQL injection)
# async def bad_query(username: str):
#     query = f"SELECT * FROM users WHERE username = '{username}'"
#     # This is vulnerable to SQL injection!
```

#### XSS Prevention

```python
import html
from markupsafe import escape

def sanitize_user_input(text: str) -> str:
    """Sanitize user input to prevent XSS."""
    if not text:
        return ""
    
    # HTML escape
    sanitized = html.escape(text)
    
    # Additional sanitization for specific contexts
    sanitized = sanitized.replace("javascript:", "")
    sanitized = sanitized.replace("data:", "")
    
    return sanitized

# Use in API responses
class UserResponse(BaseModel):
    username: str
    display_name: Optional[str] = None
    
    @validator('display_name', pre=True)
    def sanitize_display_name(cls, v):
        return sanitize_user_input(v) if v else None
```

### Rate Limiting

#### Advanced Rate Limiting

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Create limiter with Redis backend
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379"
)

# Different limits for different endpoints
@app.post("/api/v1/auth/token")
@limiter.limit("5/minute")  # Strict limit for login
async def login(request: Request, credentials: UserCredentials):
    pass

@app.post("/api/v1/users/register")
@limiter.limit("3/hour")  # Very strict for registration
async def register(request: Request, user_data: UserRegistration):
    pass

@app.get("/api/v1/users/profile")
@limiter.limit("100/minute")  # Generous for profile access
async def get_profile(request: Request):
    pass

# Custom rate limit handler
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "error": "rate_limit_exceeded",
            "error_description": f"Rate limit exceeded: {exc.detail}",
            "retry_after": exc.retry_after
        }
    )
```

#### User-based Rate Limiting

```python
class UserRateLimiter:
    def __init__(self, redis_client):
        self.redis = redis_client
    
    async def check_user_rate_limit(
        self, 
        user_id: str, 
        action: str, 
        limit: int, 
        window: int
    ) -> bool:
        """Check if user has exceeded rate limit for specific action."""
        key = f"rate_limit:user:{user_id}:{action}"
        
        # Get current count
        current = await self.redis.get(key)
        if current is None:
            current = 0
        else:
            current = int(current)
        
        if current >= limit:
            return False
        
        # Increment counter
        pipe = self.redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, window)
        await pipe.execute()
        
        return True
```

## 🔍 Security Monitoring

### Audit Logging

#### Comprehensive Audit Trail

```python
import structlog
from enum import Enum

class AuditEventType(Enum):
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_REGISTRATION = "user_registration"
    PASSWORD_CHANGE = "password_change"
    ACCOUNT_LOCKED = "account_locked"
    TOKEN_ISSUED = "token_issued"
    TOKEN_REVOKED = "token_revoked"
    PERMISSION_DENIED = "permission_denied"
    ADMIN_ACTION = "admin_action"

class AuditLogger:
    def __init__(self):
        self.logger = structlog.get_logger("audit")
    
    async def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[dict] = None
    ):
        """Log security audit event."""
        
        event_data = {
            "event_type": event_type.value,
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "details": details or {}
        }
        
        # Log to structured logger
        self.logger.info("Security audit event", **event_data)
        
        # Store in database for compliance
        await self.store_audit_event(event_data)
    
    async def store_audit_event(self, event_data: dict):
        """Store audit event in database."""
        # Implementation depends on your audit storage requirements
        pass
```

### Security Alerts

#### Real-time Security Monitoring

```python
class SecurityMonitor:
    def __init__(self, alert_service):
        self.alert_service = alert_service
        self.thresholds = {
            "failed_logins_per_minute": 10,
            "failed_logins_per_hour": 100,
            "new_registrations_per_hour": 50,
            "token_validation_failures_per_minute": 20
        }
    
    async def check_security_metrics(self):
        """Check security metrics and trigger alerts."""
        
        # Check failed login attempts
        failed_logins = await self.get_failed_logins_count(minutes=1)
        if failed_logins > self.thresholds["failed_logins_per_minute"]:
            await self.alert_service.send_alert(
                "High number of failed login attempts",
                severity="HIGH",
                details={"count": failed_logins, "timeframe": "1 minute"}
            )
        
        # Check for potential brute force attacks
        await self.check_brute_force_patterns()
        
        # Check for suspicious token activity
        await self.check_token_anomalies()
    
    async def check_brute_force_patterns(self):
        """Detect potential brute force attacks."""
        # Implementation for pattern detection
        pass
```

## 🚨 Incident Response

### Security Incident Procedures

#### Immediate Response Actions

1. **Identify the Incident**
   - Monitor security alerts
   - Analyze audit logs
   - Assess impact scope

2. **Contain the Threat**
   ```python
   # Emergency user lockout
   await user_service.lock_user(user_id, reason="Security incident")
   
   # Revoke all user tokens
   await token_service.revoke_all_user_tokens(user_id)
   
   # Block suspicious IP addresses
   await rate_limiter.block_ip(ip_address, duration=3600)
   ```

3. **Investigate and Document**
   - Collect relevant logs
   - Document timeline
   - Identify root cause

4. **Recovery and Lessons Learned**
   - Implement fixes
   - Update security measures
   - Conduct post-incident review

### Breach Response Plan

#### Data Breach Response

```python
class BreachResponseService:
    async def handle_potential_breach(self, incident_details: dict):
        """Handle potential data breach."""
        
        # 1. Immediate containment
        await self.contain_breach(incident_details)
        
        # 2. Assessment
        impact = await self.assess_breach_impact(incident_details)
        
        # 3. Notification (if required)
        if impact.requires_notification:
            await self.notify_authorities(impact)
            await self.notify_affected_users(impact.affected_users)
        
        # 4. Documentation
        await self.document_incident(incident_details, impact)
    
    async def contain_breach(self, incident_details: dict):
        """Immediate containment actions."""
        # Revoke compromised tokens
        # Lock affected accounts
        # Block malicious IPs
        # Disable compromised features
        pass
```

## 📋 Security Checklist

### Pre-Production Security Checklist

#### Authentication & Authorization
- [ ] Strong password policy enforced
- [ ] Account lockout protection enabled
- [ ] MFA available for admin accounts
- [ ] JWT tokens use secure algorithms (RS256)
- [ ] Token lifetimes are appropriately short
- [ ] Token revocation implemented
- [ ] Role-based access control configured
- [ ] Scope-based permissions implemented

#### Transport Security
- [ ] HTTPS enforced in production
- [ ] Security headers configured
- [ ] HSTS enabled
- [ ] Certificate pinning considered
- [ ] CORS properly configured

#### Input Security
- [ ] All inputs validated with Pydantic
- [ ] SQL injection prevention verified
- [ ] XSS prevention implemented
- [ ] CSRF protection enabled
- [ ] File upload security (if applicable)

#### Infrastructure Security
- [ ] Rate limiting configured
- [ ] Security monitoring enabled
- [ ] Audit logging implemented
- [ ] Database access secured
- [ ] Redis access secured
- [ ] Secrets management implemented

#### Operational Security
- [ ] Security incident response plan
- [ ] Regular security updates scheduled
- [ ] Penetration testing completed
- [ ] Security training for team
- [ ] Backup and recovery procedures

## 🔧 Security Tools and Testing

### Security Testing Tools

#### Automated Security Testing

```bash
# Install security testing tools
pip install bandit safety semgrep

# Static security analysis
bandit -r app/
safety check
semgrep --config=auto app/

# Dependency vulnerability scanning
pip-audit

# SAST (Static Application Security Testing)
# Configure in CI/CD pipeline
```

#### Penetration Testing

```python
# Example security test cases
import pytest
import httpx

class TestSecurityVulnerabilities:
    
    @pytest.mark.security
    async def test_sql_injection_protection(self, async_client):
        """Test SQL injection protection."""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'/*",
            "' UNION SELECT * FROM users --"
        ]
        
        for payload in malicious_inputs:
            response = await async_client.post(
                "/api/v1/auth/token",
                data={"username": payload, "password": "test"}
            )
            # Should not cause server error or expose data
            assert response.status_code in [400, 401, 422]
    
    @pytest.mark.security
    async def test_xss_protection(self, async_client, auth_headers):
        """Test XSS protection."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//"
        ]
        
        for payload in xss_payloads:
            response = await async_client.put(
                "/api/v1/users/profile",
                headers=auth_headers,
                json={"display_name": payload}
            )
            
            # Check response doesn't contain unescaped payload
            if response.status_code == 200:
                assert payload not in response.text
    
    @pytest.mark.security
    async def test_rate_limiting(self, async_client):
        """Test rate limiting protection."""
        # Attempt to exceed rate limit
        for _ in range(10):
            response = await async_client.post(
                "/api/v1/auth/token",
                data={"username": "test", "password": "wrong"}
            )
        
        # Should be rate limited
        assert response.status_code == 429
```

## 📚 Security Resources

### Security Standards and Compliance

- **OWASP Top 10**: Web application security risks
- **NIST Cybersecurity Framework**: Comprehensive security framework
- **ISO 27001**: Information security management
- **SOC 2**: Security and availability controls
- **GDPR**: Data protection and privacy

### Security Best Practices

1. **Principle of Least Privilege**: Grant minimum necessary permissions
2. **Defense in Depth**: Multiple layers of security controls
3. **Zero Trust**: Never trust, always verify
4. **Security by Design**: Build security into the architecture
5. **Regular Updates**: Keep dependencies and systems updated

### Recommended Reading

#### External Resources
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [FastAPI Security Documentation](https://fastapi.tiangolo.com/tutorial/security/)
- [Python Security Guidelines](https://python.org/dev/security/)

#### permiso Documentation
- [System Architecture](../architecture/authentication-system.md) - Complete system architecture overview
- [FastAPI Dependency Patterns](../development/fastapi-dependency-patterns.md) - Security-focused dependency injection
- [Code Examples & Best Practices](../development/code-examples-best-practices.md) - Secure implementation examples
- [Service-to-Service Authentication](../developer-portal/integrations/service-to-service.md) - Secure service integration
- [Web Application Integration](../developer-portal/integrations/web-applications.md) - Frontend security patterns
- [Testing Guide](../development/testing.md) - Security testing strategies

---

**Security is everyone's responsibility! 🔒 Build secure, trustworthy authentication systems with permiso.**