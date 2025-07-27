# 🏗️ Comprehensive Service Integration Guide - Part 3

This is the final part of the comprehensive integration guide, covering monitoring, troubleshooting, and a complete working example.

## 📊 Monitoring and Auditing

### 1. Comprehensive Monitoring Setup

```python
# shared/monitoring/metrics.py
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time
import functools
from typing import Callable, Any
import structlog

logger = structlog.get_logger(__name__)

# Metrics definitions
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code', 'service']
)

REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint', 'service']
)

AUTH_REQUESTS = Counter(
    'auth_requests_total',
    'Total authentication requests',
    ['client_id', 'grant_type', 'status']
)

TOKEN_VALIDATIONS = Counter(
    'token_validations_total',
    'Total token validations',
    ['service', 'status']
)

ACTIVE_TOKENS = Gauge(
    'active_tokens_count',
    'Number of active tokens',
    ['token_type']
)

FAILED_LOGINS = Counter(
    'failed_login_attempts_total',
    'Failed login attempts',
    ['reason']
)

class MetricsCollector:
    """Centralized metrics collection."""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        
    def track_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Track HTTP request metrics."""
        REQUEST_COUNT.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            service=self.service_name
        ).inc()
        
        REQUEST_DURATION.labels(
            method=method,
            endpoint=endpoint,
            service=self.service_name
        ).observe(duration)
    
    def track_auth_request(self, client_id: str, grant_type: str, success: bool):
        """Track authentication request."""
        status = "success" if success else "failure"
        AUTH_REQUESTS.labels(
            client_id=client_id,
            grant_type=grant_type,
            status=status
        ).inc()
    
    def track_token_validation(self, success: bool):
        """Track token validation."""
        status = "success" if success else "failure"
        TOKEN_VALIDATIONS.labels(
            service=self.service_name,
            status=status
        ).inc()
    
    def update_active_tokens(self, token_type: str, count: int):
        """Update active token count."""
        ACTIVE_TOKENS.labels(token_type=token_type).set(count)
    
    def track_failed_login(self, reason: str):
        """Track failed login attempt."""
        FAILED_LOGINS.labels(reason=reason).inc()

def metrics_middleware(metrics_collector: MetricsCollector):
    """FastAPI middleware for metrics collection."""
    
    async def middleware(request, call_next):
        start_time = time.time()
        
        response = await call_next(request)
        
        duration = time.time() - start_time
        
        metrics_collector.track_request(
            method=request.method,
            endpoint=request.url.path,
            status_code=response.status_code,
            duration=duration
        )
        
        return response
    
    return middleware

def track_auth_metrics(metrics_collector: MetricsCollector):
    """Decorator for tracking authentication metrics."""
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            success = False
            client_id = "unknown"
            grant_type = "unknown"
            
            try:
                # Extract client_id and grant_type from request
                if 'client_id' in kwargs:
                    client_id = kwargs['client_id']
                elif len(args) > 0 and hasattr(args[0], 'client_id'):
                    client_id = args[0].client_id
                
                if 'grant_type' in kwargs:
                    grant_type = kwargs['grant_type']
                
                result = await func(*args, **kwargs)
                success = True
                return result
                
            except Exception as e:
                logger.error("Authentication failed", error=str(e), client_id=client_id)
                raise
            finally:
                metrics_collector.track_auth_request(client_id, grant_type, success)
        
        return wrapper
    return decorator
```

### 2. Structured Logging

```python
# shared/logging/setup.py
import structlog
import logging
import sys
from typing import Dict, Any
import json
from datetime import datetime

def setup_logging(
    service_name: str,
    log_level: str = "INFO",
    log_format: str = "json",
    include_trace_id: bool = True
):
    """Setup structured logging for the service."""
    
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper())
    )
    
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        add_service_context(service_name),
    ]
    
    if include_trace_id:
        processors.append(add_trace_id)
    
    if log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

def add_service_context(service_name: str):
    """Add service context to log entries."""
    def processor(logger, method_name, event_dict):
        event_dict["service"] = service_name
        event_dict["version"] = "1.0.0"  # Could be dynamic
        return event_dict
    return processor

def add_trace_id(logger, method_name, event_dict):
    """Add trace ID for request correlation."""
    # In a real implementation, you'd extract this from request context
    # For now, we'll use a simple approach
    import uuid
    if "trace_id" not in event_dict:
        event_dict["trace_id"] = str(uuid.uuid4())[:8]
    return event_dict

class SecurityAuditLogger:
    """Specialized logger for security events."""
    
    def __init__(self, service_name: str):
        self.logger = structlog.get_logger("security_audit")
        self.service_name = service_name
    
    def log_authentication_attempt(
        self,
        client_id: str,
        success: bool,
        ip_address: str = None,
        user_agent: str = None,
        failure_reason: str = None
    ):
        """Log authentication attempt."""
        self.logger.info(
            "authentication_attempt",
            client_id=client_id,
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
            failure_reason=failure_reason,
            event_type="auth_attempt"
        )
    
    def log_token_validation(
        self,
        token_jti: str,
        success: bool,
        requested_scopes: list = None,
        failure_reason: str = None
    ):
        """Log token validation."""
        self.logger.info(
            "token_validation",
            token_jti=token_jti,
            success=success,
            requested_scopes=requested_scopes,
            failure_reason=failure_reason,
            event_type="token_validation"
        )
    
    def log_api_access(
        self,
        endpoint: str,
        method: str,
        client_id: str,
        user_id: str = None,
        scopes_used: list = None,
        response_status: int = None
    ):
        """Log API access."""
        self.logger.info(
            "api_access",
            endpoint=endpoint,
            method=method,
            client_id=client_id,
            user_id=user_id,
            scopes_used=scopes_used,
            response_status=response_status,
            event_type="api_access"
        )
    
    def log_security_violation(
        self,
        violation_type: str,
        description: str,
        client_id: str = None,
        ip_address: str = None,
        severity: str = "medium"
    ):
        """Log security violation."""
        self.logger.warning(
            "security_violation",
            violation_type=violation_type,
            description=description,
            client_id=client_id,
            ip_address=ip_address,
            severity=severity,
            event_type="security_violation"
        )
```

### 3. Health Checks and Observability

```python
# shared/health/checks.py
import asyncio
import time
from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum
import httpx
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"

@dataclass
class HealthCheck:
    name: str
    status: HealthStatus
    response_time_ms: float
    details: Dict[str, Any] = None
    error: str = None

class HealthChecker:
    """Comprehensive health checking system."""
    
    def __init__(self):
        self.checks: List[callable] = []
    
    def add_check(self, check_func: callable):
        """Add a health check function."""
        self.checks.append(check_func)
    
    async def run_all_checks(self) -> Dict[str, Any]:
        """Run all health checks."""
        results = []
        overall_status = HealthStatus.HEALTHY
        
        for check_func in self.checks:
            try:
                result = await check_func()
                results.append(result)
                
                if result.status == HealthStatus.UNHEALTHY:
                    overall_status = HealthStatus.UNHEALTHY
                elif result.status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
                    overall_status = HealthStatus.DEGRADED
                    
            except Exception as e:
                results.append(HealthCheck(
                    name=check_func.__name__,
                    status=HealthStatus.UNHEALTHY,
                    response_time_ms=0,
                    error=str(e)
                ))
                overall_status = HealthStatus.UNHEALTHY
        
        return {
            "status": overall_status.value,
            "timestamp": time.time(),
            "checks": [
                {
                    "name": check.name,
                    "status": check.status.value,
                    "response_time_ms": check.response_time_ms,
                    "details": check.details,
                    "error": check.error
                }
                for check in results
            ]
        }

async def check_database_health(db_session: AsyncSession) -> HealthCheck:
    """Check database connectivity and performance."""
    start_time = time.perf_counter()
    
    try:
        # Simple query to test connectivity
        result = await db_session.execute(text("SELECT 1"))
        result.scalar()
        
        response_time = (time.perf_counter() - start_time) * 1000
        
        # Check response time thresholds
        if response_time > 1000:  # 1 second
            status = HealthStatus.UNHEALTHY
        elif response_time > 500:  # 500ms
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY
        
        return HealthCheck(
            name="database",
            status=status,
            response_time_ms=response_time,
            details={"query": "SELECT 1"}
        )
        
    except Exception as e:
        response_time = (time.perf_counter() - start_time) * 1000
        return HealthCheck(
            name="database",
            status=HealthStatus.UNHEALTHY,
            response_time_ms=response_time,
            error=str(e)
        )

async def check_redis_health(redis_url: str) -> HealthCheck:
    """Check Redis connectivity and performance."""
    start_time = time.perf_counter()
    
    try:
        redis_client = redis.from_url(redis_url)
        
        # Test basic operations
        await redis_client.set("health_check", "ok", ex=10)
        result = await redis_client.get("health_check")
        await redis_client.delete("health_check")
        
        await redis_client.close()
        
        response_time = (time.perf_counter() - start_time) * 1000
        
        if response_time > 500:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY
        
        return HealthCheck(
            name="redis",
            status=status,
            response_time_ms=response_time,
            details={"operation": "set/get/delete"}
        )
        
    except Exception as e:
        response_time = (time.perf_counter() - start_time) * 1000
        return HealthCheck(
            name="redis",
            status=HealthStatus.UNHEALTHY,
            response_time_ms=response_time,
            error=str(e)
        )

async def check_external_service_health(service_url: str, service_name: str) -> HealthCheck:
    """Check external service health."""
    start_time = time.perf_counter()
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{service_url}/health")
            
            response_time = (time.perf_counter() - start_time) * 1000
            
            if response.status_code == 200:
                status = HealthStatus.HEALTHY
            else:
                status = HealthStatus.DEGRADED
            
            return HealthCheck(
                name=service_name,
                status=status,
                response_time_ms=response_time,
                details={
                    "status_code": response.status_code,
                    "url": f"{service_url}/health"
                }
            )
            
    except Exception as e:
        response_time = (time.perf_counter() - start_time) * 1000
        return HealthCheck(
            name=service_name,
            status=HealthStatus.UNHEALTHY,
            response_time_ms=response_time,
            error=str(e)
        )
```

## 🚨 Troubleshooting Guide

### 1. Common Issues and Solutions

#### Authentication Issues

**Issue: "Invalid client credentials"**
```bash
# Check client registration
curl -X GET "http://localhost:8000/api/v1/admin/service-clients/mt5-api-service" \
  -H "Authorization: Bearer ADMIN_TOKEN"

# Verify client secret (regenerate if needed)
curl -X POST "http://localhost:8000/api/v1/admin/service-clients/mt5-api-service/rotate-secret" \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

**Issue: "Token has expired"**
```python
# Check token expiration settings
import jwt
from datetime import datetime

def debug_token(token_string):
    # Decode without verification to inspect claims
    decoded = jwt.decode(token_string, options={"verify_signature": False})
    
    exp_timestamp = decoded.get('exp')
    if exp_timestamp:
        exp_datetime = datetime.fromtimestamp(exp_timestamp)
        now = datetime.utcnow()
        
        print(f"Token expires at: {exp_datetime}")
        print(f"Current time: {now}")
        print(f"Time remaining: {exp_datetime - now}")
        print(f"Is expired: {now > exp_datetime}")
    
    return decoded

# Usage
token_info = debug_token("your-jwt-token-here")
print(json.dumps(token_info, indent=2))
```

**Issue: "Insufficient permissions"**
```python
# Debug scope checking
def debug_scopes(token_payload, required_scopes):
    token_scopes = token_payload.get('scopes', [])
    
    print(f"Required scopes: {required_scopes}")
    print(f"Token scopes: {token_scopes}")
    
    missing = set(required_scopes) - set(token_scopes)
    print(f"Missing scopes: {missing}")
    
    # Check for implied scopes
    implied = get_implied_scopes(token_scopes)
    print(f"Implied scopes: {implied}")
    
    final_missing = missing - set(implied)
    print(f"Final missing scopes: {final_missing}")
    
    return len(final_missing) == 0
```

#### Network and Connectivity Issues

**Issue: "Connection refused"**
```bash
# Check service status
docker-compose ps

# Check service logs
docker-compose logs permiso-auth
docker-compose logs mt5-api

# Test connectivity
curl -v http://localhost:8000/health
curl -v http://localhost:8001/health

# Check network connectivity between containers
docker-compose exec mt5-api ping permiso-auth
```

**Issue: "DNS resolution failed"**
```bash
# Check Docker network
docker network ls
docker network inspect permiso_trading-network

# Test DNS resolution
docker-compose exec mt5-api nslookup permiso-auth
docker-compose exec mt5-api cat /etc/hosts
```

#### Performance Issues

**Issue: "Slow token validation"**
```python
# Profile token validation
import time
import cProfile

def profile_token_validation():
    def validate_token_performance():
        # Your token validation code here
        start = time.perf_counter()
        
        # Simulate token validation
        payload = jwt_service.validate_token(token)
        
        end = time.perf_counter()
        print(f"Token validation took: {(end - start) * 1000:.2f}ms")
        
        return payload
    
    # Profile the function
    cProfile.run('validate_token_performance()')

# Check Redis performance
async def check_redis_performance():
    import redis.asyncio as redis
    
    redis_client = redis.from_url("redis://localhost:6379/0")
    
    # Test Redis latency
    start = time.perf_counter()
    await redis_client.ping()
    end = time.perf_counter()
    
    print(f"Redis ping: {(end - start) * 1000:.2f}ms")
    
    # Test token revocation check
    start = time.perf_counter()
    result = await redis_client.exists("revoked_token:test")
    end = time.perf_counter()
    
    print(f"Token revocation check: {(end - start) * 1000:.2f}ms")
```

### 2. Debugging Tools

```python
# tools/debug_auth.py
import asyncio
import httpx
import json
from typing import Dict, Any

class AuthDebugger:
    """Debugging tools for authentication issues."""
    
    def __init__(self, auth_url: str, mt5_api_url: str):
        self.auth_url = auth_url
        self.mt5_api_url = mt5_api_url
    
    async def test_complete_flow(self, client_id: str, client_secret: str):
        """Test complete authentication flow with detailed logging."""
        
        print("🔍 Testing complete authentication flow...")
        
        # Step 1: Get service token
        print("\n1️⃣ Requesting service token...")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.auth_url}/api/v1/auth/service-token",
                    data={
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "scope": "trade:read account:read"
                    }
                )
                
                print(f"Status: {response.status_code}")
                print(f"Headers: {dict(response.headers)}")
                
                if response.status_code == 200:
                    token_data = response.json()
                    print(f"✅ Token obtained successfully")
                    print(f"Token type: {token_data.get('token_type')}")
                    print(f"Expires in: {token_data.get('expires_in')} seconds")
                    print(f"Scope: {token_data.get('scope')}")
                    
                    access_token = token_data["access_token"]
                    
                    # Decode token for inspection
                    self.inspect_token(access_token)
                    
                else:
                    error_data = response.json()
                    print(f"❌ Token request failed: {error_data}")
                    return
                    
        except Exception as e:
            print(f"❌ Token request error: {e}")
            return
        
        # Step 2: Test API access
        print("\n2️⃣ Testing API access...")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.mt5_api_url}/api/v1/trades",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                
                print(f"Status: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ API access successful")
                    print(f"Response: {json.dumps(data, indent=2)}")
                else:
                    error_data = response.json()
                    print(f"❌ API access failed: {error_data}")
                    
        except Exception as e:
            print(f"❌ API access error: {e}")
    
    def inspect_token(self, token: str):
        """Inspect JWT token contents."""
        import jwt
        from datetime import datetime
        
        print("\n🔍 Token inspection:")
        
        try:
            # Decode without verification to inspect
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            print(f"Issuer: {decoded.get('iss')}")
            print(f"Subject: {decoded.get('sub')}")
            print(f"Audience: {decoded.get('aud')}")
            print(f"Token type: {decoded.get('type')}")
            print(f"Client ID: {decoded.get('client_id')}")
            print(f"Scopes: {decoded.get('scopes')}")
            
            # Check expiration
            exp = decoded.get('exp')
            if exp:
                exp_datetime = datetime.fromtimestamp(exp)
                now = datetime.utcnow()
                remaining = exp_datetime - now
                
                print(f"Expires at: {exp_datetime}")
                print(f"Time remaining: {remaining}")
                print(f"Is expired: {now > exp_datetime}")
            
        except Exception as e:
            print(f"❌ Token inspection failed: {e}")
    
    async def test_token_validation(self, token: str):
        """Test token validation endpoint."""
        print("\n🔍 Testing token validation...")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.auth_url}/api/v1/auth/introspect",
                    json={"token": token},
                    headers={"Authorization": f"Bearer {token}"}
                )
                
                print(f"Status: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ Token validation successful")
                    print(f"Active: {data.get('active')}")
                    print(f"Client ID: {data.get('client_id')}")
                    print(f"Scope: {data.get('scope')}")
                else:
                    error_data = response.json()
                    print(f"❌ Token validation failed: {error_data}")
                    
        except Exception as e:
            print(f"❌ Token validation error: {e}")

# Usage
async def main():
    debugger = AuthDebugger(
        auth_url="http://localhost:8000",
        mt5_api_url="http://localhost:8001"
    )
    
    await debugger.test_complete_flow(
        client_id="mt5-api-service",
        client_secret="your-client-secret"
    )

if __name__ == "__main__":
    asyncio.run(main())
```

### 3. Log Analysis Tools

```python
# tools/log_analyzer.py
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Any

class LogAnalyzer:
    """Analyze authentication and API logs."""
    
    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        self.logs = []
        self.load_logs()
    
    def load_logs(self):
        """Load logs from file."""
        try:
            with open(self.log_file_path, 'r') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        self.logs.append(log_entry)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            print(f"Log file not found: {self.log_file_path}")
    
    def analyze_authentication_patterns(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze authentication patterns."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        auth_logs = [
            log for log in self.logs
            if log.get('event_type') == 'auth_attempt' and
            datetime.fromisoformat(log.get('timestamp', '').replace('Z', '+00:00')) > cutoff_time
        ]
        
        total_attempts = len(auth_logs)
        successful_attempts = len([log for log in auth_logs if log.get('success')])
        failed_attempts = total_attempts - successful_attempts
        
        # Analyze failure reasons
        failure_reasons = Counter([
            log.get('failure_reason', 'unknown')
            for log in auth_logs
            if not log.get('success')
        ])
        
        # Analyze by client
        client_stats = defaultdict(lambda: {'success': 0, 'failure': 0})
        for log in auth_logs:
            client_id = log.get('client_id', 'unknown')
            if log.get('success'):
                client_stats[client_id]['success'] += 1
            else:
                client_stats[client_id]['failure'] += 1
        
        # Analyze by time
        hourly_stats = defaultdict(lambda: {'success': 0, 'failure': 0})
        for log in auth_logs:
            timestamp = datetime.fromisoformat(log.get('timestamp', '').replace('Z', '+00:00'))
            hour_key = timestamp.strftime('%Y-%m-%d %H:00')
            
            if log.get('success'):
                hourly_stats[hour_key]['success'] += 1
            else:
                hourly_stats[hour_key]['failure'] += 1
        
        return {
            'summary': {
                'total_attempts': total_attempts,
                'successful_attempts': successful_attempts,
                'failed_attempts': failed_attempts,
                'success_rate': (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0
            },
            'failure_reasons': dict(failure_reasons),
            'client_stats': dict(client_stats),
            'hourly_stats': dict(hourly_stats)
        }
    
    def detect_suspicious_activity(self) -> List[Dict[str, Any]]:
        """Detect suspicious authentication activity."""
        suspicious_events = []
        
        # Detect brute force attempts
        ip_failure_counts = defaultdict(int)
        client_failure_counts = defaultdict(int)
        
        recent_logs = [
            log for log in self.logs
            if datetime.fromisoformat(log.get('timestamp', '').replace('Z', '+00:00')) > 
            datetime.utcnow() - timedelta(hours=1)
        ]
        
        for log in recent_logs:
            if log.get('event_type') == 'auth_attempt' and not log.get('success'):
                ip_address = log.get('ip_address')
                client_id = log.get('client_id')
                
                if ip_address:
                    ip_failure_counts[ip_address] += 1
                
                if client_id:
                    client_failure_counts[client_id] += 1
        
        # Flag IPs with many failures
        for ip, count in ip_failure_counts.items():
            if count > 10:  # Threshold
                suspicious_events.append({
                    'type': 'brute_force_ip',
                    'ip_address': ip,
                    'failure_count': count,
                    'severity': 'high' if count > 50 else 'medium'
                })
        
        # Flag clients with many failures
        for client_id, count in client_failure_counts.items():
            if count > 20:  # Higher threshold for clients
                suspicious_events.append({
                    'type': 'brute_force_client',
                    'client_id': client_id,
                    'failure_count': count,
                    'severity': 'high' if count > 100 else 'medium'
                })
        
        return suspicious_events
    
    def generate_report(self) -> str:
        """Generate comprehensive analysis report."""
        auth_analysis = self.analyze_authentication_patterns()
        suspicious_activity = self.detect_suspicious_activity()
        
        report = f"""
# Authentication Log Analysis Report
Generated: {datetime.utcnow().isoformat()}

## Summary
- Total authentication attempts: {auth_analysis['summary']['total_attempts']}
- Successful attempts: {auth_analysis['summary']['successful_attempts']}
- Failed attempts: {auth_analysis['summary']['failed_attempts']}
- Success rate: {auth_analysis['summary']['success_rate']:.2f}%

## Failure Reasons
"""
        
        for reason, count in auth_analysis['failure_reasons'].items():
            report += f"- {reason}: {count}\n"
        
        report += "\n## Client Statistics\n"
        for client_id, stats in auth_analysis['client_stats'].items():
            total =